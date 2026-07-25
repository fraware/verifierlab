"""Local discrete/text RL baseline and external trainer adapter hooks.

Heavy trainer SDKs stay behind the optional ``[rl]`` extra. The base package
ships a tabular Q-learning baseline that needs no torch/ray.
"""

from __future__ import annotations

import random
from typing import Any, Protocol, runtime_checkable

from verifierlab.attacks.fuzzing import DEFAULT_SCHEMA
from verifierlab.attacks.registry import register
from verifierlab.attacks.runtime import evaluate_candidate_trajectory


@runtime_checkable
class ExternalTrainerAdapter(Protocol):
    """Adapter contract for external RL trainers (RLlib, CleanRL, custom)."""

    def start(self, config: dict[str, Any]) -> None: ...

    def act(self, observation: dict[str, Any]) -> dict[str, Any]: ...

    def learn(self, transition: dict[str, Any]) -> dict[str, Any]: ...

    def save(self) -> dict[str, Any]: ...

    def load(self, state: dict[str, Any]) -> None: ...


class TabularQTrainer:
    """Minimal discrete Q-learning trainer (no ML framework deps)."""

    def __init__(self) -> None:
        self.q: dict[str, dict[str, float]] = {}
        self.actions: list[dict[str, Any]] = []
        self.alpha = 0.3
        self.gamma = 0.9
        self.epsilon = 0.2
        self._rng = random.Random(0)

    def start(self, config: dict[str, Any]) -> None:
        self.alpha = float(config.get("alpha", 0.3))
        self.gamma = float(config.get("gamma", 0.9))
        self.epsilon = float(config.get("epsilon", 0.2))
        self._rng = random.Random(int(config.get("seed", 0)))
        schema = dict(config.get("schema") or DEFAULT_SCHEMA)
        ops = list(schema.get("op", {}).get("enum") or ["noop", "refund"])
        amounts = list(schema.get("amount", {}).get("boundaries") or [0, 50, 100, 120, 200])
        self.actions = []
        for op in ops:
            if op == "noop":
                self.actions.append({"op": "noop"})
            else:
                for amt in amounts:
                    self.actions.append({"op": op, "amount": int(amt)})
        if not self.actions:
            self.actions = [{"op": "noop"}]

    def _key(self, observation: dict[str, Any]) -> str:
        return f"{observation.get('step', 0)}:{observation.get('balance', 0)}"

    def _action_key(self, action: dict[str, Any]) -> str:
        return f"{action.get('op')}:{action.get('amount', '')}"

    def act(self, observation: dict[str, Any]) -> dict[str, Any]:
        state = self._key(observation)
        if self._rng.random() < self.epsilon or state not in self.q:
            return dict(self._rng.choice(self.actions))
        best_key = max(self.q[state].items(), key=lambda kv: kv[1])[0]
        for action in self.actions:
            if self._action_key(action) == best_key:
                return dict(action)
        return dict(self._rng.choice(self.actions))

    def learn(self, transition: dict[str, Any]) -> dict[str, Any]:
        s = self._key(transition["obs"])
        a = self._action_key(transition["action"])
        r = float(transition.get("reward", 0.0))
        ns = self._key(transition.get("next_obs") or {})
        self.q.setdefault(s, {})
        old = self.q[s].get(a, 0.0)
        next_max = max(self.q.get(ns, {}).values()) if self.q.get(ns) else 0.0
        self.q[s][a] = old + self.alpha * (r + self.gamma * next_max - old)
        return {"td_error": abs(r + self.gamma * next_max - old)}

    def save(self) -> dict[str, Any]:
        return {
            "q": self.q,
            "actions": self.actions,
            "alpha": self.alpha,
            "gamma": self.gamma,
            "epsilon": self.epsilon,
            "rng_state": self._rng.getstate(),
        }

    def load(self, state: dict[str, Any]) -> None:
        self.q = dict(state.get("q") or {})
        self.actions = list(state.get("actions") or self.actions)
        if "alpha" in state:
            self.alpha = float(state["alpha"])
        if "gamma" in state:
            self.gamma = float(state["gamma"])
        if "epsilon" in state:
            self.epsilon = float(state["epsilon"])
        if state.get("rng_state") is not None:
            self._rng.setstate(state["rng_state"])


@register("rl_tabular")
class TabularRLAttack:
    """Local RL baseline; Q-table persists across episodes via checkpoint/restore."""

    COHORT = "optimized"

    def __init__(self) -> None:
        self._trainer = TabularQTrainer()
        self._obs: dict[str, Any] = {"step": 0, "balance": 500}
        self._last_action: dict[str, Any] = {"op": "noop"}
        self._queries = 0
        self._episodes = 0
        self._broker: Any | None = None
        self._env: Any | None = None
        self._learning = True
        self._probe = False

    def initialize(self, config: dict[str, Any]) -> None:
        self._trainer.start(config)
        self._obs = {"step": 0, "balance": int(config.get("balance", 500))}
        # Default ON: candidate probe via broker when runtime is bound (Gate 2).
        self._probe = bool(config.get("probe_broker", True))
        self._queries = 0
        self._episodes = 0
        adapter = config.get("adapter")
        if adapter is not None:
            if not isinstance(adapter, ExternalTrainerAdapter):
                raise TypeError("config['adapter'] must implement ExternalTrainerAdapter")
            self._trainer = adapter  # type: ignore[assignment]
            self._trainer.start(config)

    def bind_runtime(
        self,
        *,
        broker: Any | None = None,
        env: Any | None = None,
        learning: bool = True,
    ) -> None:
        self._broker = broker
        self._env = env
        self._learning = learning

    def propose(self) -> dict[str, Any]:
        action = self._trainer.act(self._obs)
        # Optional broker probe for candidate metering when enabled.
        if self._probe and self._broker is not None and self._env is not None and self._learning:
            score, decision = evaluate_candidate_trajectory(
                self._env,
                action,
                self._broker,
                caller="rl_tabular:probe",
            )
            self._queries += 1
            accepted = getattr(decision, "accepted", None)
            # Bias epsilon-greedy via immediate public reward signal.
            if accepted is True:
                self._trainer.learn(
                    {
                        "obs": self._obs,
                        "action": action,
                        "reward": 1.0 + score,
                        "next_obs": self._obs,
                    }
                )
        action = dict(action)
        action["_cohort"] = self.COHORT
        action["_strategy"] = "rl_tabular"
        self._last_action = {k: v for k, v in action.items() if not str(k).startswith("_")}
        return action

    def observe(self, feedback: dict[str, Any]) -> None:
        self._episodes += 1
        next_obs = dict(feedback.get("observation") or self._obs)
        reward = float(feedback.get("reward", 0.0))
        if feedback.get("verifier_accepted"):
            reward += 1.0
        if self._learning:
            self._trainer.learn(
                {
                    "obs": self._obs,
                    "action": self._last_action,
                    "reward": reward,
                    "next_obs": next_obs,
                }
            )
        self._obs = next_obs

    def checkpoint(self) -> dict[str, Any]:
        return {
            "schema_version": "1",
            "strategy": "rl_tabular",
            "cohort": self.COHORT,
            "queries": self._queries,
            "episodes": self._episodes,
            "obs": self._obs,
            "last_action": self._last_action,
            "probe_broker": self._probe,
            "trainer": self._trainer.save() if hasattr(self._trainer, "save") else {},
        }

    def restore(self, state: dict[str, Any]) -> None:
        self._queries = int(state.get("queries", 0))
        self._episodes = int(state.get("episodes", 0))
        self._obs = dict(state.get("obs") or self._obs)
        self._last_action = dict(state.get("last_action") or self._last_action)
        self._probe = bool(state.get("probe_broker", self._probe))
        trainer_state = state.get("trainer") or {}
        if trainer_state and hasattr(self._trainer, "load"):
            self._trainer.load(trainer_state)
