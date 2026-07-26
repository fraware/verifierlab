"""Broker-wired Gymnasium env wrapper for RLlib (rewards via broker only).

Hidden adjudication labels are never exposed to the trainer. Public verifier
feedback is obtained exclusively through :class:`VerifierBroker`.
"""

from __future__ import annotations

from typing import Any

from verifierlab.verifiers.capabilities import AccessDenied

_GT_DENY = frozenset(
    {
        "gt_valid",
        "label",
        "hidden_label",
        "gt_label",
        "commitment_label",
        "ground_truth",
        "vault_secret",
        "private_holdout",
        "is_valid",
    }
)


def _strip_gt(payload: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in payload.items():
        lowered = str(key).lower()
        if lowered in _GT_DENY or lowered.startswith("gt_") or lowered.startswith("hidden_"):
            continue
        if isinstance(value, dict):
            out[key] = _strip_gt(value)
        else:
            out[key] = value
    return out


class BrokerRewardEnv:
    """Wrap a gymnasium-like env so step rewards come from the broker.

    The underlying env may emit shaped rewards; those are discarded. The trainer
    observes only broker-metered public decisions (score / accept channel).
    """

    metadata: dict[str, Any] = {"render_modes": []}  # noqa: RUF012

    def __init__(
        self,
        env: Any,
        *,
        broker: Any,
        max_queries: int | None = None,
        max_env_steps: int | None = None,
        build_trajectory: Any | None = None,
    ) -> None:
        self.env = env
        self.broker = broker
        self.max_queries = max_queries
        self.max_env_steps = max_env_steps
        self.build_trajectory = build_trajectory
        self.action_space = getattr(env, "action_space", None)
        self.observation_space = getattr(env, "observation_space", None)
        self._steps: list[dict[str, Any]] = []
        self._query_count = 0
        self._env_steps = 0
        self._frozen = False
        self._last_obs: Any = None
        self._seed = 0

    def reset(
        self,
        *,
        seed: int | None = None,
        options: dict[str, Any] | None = None,
    ) -> tuple[Any, dict[str, Any]]:
        if self._frozen:
            raise RuntimeError("BrokerRewardEnv is frozen; restore/unfreeze before reset")
        self._steps = []
        self._query_count = 0
        self._env_steps = 0
        if seed is not None:
            self._seed = int(seed)
        result = self.env.reset(seed=seed, options=options) if options is not None else self.env.reset(seed=seed)
        if isinstance(result, tuple) and len(result) == 2:
            obs, info = result
        else:
            obs, info = result, {}
        self._last_obs = obs
        info = _strip_gt(dict(info) if isinstance(info, dict) else {"info": info})
        info["broker_queries"] = self._query_count
        return obs, info

    def step(self, action: Any) -> tuple[Any, float, bool, bool, dict[str, Any]]:
        if self._frozen:
            raise RuntimeError("BrokerRewardEnv is frozen; no further training steps")
        if self.max_env_steps is not None and self._env_steps >= self.max_env_steps:
            raise RuntimeError("env-step budget exhausted")
        if self.max_queries is not None and self._query_count >= self.max_queries:
            raise RuntimeError("query budget exhausted")

        step_result = self.env.step(action)
        if len(step_result) == 5:
            obs, _env_reward, terminated, truncated, info = step_result
        else:
            obs, _env_reward, done, info = step_result
            terminated, truncated = bool(done), False

        self._env_steps += 1
        action_dict = action if isinstance(action, dict) else {"action": action}
        clean = {
            k: v
            for k, v in action_dict.items()
            if not str(k).startswith("_")
            and str(k).lower() not in _GT_DENY
            and not str(k).lower().startswith("gt_")
        }
        for key in clean:
            lowered = str(key).lower()
            if lowered in _GT_DENY or lowered.startswith("gt_") or lowered.startswith("hidden_"):
                raise AccessDenied(f"BrokerRewardEnv refuses GT-bearing action key {key!r}")
        self._steps.append(clean)

        if self.build_trajectory is not None:
            traj = self.build_trajectory(list(self._steps))
        else:
            traj = {
                "schema_version": "1",
                "seed": self._seed,
                "steps": list(self._steps),
                "observation": obs if isinstance(obs, dict) else {"value": str(obs)},
            }
        traj = _strip_gt(traj) if isinstance(traj, dict) else traj
        decision = self.broker.query(traj, caller="rllib:broker_reward_env")
        self._query_count += 1
        reward = (
            float(decision.score)
            if decision.score is not None
            else (1.0 if decision.accepted is True else 0.0)
        )
        info = _strip_gt(dict(info) if isinstance(info, dict) else {"info": info})
        info.update(
            {
                "broker_accepted": decision.accepted,
                "broker_status": decision.status,
                "broker_queries": self._query_count,
                "env_steps": self._env_steps,
            }
        )
        self._last_obs = obs
        return obs, reward, bool(terminated), bool(truncated), info

    def freeze(self) -> None:
        """Freeze before holdout evaluation — no further training queries."""
        self._frozen = True

    def unfreeze(self) -> None:
        self._frozen = False

    @property
    def frozen(self) -> bool:
        return self._frozen

    def close(self) -> None:
        close = getattr(self.env, "close", None)
        if callable(close):
            close()
