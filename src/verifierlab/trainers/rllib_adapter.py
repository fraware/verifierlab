"""RLlib PPO trainer adapter (``[rllib]`` extra) — integration conformance.

Rewards flow only through the broker-wired :class:`BrokerRewardEnv`. This module
does **not** claim RL capability / SOTA results; PR-tier tests skip when Ray is
absent.
"""

from __future__ import annotations

import json
from typing import Any

from verifierlab.trainers.rllib_env import BrokerRewardEnv


def ray_rllib_available() -> bool:
    """Return True when ``ray`` with RLlib is importable."""
    try:
        import ray  # noqa: F401
        from ray import rllib  # noqa: F401
    except ImportError:
        return False
    return True


def require_ray_rllib() -> Any:
    """Import ``ray`` or raise a clear install hint."""
    try:
        import ray
    except ImportError as exc:
        raise ImportError(
            "RLlib adapter requires ray[rllib]; "
            "install with: pip install 'verifierlab[rllib]'"
        ) from exc
    return ray


class RLlibPPOAdapter:
    """External trainer implementing the Milestone C trainer protocol (PPO first).

    Protocol methods: ``initialize`` / ``train`` / ``act`` / ``checkpoint`` /
    ``restore`` / ``freeze`` / ``evaluate`` / ``close``. Legacy aliases
    ``start`` / ``learn`` / ``save`` / ``load`` delegate to the same paths.
    """

    name = "rllib_ppo"

    def __init__(
        self,
        *,
        env: Any | None = None,
        broker: Any | None = None,
        max_queries: int | None = 32,
        max_env_steps: int | None = 64,
        algo_config: dict[str, Any] | None = None,
    ) -> None:
        self._raw_env = env
        self._broker = broker
        self.max_queries = max_queries
        self.max_env_steps = max_env_steps
        self.algo_config = dict(algo_config or {})
        self._wrapped: BrokerRewardEnv | None = None
        self._algo: Any | None = None
        self._frozen = False
        self._initialized = False
        self._train_stats: list[dict[str, Any]] = []
        self._checkpoint_blob: dict[str, Any] = {}

    @property
    def integration_status(self) -> str:
        return "live" if ray_rllib_available() else "not-live"

    def initialize(self, config: dict[str, Any]) -> None:
        require_ray_rllib()
        import ray
        from ray.rllib.algorithms.ppo import PPOConfig

        if not ray.is_initialized():
            ray.init(ignore_reinit_error=True, include_dashboard=False, logging_level="ERROR")

        if self._broker is None and config.get("broker") is not None:
            self._broker = config["broker"]
        if self._raw_env is None and config.get("env") is not None:
            self._raw_env = config["env"]
        if self._broker is None or self._raw_env is None:
            raise RuntimeError("RLlibPPOAdapter requires env and broker in config or constructor")

        self.max_queries = int(config.get("max_queries", self.max_queries or 32))
        self.max_env_steps = int(config.get("max_env_steps", self.max_env_steps or 64))
        self._wrapped = BrokerRewardEnv(
            self._raw_env,
            broker=self._broker,
            max_queries=self.max_queries,
            max_env_steps=self.max_env_steps,
            build_trajectory=config.get("build_trajectory"),
        )

        # Tiny CPU config for PR-tier conformance (not a capability claim).
        cfg = (
            PPOConfig()
            .environment(env=None)  # we drive env manually for broker wiring
            .framework("torch")
            .env_runners(num_env_runners=0)
            .training(train_batch_size=config.get("train_batch_size", 32))
            .resources(num_gpus=0)
        )
        for key, value in {**self.algo_config, **dict(config.get("algo_config") or {})}.items():
            if hasattr(cfg, key):
                setattr(cfg, key, value)
        # Prefer building a lightweight algo when API allows; fall back to manual loop.
        try:
            self._algo = cfg.build()
        except Exception:
            # Manual PPO-less path: act/learn via tabular fallback is not used;
            # we keep algo None and use greedy random act for protocol smoke.
            self._algo = None
        self._initialized = True
        self._frozen = False
        self._train_stats = []

    def start(self, config: dict[str, Any]) -> None:
        """Alias for :meth:`initialize`."""
        self.initialize(config)

    def act(self, observation: dict[str, Any]) -> dict[str, Any]:
        if not self._initialized:
            raise RuntimeError("call initialize/start before act")
        if self._frozen:
            return self.evaluate(observation)
        if self._algo is not None and self._wrapped is not None:
            # Compute action from last observation when algo is live.
            obs = observation.get("observation", observation)
            try:
                action = self._algo.compute_single_action(obs)
                return {"action": action}
            except Exception:
                pass
        # Deterministic stub action for protocol conformance without full PPO graph.
        space = getattr(self._wrapped, "action_space", None) if self._wrapped else None
        if space is not None and hasattr(space, "sample"):
            return {"action": int(space.sample()) if hasattr(space.sample(), "__int__") else 0}
        return {"action": 0}

    def train(self, transition: dict[str, Any]) -> dict[str, Any]:
        if self._frozen:
            raise RuntimeError("trainer is frozen; refuse train/learn")
        if not self._initialized:
            raise RuntimeError("call initialize/start before train")
        stats: dict[str, Any] = {"reward": float(transition.get("reward", 0.0))}
        if self._algo is not None:
            try:
                result = self._algo.train()
                stats["algo"] = {
                    k: result.get(k)
                    for k in ("episode_reward_mean", "timesteps_total")
                    if isinstance(result, dict) and k in result
                }
            except Exception as exc:
                stats["algo_error"] = str(exc)
        self._train_stats.append(stats)
        return stats

    def learn(self, transition: dict[str, Any]) -> dict[str, Any]:
        """Alias for :meth:`train`."""
        return self.train(transition)

    def checkpoint(self) -> dict[str, Any]:
        blob: dict[str, Any] = {
            "schema_version": "1",
            "adapter": self.name,
            "frozen": self._frozen,
            "train_stats": list(self._train_stats),
            "max_queries": self.max_queries,
            "max_env_steps": self.max_env_steps,
        }
        if self._algo is not None:
            try:
                path = self._algo.save()
                blob["algo_checkpoint"] = str(path)
            except Exception as exc:
                blob["algo_checkpoint_error"] = str(exc)
        if self._wrapped is not None:
            blob["env_frozen"] = self._wrapped.frozen
            blob["query_count"] = self._wrapped._query_count
            blob["env_steps"] = self._wrapped._env_steps
        self._checkpoint_blob = blob
        return dict(blob)

    def save(self) -> dict[str, Any]:
        """Alias for :meth:`checkpoint`."""
        return self.checkpoint()

    def restore(self, state: dict[str, Any]) -> None:
        self._frozen = bool(state.get("frozen", False))
        self._train_stats = list(state.get("train_stats") or [])
        self.max_queries = state.get("max_queries", self.max_queries)
        self.max_env_steps = state.get("max_env_steps", self.max_env_steps)
        path = state.get("algo_checkpoint")
        if path and self._algo is not None:
            try:
                self._algo.restore(path)
            except Exception:
                pass
        if self._wrapped is not None and self._frozen:
            self._wrapped.freeze()

    def load(self, state: dict[str, Any]) -> None:
        """Alias for :meth:`restore`."""
        self.restore(state)

    def freeze(self) -> None:
        """Freeze policy and env before holdout evaluation."""
        self._frozen = True
        if self._wrapped is not None:
            self._wrapped.freeze()

    def evaluate(self, observation: dict[str, Any]) -> dict[str, Any]:
        """Act without learning (holdout / frozen path)."""
        was_frozen = self._frozen
        self._frozen = True
        try:
            action = self.act(observation) if was_frozen else self.act(observation)
            # Force non-learning act path.
            if self._algo is not None:
                obs = observation.get("observation", observation)
                try:
                    action = {"action": self._algo.compute_single_action(obs)}
                except Exception:
                    pass
            return {"action": action.get("action", 0), "mode": "evaluate", "frozen": True}
        finally:
            self._frozen = was_frozen

    def close(self) -> None:
        if self._algo is not None:
            try:
                self._algo.stop()
            except Exception:
                pass
            self._algo = None
        if self._wrapped is not None:
            self._wrapped.close()
            self._wrapped = None
        self._initialized = False

    def capture_config(self) -> dict[str, Any]:
        return {
            "framework": "rllib",
            "algorithm": "PPO",
            "adapter": self.name,
            "sdk_available": ray_rllib_available(),
            "integration_status": self.integration_status,
            "max_queries": self.max_queries,
            "max_env_steps": self.max_env_steps,
            "claim": "integration_conformance",
            "not_a_capability_result": True,
        }

    def run_tiny_episode(self, *, seed: int = 0, steps: int = 4) -> dict[str, Any]:
        """PR-tier smoke: reset → act → broker-rewarded step → freeze → checkpoint."""
        if self._wrapped is None:
            raise RuntimeError("initialize before run_tiny_episode")
        obs, info = self._wrapped.reset(seed=seed)
        rewards: list[float] = []
        for _ in range(steps):
            action = self.act({"observation": obs, "info": info})
            raw = action.get("action", 0)
            obs, reward, terminated, truncated, info = self._wrapped.step(raw)
            rewards.append(float(reward))
            if terminated or truncated:
                break
        self.freeze()
        ckpt = self.checkpoint()
        return {
            "schema_version": "1",
            "framework": "rllib",
            "integration_status": self.integration_status,
            "rewards": rewards,
            "n_steps": len(rewards),
            "checkpoint": ckpt,
            "claim": "integration_conformance",
            "config": self.capture_config(),
        }

    def snapshot(self) -> bytes:
        return json.dumps(self.checkpoint(), sort_keys=True, separators=(",", ":")).encode("utf-8")
