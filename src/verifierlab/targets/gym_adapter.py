"""Gymnasium environment adapter (``[gym]`` extra).

**Live path:** wraps a real ``gymnasium.Env`` as a native
:class:`~verifierlab.api.protocols.EnvironmentTarget` and as an
:class:`~verifierlab.targets.conformance.EnvAdapter`.

When ``gymnasium`` is not installed, constructing a live env raises
``ImportError`` with an install hint — there is no fake pass stub.

For OpenEnv, see :mod:`verifierlab.targets.openenv_adapter`.

Install::

    pip install "verifierlab[gym]"
"""

from __future__ import annotations

import json
from typing import Any


def gymnasium_available() -> bool:
    """Return True when the ``gymnasium`` package is importable."""
    try:
        import gymnasium  # noqa: F401
    except ImportError:
        return False
    return True


def _jsonable(value: Any) -> Any:
    """Convert numpy / gym values into JSON-safe Python objects."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    # numpy scalar / array without importing numpy at module level
    tolist = getattr(value, "tolist", None)
    if callable(tolist):
        return _jsonable(tolist())
    item = getattr(value, "item", None)
    if callable(item):
        try:
            return _jsonable(item())
        except (ValueError, TypeError):
            pass
    return str(value)


def _extract_action(action: dict[str, Any] | int | float) -> Any:
    if isinstance(action, dict):
        if "action" in action:
            return action["action"]
        if "op" in action and action.get("op") == "noop":
            return 0
        # Best-effort: first numeric-looking value
        for key in ("a", "act", "discrete"):
            if key in action:
                return action[key]
        return 0
    return action


class GymnasiumEnvironment:
    """Native :class:`~verifierlab.api.protocols.EnvironmentTarget` over a gym env.

    Requires ``gymnasium`` (or legacy ``gym``) at construction time.
    """

    def __init__(
        self,
        env: Any,
        *,
        env_id: str | None = None,
        max_steps: int = 200,
    ) -> None:
        self._env = env
        self.env_id = env_id or getattr(getattr(env, "spec", None), "id", type(env).__name__)
        self.max_steps = max_steps
        self._seed = 0
        self._step_count = 0
        self._done = False
        self._actions: list[dict[str, Any]] = []
        self._last_obs: Any = None
        self._last_info: dict[str, Any] = {}
        self._episode_reward = 0.0

    @classmethod
    def from_id(cls, env_id: str, *, max_steps: int = 200, **kwargs: Any) -> GymnasiumEnvironment:
        """Create and wrap ``gymnasium.make(env_id)``."""
        try:
            import gymnasium as gym
        except ImportError as exc:
            raise ImportError(
                "GymnasiumEnvironment.from_id requires gymnasium; "
                "install with: pip install 'verifierlab[gym]'"
            ) from exc
        env = gym.make(env_id, **kwargs)
        return cls(env, env_id=env_id, max_steps=max_steps)

    @classmethod
    def tiny_discrete(cls, *, max_steps: int = 8) -> GymnasiumEnvironment:
        """Wrap a minimal custom Discrete env (no classic-control assets)."""
        try:
            import gymnasium as gym
            from gymnasium import spaces
        except ImportError as exc:
            raise ImportError(
                "tiny_discrete requires gymnasium; install with: pip install 'verifierlab[gym]'"
            ) from exc

        class TinyDiscreteEnv(gym.Env[Any, Any]):  # type: ignore[misc]
            metadata: dict[str, Any] = {"render_modes": []}  # noqa: RUF012

            def __init__(self) -> None:
                super().__init__()
                self.action_space = spaces.Discrete(2)
                self.observation_space = spaces.Discrete(4)
                self._state = 0

            def reset(
                self,
                *,
                seed: int | None = None,
                options: dict[str, Any] | None = None,
            ) -> tuple[int, dict[str, Any]]:
                super().reset(seed=seed)
                self._state = 0
                return self._state, {"options": options or {}}

            def step(self, action: int) -> tuple[int, float, bool, bool, dict[str, Any]]:
                self._state = (int(self._state) + int(action)) % 4
                terminated = self._state == 3
                return self._state, 1.0 if terminated else 0.0, terminated, False, {}

        return cls(TinyDiscreteEnv(), env_id="TinyDiscrete-v0", max_steps=max_steps)

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._seed = seed
        self._step_count = 0
        self._done = False
        self._actions = []
        self._episode_reward = 0.0
        result = self._env.reset(seed=seed)
        if isinstance(result, tuple) and len(result) == 2:
            obs, info = result
        else:
            obs, info = result, {}
        self._last_obs = obs
        self._last_info = dict(info) if isinstance(info, dict) else {"info": info}
        return {
            "seed": seed,
            "env_id": self.env_id,
            "observation": _jsonable(obs),
            "info": _jsonable(self._last_info),
        }

    def act(self, action: dict[str, Any]) -> dict[str, Any]:
        if self._done:
            raise RuntimeError("episode already finished")
        clean = {k: v for k, v in action.items() if not str(k).startswith("_")}
        raw = _extract_action(clean)
        self._actions.append(dict(clean))
        step_result = self._env.step(raw)
        # gymnasium: obs, reward, terminated, truncated, info
        # legacy gym: obs, reward, done, info
        if len(step_result) == 5:
            obs, reward, terminated, truncated, info = step_result
            done = bool(terminated or truncated)
        else:
            obs, reward, done, info = step_result
            terminated, truncated = bool(done), False
        self._last_obs = obs
        self._last_info = dict(info) if isinstance(info, dict) else {"info": info}
        self._step_count += 1
        self._episode_reward += float(reward)
        if done or self._step_count >= self.max_steps:
            self._done = True
        return {
            "observation": _jsonable(obs),
            "reward": float(reward),
            "done": self._done,
            "terminated": bool(terminated),
            "truncated": bool(truncated) if len(step_result) == 5 else False,
            "info": _jsonable(self._last_info),
            "resources": {"steps": 1, "env_steps": self._step_count},
        }

    def finalize(self) -> dict[str, Any]:
        self._done = True
        return {
            "schema_version": "1",
            "seed": self._seed,
            "env_id": self.env_id,
            "steps": list(self._actions),
            "observation": _jsonable(self._last_obs),
            "episode_reward": self._episode_reward,
            "n_steps": self._step_count,
            "framework": "gymnasium",
        }

    def snapshot(self) -> bytes:
        payload = {
            "seed": self._seed,
            "step_count": self._step_count,
            "done": self._done,
            "actions": self._actions,
            "last_obs": _jsonable(self._last_obs),
            "last_info": _jsonable(self._last_info),
            "episode_reward": self._episode_reward,
            "env_id": self.env_id,
            "max_steps": self.max_steps,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def restore(self, snapshot: bytes) -> None:
        state = json.loads(snapshot.decode("utf-8"))
        self._seed = int(state["seed"])
        self._step_count = int(state["step_count"])
        self._done = bool(state["done"])
        self._actions = list(state["actions"])
        self._last_obs = state["last_obs"]
        self._last_info = dict(state["last_info"])
        self._episode_reward = float(state["episode_reward"])
        self.env_id = str(state["env_id"])
        self.max_steps = int(state["max_steps"])
        # Re-seed underlying env; full physics restore is env-specific.
        self._env.reset(seed=self._seed)
        for action in self._actions:
            self._env.step(_extract_action(action))

    def close(self) -> None:
        close = getattr(self._env, "close", None)
        if callable(close):
            close()


class GymAdapter:
    """EnvAdapter over a live Gymnasium environment (requires ``[gym]``)."""

    name = "gym"

    def __init__(
        self,
        *,
        env_id: str = "TinyDiscrete-v0",
        version: str = "0.1",
        env: Any | None = None,
        max_steps: int = 200,
    ) -> None:
        self.env_id = env_id
        self.version = version
        self.max_steps = max_steps
        self._steps: list[dict[str, Any]] = []
        self._seed = 0
        self._live: GymnasiumEnvironment | None = None
        self._gym_module: Any = None

        try:
            import gymnasium as gym

            self._gym_module = gym
        except ImportError:
            try:
                import gym as gym_legacy

                self._gym_module = gym_legacy
            except ImportError:
                self._gym_module = None

        if env is not None:
            self._live = GymnasiumEnvironment(env, env_id=env_id, max_steps=max_steps)
        elif self._gym_module is not None:
            if env_id in {"TinyDiscrete-v0", "CartPoleStub-v0"}:
                self._live = GymnasiumEnvironment.tiny_discrete(max_steps=max_steps)
                self.env_id = str(self._live.env_id)
            else:
                self._live = GymnasiumEnvironment.from_id(env_id, max_steps=max_steps)
        else:
            raise ImportError(
                "GymAdapter requires gymnasium; install with: pip install 'verifierlab[gym]'"
            )

    @property
    def integration_status(self) -> str:
        return "live"

    def capture_config(self) -> dict[str, Any]:
        return {
            "framework": "gymnasium",
            "version": self.version,
            "env_id": self.env_id,
            "sdk_available": self._gym_module is not None,
            "integration_status": self.integration_status,
            "live_env": True,
        }

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._seed = seed
        self._steps = []
        assert self._live is not None
        return self._live.reset(seed=seed)

    def step(self, action: dict[str, Any]) -> dict[str, Any]:
        self._steps.append(dict(action))
        assert self._live is not None
        result = self._live.act(action)
        return {
            "observation": result.get("observation"),
            "reward": result.get("reward", 0.0),
            "resources": result.get("resources", {"steps": 1}),
            "terminated": result.get("terminated", False),
            "truncated": result.get("truncated", False),
            "done": result.get("done", False),
        }

    def finalize(self) -> dict[str, Any]:
        assert self._live is not None
        traj = self._live.finalize()
        if not traj.get("steps"):
            traj["steps"] = list(self._steps)
        traj["integration_status"] = "live"
        return traj

    def map_timeout(self, exc: Exception) -> dict[str, Any]:
        return {"status": "timeout", "error": str(exc), "framework": "gymnasium"}
