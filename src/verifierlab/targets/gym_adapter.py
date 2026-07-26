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


def capture_wrapper_stack(env: Any) -> list[str]:
    """Return the Gymnasium wrapper class chain (outer → unwrapped)."""
    stack: list[str] = []
    current: Any = env
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        stack.append(type(current).__name__)
        inner = getattr(current, "env", None)
        if inner is None or inner is current:
            unwrapped = getattr(current, "unwrapped", None)
            if unwrapped is not None and unwrapped is not current and id(unwrapped) not in seen:
                stack.append(type(unwrapped).__name__)
            break
        current = inner
    return stack


def _describe_spaces(env: Any) -> dict[str, Any]:
    """Capture observation/action space metadata for trajectory profiles."""

    def _space_info(space: Any) -> dict[str, Any]:
        if space is None:
            return {"type": "unknown"}
        info: dict[str, Any] = {"type": type(space).__name__}
        if hasattr(space, "n"):
            info["n"] = int(space.n)
        if hasattr(space, "shape") and space.shape is not None:
            info["shape"] = list(space.shape)
        if hasattr(space, "spaces") and isinstance(space.spaces, dict):
            info["spaces"] = {str(k): _space_info(v) for k, v in space.spaces.items()}
        return info

    return {
        "observation_space": _space_info(getattr(env, "observation_space", None)),
        "action_space": _space_info(getattr(env, "action_space", None)),
    }


class GymnasiumEnvironment:
    """Native :class:`~verifierlab.api.protocols.EnvironmentTarget` over a gym env.

    Requires ``gymnasium`` at construction time. Legacy ``gym`` may import for
    local experiments but is **not** a beta release claim.
    """

    def __init__(
        self,
        env: Any,
        *,
        env_id: str | None = None,
        max_steps: int = 200,
        wrapper_stack: list[str] | None = None,
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
        self._wrapper_stack = list(wrapper_stack or capture_wrapper_stack(env))
        self._spaces: dict[str, Any] = _describe_spaces(env)

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

    @classmethod
    def dict_space_env(cls, *, max_steps: int = 8) -> GymnasiumEnvironment:
        """Custom env with Dict observation space (deterministic)."""
        try:
            import gymnasium as gym
            from gymnasium import spaces
        except ImportError as exc:
            raise ImportError(
                "dict_space_env requires gymnasium; install with: pip install 'verifierlab[gym]'"
            ) from exc

        class DictObsEnv(gym.Env[Any, Any]):  # type: ignore[misc]
            metadata: dict[str, Any] = {"render_modes": []}  # noqa: RUF012

            def __init__(self) -> None:
                super().__init__()
                self.action_space = spaces.Discrete(3)
                self.observation_space = spaces.Dict(
                    {
                        "pos": spaces.Discrete(5),
                        "flag": spaces.Discrete(2),
                    }
                )
                self._pos = 0
                self._flag = 0

            def reset(
                self,
                *,
                seed: int | None = None,
                options: dict[str, Any] | None = None,
            ) -> tuple[dict[str, int], dict[str, Any]]:
                super().reset(seed=seed)
                self._pos = 0
                self._flag = 0
                return {"pos": self._pos, "flag": self._flag}, {"options": options or {}}

            def step(
                self, action: int
            ) -> tuple[dict[str, int], float, bool, bool, dict[str, Any]]:
                self._pos = (self._pos + int(action)) % 5
                self._flag = int(self._pos == 4)
                terminated = self._pos == 4
                truncated = False
                return (
                    {"pos": self._pos, "flag": self._flag},
                    1.0 if terminated else 0.0,
                    terminated,
                    truncated,
                    {},
                )

        return cls(DictObsEnv(), env_id="DictObs-v0", max_steps=max_steps)

    @classmethod
    def non_json_obs_env(cls, *, max_steps: int = 4) -> GymnasiumEnvironment:
        """Env whose observations are bytes / custom objects (non-JSON)."""
        try:
            import gymnasium as gym
            from gymnasium import spaces
        except ImportError as exc:
            raise ImportError(
                "non_json_obs_env requires gymnasium; "
                "install with: pip install 'verifierlab[gym]'"
            ) from exc

        class Blob:
            def __init__(self, n: int) -> None:
                self.n = n

            def __repr__(self) -> str:
                return f"Blob({self.n})"

        class NonJsonObsEnv(gym.Env[Any, Any]):  # type: ignore[misc]
            metadata: dict[str, Any] = {"render_modes": []}  # noqa: RUF012

            def __init__(self) -> None:
                super().__init__()
                self.action_space = spaces.Discrete(2)
                self.observation_space = spaces.Discrete(4)
                self._n = 0

            def reset(
                self,
                *,
                seed: int | None = None,
                options: dict[str, Any] | None = None,
            ) -> tuple[Any, dict[str, Any]]:
                super().reset(seed=seed)
                self._n = 0
                return Blob(self._n), {"options": options or {}}

            def step(self, action: int) -> tuple[Any, float, bool, bool, dict[str, Any]]:
                self._n = (self._n + int(action)) % 4
                terminated = self._n == 3
                return Blob(self._n), 1.0 if terminated else 0.0, terminated, False, {}

        return cls(NonJsonObsEnv(), env_id="NonJsonObs-v0", max_steps=max_steps)

    @classmethod
    def truncated_env(cls, *, truncate_after: int = 2, max_steps: int = 8) -> GymnasiumEnvironment:
        """Env that truncates independently of termination."""
        try:
            import gymnasium as gym
            from gymnasium import spaces
        except ImportError as exc:
            raise ImportError(
                "truncated_env requires gymnasium; install with: pip install 'verifierlab[gym]'"
            ) from exc

        class TruncateEnv(gym.Env[Any, Any]):  # type: ignore[misc]
            metadata: dict[str, Any] = {"render_modes": []}  # noqa: RUF012

            def __init__(self) -> None:
                super().__init__()
                self.action_space = spaces.Discrete(2)
                self.observation_space = spaces.Discrete(10)
                self._t = 0
                self._state = 0

            def reset(
                self,
                *,
                seed: int | None = None,
                options: dict[str, Any] | None = None,
            ) -> tuple[int, dict[str, Any]]:
                super().reset(seed=seed)
                self._t = 0
                self._state = 0
                return self._state, {}

            def step(self, action: int) -> tuple[int, float, bool, bool, dict[str, Any]]:
                self._t += 1
                self._state = (self._state + int(action)) % 10
                terminated = self._state == 9
                truncated = self._t >= truncate_after and not terminated
                return self._state, 0.0, terminated, truncated, {"t": self._t}

        return cls(TruncateEnv(), env_id="Truncate-v0", max_steps=max_steps)

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
            "spaces": self._spaces,
            "wrapper_stack": list(self._wrapper_stack),
        }

    def act(self, action: dict[str, Any]) -> dict[str, Any]:
        if self._done:
            raise RuntimeError("episode already finished")
        clean = {k: v for k, v in action.items() if not str(k).startswith("_")}
        raw = _extract_action(clean)
        # Validate against action space when available.
        space = getattr(self._env, "action_space", None)
        if space is not None and hasattr(space, "contains"):
            try:
                if not space.contains(raw):
                    return {
                        "observation": _jsonable(self._last_obs),
                        "reward": 0.0,
                        "done": False,
                        "terminated": False,
                        "truncated": False,
                        "info": {"invalid_action": True, "action": _jsonable(raw)},
                        "resources": {"steps": 0, "env_steps": self._step_count},
                        "error": "invalid_action",
                    }
            except (TypeError, ValueError):
                return {
                    "observation": _jsonable(self._last_obs),
                    "reward": 0.0,
                    "done": False,
                    "terminated": False,
                    "truncated": False,
                    "info": {"invalid_action": True, "action": _jsonable(raw)},
                    "resources": {"steps": 0, "env_steps": self._step_count},
                    "error": "invalid_action",
                }
        self._actions.append(dict(clean))
        step_result = self._env.step(raw)
        # gymnasium: obs, reward, terminated, truncated, info
        # legacy gym: obs, reward, done, info  (compat import only; not a beta claim)
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
            "spaces": self._spaces,
            "wrapper_stack": list(self._wrapper_stack),
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
    """EnvAdapter over a live Gymnasium environment (requires ``[gym]``).

    Release-qualified path uses **gymnasium only**. Legacy ``gym`` is not a
    beta claim; construction requires ``gymnasium``.
    """

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
            self._gym_module = None

        if env is not None:
            self._live = GymnasiumEnvironment(env, env_id=env_id, max_steps=max_steps)
        elif self._gym_module is not None:
            if env_id in {"TinyDiscrete-v0", "CartPoleStub-v0"}:
                self._live = GymnasiumEnvironment.tiny_discrete(max_steps=max_steps)
                self.env_id = str(self._live.env_id)
            elif env_id == "DictObs-v0":
                self._live = GymnasiumEnvironment.dict_space_env(max_steps=max_steps)
            elif env_id == "NonJsonObs-v0":
                self._live = GymnasiumEnvironment.non_json_obs_env(max_steps=max_steps)
            elif env_id == "Truncate-v0":
                self._live = GymnasiumEnvironment.truncated_env(max_steps=max_steps)
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
        assert self._live is not None
        return {
            "framework": "gymnasium",
            "version": self.version,
            "env_id": self.env_id,
            "sdk_available": self._gym_module is not None,
            "integration_status": self.integration_status,
            "live_env": True,
            "legacy_gym_claimed": False,
            "spaces": self._live._spaces,
            "wrapper_stack": list(self._live._wrapper_stack),
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

    def act(self, action: dict[str, Any]) -> dict[str, Any]:
        """EnvironmentTarget alias for :meth:`step`."""
        return self.step(action)

    def finalize(self) -> dict[str, Any]:
        assert self._live is not None
        traj = self._live.finalize()
        if not traj.get("steps"):
            traj["steps"] = list(self._steps)
        traj["integration_status"] = "live"
        return traj

    def map_timeout(self, exc: Exception) -> dict[str, Any]:
        return {"status": "timeout", "error": str(exc), "framework": "gymnasium"}
