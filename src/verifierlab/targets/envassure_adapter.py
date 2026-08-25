"""EnvAssure adapter (``[envassure]`` extra).

**Live path:** when the ``envassure`` package is importable, wrap its public
target API. Live CI hard-fails only when the package installs cleanly.

**Not-live / protocol path:** in-repo fixture backend exercises the expected
actor/evaluator separation without claiming live status. Fixture paths never
report ``integration_status="live"``.

Attackers receive actor observations + public verifier feedback only.
Evaluator state stays in adjudication.

Install (when published)::

    pip install "verifierlab[envassure]"

Note: as of the 0.2.0rc line the ``envassure`` package is not yet published on
PyPI; the extra pin is declared for forward compatibility and installability
gating.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from verifierlab.artifacts.records import TrajectoryRecord

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
        "evaluator_state",
    }
)


def envassure_available() -> bool:
    """Return True when a live-capable ``envassure`` package is importable.

    A package that imports but lacks ``EnvAssureTarget`` / ``make_target`` is
    treated as not installable for live claims (fixture-only remains valid).
    """
    try:
        import envassure
    except ImportError:
        return False
    return hasattr(envassure, "EnvAssureTarget") or hasattr(envassure, "make_target")


def require_envassure() -> Any:
    """Import ``envassure`` or raise a clear install hint."""
    try:
        import envassure
    except ImportError as exc:
        raise ImportError(
            "EnvAssure live adapter requires the envassure package; "
            "install with: pip install 'verifierlab[envassure]'. "
            "Until the package is published, use fixture/protocol mode "
            "(EnvAssureAdapter(fixture=True)) which is explicitly not-live."
        ) from exc
    if not (hasattr(envassure, "EnvAssureTarget") or hasattr(envassure, "make_target")):
        raise ImportError(
            "envassure is installed but exposes neither EnvAssureTarget nor make_target; "
            "use EnvAssureAdapter(fixture=True) (fixture-only / not live-tested)."
        )
    return envassure


def _strip_evaluator(payload: dict[str, Any]) -> dict[str, Any]:
    """Strip evaluator / GT keys from attacker-visible payloads."""
    out: dict[str, Any] = {}
    for key, value in payload.items():
        lowered = str(key).lower()
        if (
            lowered in _GT_DENY
            or lowered.startswith("gt_")
            or lowered.startswith("hidden_")
            or lowered.startswith("evaluator_")
        ):
            continue
        if isinstance(value, dict):
            out[key] = _strip_evaluator(value)
        else:
            out[key] = value
    return out


class FixtureEnvAssureBackend:
    """In-repo protocol backend (not live). Separates actor vs evaluator state."""

    def __init__(self, *, max_steps: int = 4) -> None:
        self.max_steps = max_steps
        self.episode_id = ""
        self._seed = 0
        self._step = 0
        self._done = False
        self._actor_obs: dict[str, Any] = {}
        # Evaluator-only (never returned to attackers / worker finalize).
        self._evaluator_state: dict[str, Any] = {}
        self._actions: list[dict[str, Any]] = []

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._seed = seed
        self._step = 0
        self._done = False
        self._actions = []
        self.episode_id = str(uuid.uuid4())
        self._actor_obs = {"seed": seed, "position": 0, "message": "ready"}
        self._evaluator_state = {
            "hidden_target": "reach_3",
            "valid_threshold": 3,
            "planted_label": False,
        }
        return {
            "episode_id": self.episode_id,
            "observation": dict(self._actor_obs),
            "public_feedback": None,
        }

    def step(
        self,
        action: dict[str, Any],
        *,
        public_feedback: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self._done:
            return {
                "observation": dict(self._actor_obs),
                "done": True,
                "public_feedback": public_feedback,
            }
        clean = {k: v for k, v in action.items() if not str(k).startswith("_")}
        self._actions.append(dict(clean))
        delta = int(clean.get("action", clean.get("delta", 1)))
        pos = int(self._actor_obs["position"]) + delta
        self._actor_obs = {"seed": self._seed, "position": pos, "message": f"moved:{delta}"}
        self._step += 1
        # Update evaluator-only state (not returned below).
        target = int(self._evaluator_state["valid_threshold"])
        self._evaluator_state["planted_label"] = pos >= target
        self._evaluator_state["last_delta"] = delta
        done = pos >= target or self._step >= self.max_steps
        self._done = done
        return {
            "observation": dict(self._actor_obs),
            "done": done,
            "public_feedback": public_feedback,
            "resources": {"steps": 1, "env_steps": self._step},
        }

    def actor_view(self) -> dict[str, Any]:
        return {
            "episode_id": self.episode_id,
            "observation": dict(self._actor_obs),
            "steps": list(self._actions),
        }

    def evaluator_state(self) -> dict[str, Any]:
        """Adjudication-only. Must not appear in worker artifacts."""
        return dict(self._evaluator_state)


class EnvAssureTarget:
    """Native environment target over EnvAssure (live or fixture backend)."""

    def __init__(
        self,
        backend: Any,
        *,
        env_name: str = "envassure",
        live: bool = False,
    ) -> None:
        self._backend = backend
        self.env_name = env_name
        self._live = live
        self._seed = 0
        self._actions: list[dict[str, Any]] = []
        self._last_obs: dict[str, Any] = {}
        self._done = False
        self._public_feedback: list[dict[str, Any]] = []

    @classmethod
    def fixture(cls, *, max_steps: int = 4) -> EnvAssureTarget:
        return cls(FixtureEnvAssureBackend(max_steps=max_steps), env_name="fixture", live=False)

    @classmethod
    def from_sdk(cls, **kwargs: Any) -> EnvAssureTarget:
        mod = require_envassure()
        factory = getattr(mod, "EnvAssureTarget", None) or getattr(mod, "make_target", None)
        if factory is None:
            raise ImportError(
                "envassure is installed but exposes neither EnvAssureTarget nor make_target"
            )
        backend = factory(**kwargs) if callable(factory) else factory
        return cls(backend, env_name=str(kwargs.get("name") or "envassure"), live=True)

    @property
    def integration_status(self) -> str:
        return "live" if self._live else "not-live"

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._seed = seed
        self._actions = []
        self._done = False
        self._public_feedback = []
        result = self._backend.reset(seed=seed)
        obs = result.get("observation") if isinstance(result, dict) else result
        self._last_obs = dict(obs) if isinstance(obs, dict) else {"value": obs}
        # Never leak evaluator state to the worker-facing reset payload.
        return _strip_evaluator(
            {
                "seed": seed,
                "env_name": self.env_name,
                "observation": self._last_obs,
                "episode_id": result.get("episode_id") if isinstance(result, dict) else None,
                "integration_status": self.integration_status,
            }
        )

    def act(self, action: dict[str, Any]) -> dict[str, Any]:
        if self._done:
            raise RuntimeError("episode already finished")
        clean = {k: v for k, v in action.items() if not str(k).startswith("_")}
        # Attackers may attach public verifier feedback only — never evaluator keys.
        feedback = clean.pop("public_feedback", None)
        if isinstance(feedback, dict):
            feedback = _strip_evaluator(feedback)
            self._public_feedback.append(feedback)
        self._actions.append(dict(clean))
        step_fn = getattr(self._backend, "step", None)
        if not callable(step_fn):
            raise RuntimeError("EnvAssure backend missing step()")
        result = step_fn(clean, public_feedback=feedback)
        obs = result.get("observation") if isinstance(result, dict) else {}
        self._last_obs = dict(obs) if isinstance(obs, dict) else {"value": obs}
        self._done = bool(result.get("done")) if isinstance(result, dict) else False
        out = {
            "observation": self._last_obs,
            "done": self._done,
            "public_feedback": feedback,
            "resources": (result.get("resources") if isinstance(result, dict) else {"steps": 1}),
        }
        return _strip_evaluator(out)

    def finalize(self) -> dict[str, Any]:
        self._done = True
        traj = {
            "schema_version": "1",
            "seed": self._seed,
            "env_name": self.env_name,
            "framework": "envassure",
            "steps": list(self._actions),
            "observation": self._last_obs,
            "public_feedback": list(self._public_feedback),
            "integration_status": self.integration_status,
            "n_steps": len(self._actions),
        }
        blob = _strip_evaluator(traj)
        # Hard assert: evaluator/GT tokens must never appear in worker artifacts.
        serialized = json.dumps(blob, default=str)
        for token in ("evaluator_state", "hidden_label", "gt_label", "planted_label"):
            if token in serialized:
                raise RuntimeError(f"EnvAssure worker artifact leaked {token!r}")
        return blob

    def adjudication_evaluator_state(self) -> dict[str, Any]:
        """Coordinator/adjudicator-only accessor for evaluator state."""
        getter = getattr(self._backend, "evaluator_state", None)
        if callable(getter):
            return dict(getter())
        return {}

    def snapshot(self) -> bytes:
        payload = {
            "seed": self._seed,
            "actions": self._actions,
            "last_obs": self._last_obs,
            "done": self._done,
            "public_feedback": self._public_feedback,
            "env_name": self.env_name,
            "live": self._live,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def restore(self, snapshot: bytes) -> None:
        state = json.loads(snapshot.decode("utf-8"))
        self._seed = int(state["seed"])
        self._actions = list(state["actions"])
        self._last_obs = dict(state["last_obs"])
        self._done = bool(state["done"])
        self._public_feedback = list(state["public_feedback"])
        self.env_name = str(state["env_name"])
        self._live = bool(state["live"])
        self._backend.reset(seed=self._seed)
        for action in self._actions:
            self._backend.step(action)

    def to_trajectory_record(self) -> TrajectoryRecord:
        traj = self.finalize()
        return TrajectoryRecord(
            trajectory_id=self.env_name,
            seed=self._seed,
            steps=list(traj.get("steps") or []),
            observation=dict(traj.get("observation") or {}),
            metadata={
                "framework": "envassure",
                "integration_status": self.integration_status,
            },
        )


class EnvAssureAdapter:
    """EnvAdapter over EnvAssure (fixture by default; live when SDK present)."""

    name = "envassure"

    def __init__(
        self,
        *,
        version: str = "0.1",
        fixture: bool | None = None,
        max_steps: int = 4,
        **sdk_kwargs: Any,
    ) -> None:
        self.version = version
        self.max_steps = max_steps
        self._steps: list[dict[str, Any]] = []
        self._seed = 0
        use_fixture = fixture if fixture is not None else not envassure_available()
        if use_fixture:
            self._target = EnvAssureTarget.fixture(max_steps=max_steps)
            self._mode = "not-live"
        else:
            self._target = EnvAssureTarget.from_sdk(**sdk_kwargs)
            self._mode = "live"

    @property
    def integration_status(self) -> str:
        return self._mode

    def capture_config(self) -> dict[str, Any]:
        return {
            "framework": "envassure",
            "version": self.version,
            "sdk_available": envassure_available(),
            "integration_status": self.integration_status,
            "mode": self._mode,
            "boundary": "actor_obs_plus_public_feedback",
            "evaluator_state": "adjudication_only",
        }

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._seed = seed
        self._steps = []
        return self._target.reset(seed=seed)

    def step(self, action: dict[str, Any]) -> dict[str, Any]:
        self._steps.append(dict(action))
        result = self._target.act(action)
        return {
            "observation": result.get("observation"),
            "reward": 0.0,
            "resources": result.get("resources", {"steps": 1}),
            "done": result.get("done", False),
            "public_feedback": result.get("public_feedback"),
        }

    def act(self, action: dict[str, Any]) -> dict[str, Any]:
        """EnvironmentTarget alias for :meth:`step`."""
        return self.step(action)

    def finalize(self) -> dict[str, Any]:
        traj = self._target.finalize()
        if not traj.get("steps"):
            traj["steps"] = list(self._steps)
        return traj

    def map_timeout(self, exc: Exception) -> dict[str, Any]:
        return {"status": "timeout", "error": str(exc), "framework": "envassure"}

    def adjudication_evaluator_state(self) -> dict[str, Any]:
        return self._target.adjudication_evaluator_state()
