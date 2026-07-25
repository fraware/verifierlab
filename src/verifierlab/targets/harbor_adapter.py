"""Harbor adapter (``[harbor]`` extra).

**Live mode (requires ``harbor``):** parses/validates ATIF via Harbor's Pydantic
``Trajectory`` models and ``TrajectoryValidator``, then maps to native
trajectories. Harbor itself orchestrates agents in sandboxes; VerifierLab
consumes Harbor artifacts and types — it does not re-implement the Harbor
runner.

**ATIF log-format regression (no SDK):** ``atif_to_native`` translates ATIF JSON
fixtures. Labeled ``log_format_regression`` — not an empty stub runner.

Harbor on PyPI requires Python ``>=3.12``::

    pip install "verifierlab[harbor]"
    # or: pip install 'harbor>=0.17,<0.21'
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from verifierlab.artifacts.records import TrajectoryRecord

HARBOR_INSTALL = (
    "Harbor live adapter requires the harbor package (Python >=3.12); "
    "install with: pip install 'verifierlab[harbor]'"
)


def harbor_sdk_available() -> bool:
    """Return True when Harbor trajectory types import cleanly.

    On some Windows hosts ``import harbor`` fails because transitive deps
    (``litellm`` → maturin/truststore) fail to build. Treat that as unavailable
    so CI can keep the ATIF log-format regression path green without forcing
    a broken live SDK install.
    """
    try:
        import harbor  # noqa: F401
        from harbor.models.trajectories import Trajectory  # noqa: F401
    except Exception:
        # ImportError *or* broken wheel / native build fallout.
        return False
    return True


def harbor_install_status() -> dict[str, Any]:
    """Structured Harbor availability probe for doctor / docs / skip reasons."""
    if sys.version_info < (3, 12):
        return {
            "available": False,
            "mode": "unsupported_python",
            "reason": (
                f"harbor requires Python >=3.12; "
                f"current is {sys.version_info.major}.{sys.version_info.minor}"
            ),
            "lighter_path": "atif_log_format_regression",
        }
    try:
        import harbor  # noqa: F401
        from harbor.models.trajectories import Trajectory  # noqa: F401
    except ImportError as exc:
        return {
            "available": False,
            "mode": "not_installed",
            "reason": str(exc),
            "lighter_path": "atif_log_format_regression",
            "hint": HARBOR_INSTALL,
        }
    except Exception as exc:
        return {
            "available": False,
            "mode": "broken_install",
            "reason": f"{type(exc).__name__}: {exc}",
            "lighter_path": "atif_log_format_regression",
            "hint": (
                "Harbor SDK import failed (often litellm/maturin on Windows). "
                "Use ATIF JSON fixtures via HarborAdapter without the live SDK; "
                "optional: install harbor in a Linux CI job or conda env."
            ),
        }
    return {
        "available": True,
        "mode": "live",
        "reason": "harbor trajectory types importable",
        "lighter_path": "atif_log_format_regression",
    }


def require_harbor() -> Any:
    """Import ``harbor`` or raise a clear install hint."""
    try:
        import harbor
    except ImportError as exc:
        hint = HARBOR_INSTALL
        if sys.version_info < (3, 12):
            hint += f" (current Python {sys.version_info.major}.{sys.version_info.minor})"
        raise ImportError(hint) from exc
    return harbor


def load_atif_trajectory(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    """Load a Harbor ATIF trajectory from a path or dict."""
    if isinstance(source, dict):
        return dict(source)
    path = Path(source)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"ATIF trajectory must be a JSON object, got {type(data).__name__}")
    return data


def parse_harbor_trajectory(atif: dict[str, Any]) -> Any:
    """Parse ATIF with Harbor's ``Trajectory`` model (requires ``harbor``)."""
    require_harbor()
    try:
        from harbor.models.trajectories import Trajectory
    except ImportError:
        # Older layouts may export differently.
        from harbor.models.trajectories.trajectory import Trajectory

    if hasattr(Trajectory, "model_validate"):
        return Trajectory.model_validate(atif)
    return Trajectory(**atif)


def validate_atif(atif: dict[str, Any] | str | Path) -> bool:
    """Validate ATIF using Harbor's ``TrajectoryValidator`` when available."""
    require_harbor()
    try:
        from harbor.utils.trajectory_validator import TrajectoryValidator
    except ImportError as exc:
        raise ImportError(
            "harbor.utils.trajectory_validator.TrajectoryValidator not found; "
            "upgrade harbor or use parse_harbor_trajectory()"
        ) from exc
    validator = TrajectoryValidator()
    return bool(validator.validate(atif))


def harbor_trajectory_to_dict(trajectory: Any) -> dict[str, Any]:
    """Serialize a Harbor ``Trajectory`` instance to a plain dict."""
    if isinstance(trajectory, dict):
        return dict(trajectory)
    dump = getattr(trajectory, "model_dump", None)
    if callable(dump):
        return dict(dump(mode="json"))
    as_dict = getattr(trajectory, "dict", None)
    if callable(as_dict):
        return dict(as_dict())
    raise TypeError(f"Cannot convert Harbor trajectory of type {type(trajectory).__name__}")


def atif_to_native(trajectory: dict[str, Any]) -> dict[str, Any]:
    """Translate an ATIF trajectory into a native VerifierLab trajectory."""
    steps_out: list[dict[str, Any]] = []
    for step in trajectory.get("steps") or []:
        if not isinstance(step, dict):
            continue
        native_step: dict[str, Any] = {
            "op": "harbor_step",
            "step_id": step.get("step_id"),
            "source": step.get("source"),
            "message": step.get("message"),
            "timestamp": step.get("timestamp"),
        }
        if "tool_calls" in step:
            native_step["tool_calls"] = step["tool_calls"]
        if "observation" in step:
            native_step["observation"] = step["observation"]
        if "reasoning_content" in step:
            native_step["reasoning_content"] = step["reasoning_content"]
        if "metrics" in step:
            native_step["metrics"] = step["metrics"]
        if "model_name" in step:
            native_step["model_name"] = step["model_name"]
        steps_out.append(native_step)

    agent_raw = trajectory.get("agent")
    agent: dict[str, Any] = agent_raw if isinstance(agent_raw, dict) else {}
    metrics_raw = trajectory.get("final_metrics")
    final_metrics: dict[str, Any] = metrics_raw if isinstance(metrics_raw, dict) else {}
    return {
        "schema_version": "1",
        "framework": "harbor",
        "atif_schema_version": trajectory.get("schema_version"),
        "session_id": trajectory.get("session_id"),
        "agent": agent,
        "notes": trajectory.get("notes"),
        "steps": steps_out,
        "final_metrics": final_metrics,
        "resources": {
            "total_prompt_tokens": final_metrics.get("total_prompt_tokens"),
            "total_completion_tokens": final_metrics.get("total_completion_tokens"),
            "total_steps": final_metrics.get("total_steps") or len(steps_out),
        },
        "verifier_trace": {
            "session_id": trajectory.get("session_id"),
            "agent_name": agent.get("name"),
        },
    }


def native_to_atif(trajectory: dict[str, Any]) -> dict[str, Any]:
    """Rebuild an ATIF-compatible trajectory dict from native form (round-trip)."""
    steps: list[dict[str, Any]] = []
    for idx, step in enumerate(trajectory.get("steps") or [], start=1):
        if not isinstance(step, dict):
            continue
        atif_step: dict[str, Any] = {
            "step_id": step.get("step_id") or idx,
            "source": step.get("source") or "agent",
            "message": step.get("message") or "",
        }
        if step.get("timestamp"):
            atif_step["timestamp"] = step["timestamp"]
        for key in ("tool_calls", "observation", "reasoning_content", "metrics", "model_name"):
            if key in step:
                atif_step[key] = step[key]
        steps.append(atif_step)

    return {
        "schema_version": trajectory.get("atif_schema_version") or "ATIF-v1.5",
        "session_id": trajectory.get("session_id") or "unknown",
        "agent": trajectory.get("agent") or {"name": "unknown", "version": "0"},
        "notes": trajectory.get("notes"),
        "final_metrics": trajectory.get("final_metrics") or {},
        "steps": steps,
    }


def native_to_trajectory_record(
    trajectory: dict[str, Any],
    *,
    trajectory_id: str | None = None,
    seed: int = 0,
) -> TrajectoryRecord:
    """Map a native Harbor trajectory into a :class:`TrajectoryRecord`."""
    return TrajectoryRecord(
        trajectory_id=trajectory_id or str(trajectory.get("session_id") or "harbor"),
        seed=int(trajectory.get("seed", seed)),
        steps=list(trajectory.get("steps") or []),
        observation={
            "session_id": trajectory.get("session_id"),
            "agent": trajectory.get("agent") or {},
        },
        metadata={
            "framework": "harbor",
            "atif_schema_version": trajectory.get("atif_schema_version"),
            "final_metrics": trajectory.get("final_metrics") or {},
        },
    )


class HarborAdapter:
    """Map Harbor / ATIF trajectories into native trajectory artifacts.

    Modes:

    * ``live`` — ``harbor`` installed; ATIF parsed/validated with Harbor types.
    * ``log_format_regression`` — ATIF JSON without the Harbor SDK.
    """

    name = "harbor"

    def __init__(
        self,
        *,
        task: str = "demo",
        version: str = "0.1",
        atif: dict[str, Any] | None = None,
        atif_path: str | Path | None = None,
        validate: bool = True,
    ) -> None:
        self.task = task
        self.version = version
        self._steps: list[dict[str, Any]] = []
        self._seed = 0
        self._native: dict[str, Any] | None = None
        self._harbor_obj: Any = None
        self._validated: bool | None = None
        self._mode = "unset"

        if atif_path is None and atif is None:
            raise ValueError(
                "HarborAdapter requires atif= or atif_path= (ATIF artifact). "
                "Harbor agent orchestration runs outside VerifierLab; feed ATIF "
                "JSON produced by Harbor. For live type validation install "
                "harbor: pip install 'verifierlab[harbor]'"
            )

        raw = load_atif_trajectory(atif_path if atif_path is not None else atif)  # type: ignore[arg-type]
        sdk = harbor_sdk_available()
        if sdk:
            self._harbor_obj = parse_harbor_trajectory(raw)
            raw = harbor_trajectory_to_dict(self._harbor_obj)
            if validate:
                try:
                    self._validated = validate_atif(raw)
                except Exception:
                    # Some Harbor versions expect a path; still keep the parse.
                    self._validated = None
            self._mode = "live"
        else:
            self._mode = "log_format_regression"

        self._native = atif_to_native(raw)
        agent = self._native.get("agent") or {}
        if isinstance(agent, dict) and agent.get("name"):
            self.task = str(agent["name"])

    @property
    def integration_status(self) -> str:
        return self._mode

    def capture_config(self) -> dict[str, Any]:
        return {
            "framework": "harbor",
            "version": self.version,
            "task": self.task,
            "sdk_available": harbor_sdk_available(),
            "integration_status": self.integration_status,
            "mode": self._mode,
            "validated": self._validated,
            "harbor_type": type(self._harbor_obj).__name__
            if self._harbor_obj is not None
            else None,
        }

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._seed = seed
        self._steps = []
        assert self._native is not None
        return {
            "seed": seed,
            "task": self.task,
            "session_id": self._native.get("session_id"),
            "n_steps": len(self._native.get("steps") or []),
        }

    def step(self, action: dict[str, Any]) -> dict[str, Any]:
        self._steps.append(dict(action))
        resources: dict[str, Any] = {"queries": 1}
        if self._native and isinstance(self._native.get("resources"), dict):
            resources = {
                **resources,
                **{k: v for k, v in self._native["resources"].items() if v is not None},
            }
        return {
            "observation": {"step": len(self._steps)},
            "reward": 0.0,
            "resources": resources,
            "trajectory_ref": f"harbor:{self.task}:{len(self._steps)}",
        }

    def finalize(self) -> dict[str, Any]:
        assert self._native is not None
        out = dict(self._native)
        out["seed"] = self._seed
        out["integration_status"] = self.integration_status
        if self._steps:
            out["steps"] = list(out.get("steps") or []) + list(self._steps)
        return out

    def map_timeout(self, exc: Exception) -> dict[str, Any]:
        return {"status": "timeout", "error": str(exc), "framework": "harbor"}
