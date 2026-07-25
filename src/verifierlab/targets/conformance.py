"""Adapter conformance harness shared by Inspect/Harbor/Gym/OpenEnv/NeMo."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class EnvAdapter(Protocol):
    name: str

    def capture_config(self) -> dict[str, Any]:
        ...

    def reset(self, *, seed: int) -> dict[str, Any]:
        ...

    def step(self, action: dict[str, Any]) -> dict[str, Any]:
        ...

    def finalize(self) -> dict[str, Any]:
        ...

    def map_timeout(self, exc: Exception) -> dict[str, Any]:
        ...


@dataclass
class ConformanceResult:
    adapter: str
    checks: dict[str, bool] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return all(self.checks.values()) if self.checks else False

    def as_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "ok": self.ok,
            "checks": dict(self.checks),
            "details": dict(self.details),
        }


def run_conformance(adapter: EnvAdapter, *, seed: int = 0) -> ConformanceResult:
    """Exercise config capture, trajectory preservation, timeout mapping, accounting."""
    result = ConformanceResult(adapter=getattr(adapter, "name", type(adapter).__name__))
    cfg = adapter.capture_config()
    result.checks["config_capture"] = isinstance(cfg, dict) and "version" in cfg

    obs = adapter.reset(seed=seed)
    step = adapter.step({"op": "noop"})
    traj = adapter.finalize()
    result.checks["raw_trajectory_preservation"] = (
        isinstance(traj, dict) and "steps" in traj and isinstance(obs, dict)
    )
    result.checks["resource_accounting"] = "resources" in step or "reward" in step

    timeout = adapter.map_timeout(TimeoutError("simulated"))
    result.checks["timeout_mapping"] = timeout.get("status") == "timeout"

    # Hidden-label separation: adapter payloads must not include ground-truth labels.
    blob = str(traj) + str(step) + str(obs)
    result.checks["hidden_label_separation"] = "hidden_label" not in blob and "gt_label" not in blob

    # Version drift marker present in config.
    result.checks["version_drift_field"] = "version" in cfg and "framework" in cfg

    result.details["config"] = cfg
    result.details["trajectory_keys"] = sorted(traj.keys())
    return result
