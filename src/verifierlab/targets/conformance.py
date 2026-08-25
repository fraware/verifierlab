"""Adapter conformance harness shared by Inspect/Harbor/Gym/OpenEnv/NeMo.

Checks cover AdapterContractVersion surfaces:
- decision normalization (accept / reject / abstain / error / timeout)
- timeout / error taxonomy mapping
- hidden-label isolation (no GT leakage in adapter payloads)
- version reporting / config capture / version drift markers
- raw trajectory preservation + resource accounting
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from verifierlab.api.decision import DecisionKind
from verifierlab.api.verifier import normalize_decision
from verifierlab.targets.contract import ADAPTER_CONTRACT_V1


@runtime_checkable
class EnvAdapter(Protocol):
    name: str

    def capture_config(self) -> dict[str, Any]: ...

    def reset(self, *, seed: int) -> dict[str, Any]: ...

    def step(self, action: dict[str, Any]) -> dict[str, Any]: ...

    def finalize(self) -> dict[str, Any]: ...

    def map_timeout(self, exc: Exception) -> dict[str, Any]: ...


@dataclass
class ConformanceResult:
    adapter: str
    checks: dict[str, bool] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    contract: dict[str, Any] = field(default_factory=lambda: ADAPTER_CONTRACT_V1.as_report())

    @property
    def ok(self) -> bool:
        return all(self.checks.values()) if self.checks else False

    def as_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "ok": self.ok,
            "contract": dict(self.contract),
            "checks": dict(self.checks),
            "details": dict(self.details),
        }


_GT_LEAK_TOKENS = (
    "hidden_label",
    "gt_label",
    "ground_truth",
    "gt_valid",
    "planted_oracle",
)


def _blob_has_gt_leak(blob: str) -> bool:
    lowered = blob.lower()
    return any(token in lowered for token in _GT_LEAK_TOKENS)


def check_decision_normalization() -> dict[str, bool]:
    """Shared decision-normalization suite (adapter-independent)."""
    checks: dict[str, bool] = {}
    accept = normalize_decision({"decision": "accept"})
    checks["decision_accept"] = accept.kind is DecisionKind.ACCEPT and accept.accepted is True

    reject = normalize_decision("reject")
    checks["decision_reject_not_truthy"] = (
        reject.kind is DecisionKind.REJECT and reject.accepted is False
    )

    abstain = normalize_decision({"status": "abstain"})
    checks["decision_abstain"] = abstain.kind is DecisionKind.ABSTAIN and abstain.accepted is None

    timeout = normalize_decision({"decision": "timeout"})
    checks["decision_timeout_is_error"] = timeout.kind is DecisionKind.ERROR

    error = normalize_decision({"decision": "error", "reason_codes": ["adapter_timeout"]})
    checks["decision_error"] = error.kind is DecisionKind.ERROR

    unknown = normalize_decision({"decision": "not-a-real-status"})
    checks["decision_unknown_fail_closed"] = (
        unknown.kind is DecisionKind.ERROR or unknown.kind is DecisionKind.INDETERMINATE
    ) and unknown.accepted is not True

    return checks


def check_timeout_error_mapping(adapter: EnvAdapter) -> dict[str, bool]:
    """Timeout and generic error mapping from adapter → structured status."""
    checks: dict[str, bool] = {}
    timeout = adapter.map_timeout(TimeoutError("simulated"))
    checks["timeout_mapping"] = timeout.get("status") == "timeout"
    checks["timeout_no_gt_leak"] = not _blob_has_gt_leak(str(timeout))

    # Adapters may not expose map_error; fall back to map_timeout on RuntimeError.
    mapper = getattr(adapter, "map_error", None)
    if callable(mapper):
        err = mapper(RuntimeError("simulated"))
    else:
        err = adapter.map_timeout(RuntimeError("simulated"))
    status = str(err.get("status") or "").lower()
    checks["error_mapping"] = status in {"error", "timeout", "failed", "exception"}
    checks["error_no_gt_leak"] = not _blob_has_gt_leak(str(err))
    return checks


def check_isolation(
    obs: dict[str, Any], step: dict[str, Any], traj: dict[str, Any]
) -> dict[str, bool]:
    """Hidden-label / GT isolation across adapter observation surfaces."""
    blob = str(traj) + str(step) + str(obs)
    return {
        "hidden_label_separation": not _blob_has_gt_leak(blob),
        "trajectory_has_steps": isinstance(traj, dict) and "steps" in traj,
        "observation_is_mapping": isinstance(obs, dict),
    }


def run_conformance(adapter: EnvAdapter, *, seed: int = 0) -> ConformanceResult:
    """Exercise config capture, trajectory preservation, timeout/error, isolation."""
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

    result.checks.update(check_timeout_error_mapping(adapter))
    result.checks.update(check_isolation(obs, step, traj))
    result.checks.update({f"norm_{k}": v for k, v in check_decision_normalization().items()})

    # Version drift marker present in config (version_reporting surface).
    result.checks["version_drift_field"] = "version" in cfg and "framework" in cfg
    result.checks["contract_version_reported"] = bool(result.contract.get("digest"))

    result.details["config"] = cfg
    result.details["trajectory_keys"] = sorted(traj.keys()) if isinstance(traj, dict) else []
    result.details["contract_surfaces"] = list(ADAPTER_CONTRACT_V1.surfaces)
    return result
