"""Metrics: FAR/FRR, abstention, missingness, stratified by cohort/access."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CohortMetrics:
    cohort: str
    n: int = 0
    tp: int = 0
    tn: int = 0
    fp: int = 0  # FAR numerator: accept ∧ invalid
    fn: int = 0  # FRR numerator: reject ∧ valid
    abstentions: int = 0
    missing: int = 0
    failed: int = 0

    @property
    def far(self) -> float | None:
        """False accept rate among labeled invalid non-abstentions: FP / (FP + TN)."""
        denom = self.fp + self.tn
        return (self.fp / denom) if denom else None

    @property
    def frr(self) -> float | None:
        """False reject rate among labeled valid non-abstentions: FN / (FN + TP)."""
        denom = self.fn + self.tp
        return (self.fn / denom) if denom else None

    @property
    def abstention_rate(self) -> float | None:
        decided = self.n - self.missing - self.failed
        return (self.abstentions / decided) if decided else None

    @property
    def missingness(self) -> float | None:
        return (self.missing / self.n) if self.n else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "cohort": self.cohort,
            "n": self.n,
            "tp": self.tp,
            "tn": self.tn,
            "fp": self.fp,
            "fn": self.fn,
            "far": self.far,
            "frr": self.frr,
            "abstentions": self.abstentions,
            "abstention_rate": self.abstention_rate,
            "missing": self.missing,
            "missingness": self.missingness,
            "failed": self.failed,
        }


@dataclass
class MetricsReport:
    access_model: str
    cohorts: dict[str, CohortMetrics] = field(default_factory=dict)
    overall: CohortMetrics = field(default_factory=lambda: CohortMetrics(cohort="overall"))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1",
            "access_model": self.access_model,
            "overall": self.overall.as_dict(),
            "cohorts": {k: v.as_dict() for k, v in sorted(self.cohorts.items())},
        }


def _update(
    cm: CohortMetrics,
    *,
    accepted: bool | None,
    valid: bool | None,
    abstain: bool = False,
    failed: bool = False,
) -> None:
    """Update confusion counts with explicit missing vs abstention semantics.

    - ``failed``: execution error — counted in n/failed, not in FAR/FRR denoms
    - ``valid is None``: missing ground truth — not in FAR/FRR denoms
    - ``abstain`` or ``accepted is None`` (with known valid): abstention
    - else: TP/TN/FP/FN under standard verifier x GT contingency
    """
    cm.n += 1
    if failed:
        cm.failed += 1
        return
    if valid is None:
        cm.missing += 1
        return
    if abstain or accepted is None:
        cm.abstentions += 1
        return
    if accepted and valid:
        cm.tp += 1
    elif (not accepted) and (not valid):
        cm.tn += 1
    elif accepted and (not valid):
        cm.fp += 1
    else:
        cm.fn += 1


class AccessModelPoolError(ValueError):
    """Raised when results mix access models without explicit stratification."""


def compute_metrics(
    results: list[dict[str, Any]],
    *,
    access_model: str = "black-box",
) -> MetricsReport:
    """Compute FAR/FRR stratified by cohort; never pool across access models."""
    return compute_metrics_iter(results, access_model=access_model)


def compute_metrics_iter(
    results: Any,
    *,
    access_model: str = "black-box",
) -> MetricsReport:
    """Streaming FAR/FRR; refuses silent pooling across access-model classes."""
    report = MetricsReport(access_model=access_model)
    for row in results:
        row_access = row.get("access_model")
        if row_access is not None and str(row_access) != access_model:
            raise AccessModelPoolError(
                f"refusing to pool metrics across access models: "
                f"report={access_model!r} row={row_access!r} unit={row.get('unit_id')}"
            )
        cohort = str(row.get("cohort") or "unknown")
        failed = bool(row.get("error")) or row.get("status") == "failed"
        accepted = row.get("verifier_accepted")
        if accepted is None and "decision" in row and not failed:
            decision = row["decision"]
            if decision == "abstain":
                accepted = None
            elif isinstance(decision, bool):
                accepted = decision
        valid = row.get("gt_valid")
        if valid is None and "label" in row and isinstance(row["label"], dict):
            valid = row["label"].get("valid")
        abstain = bool(row.get("abstain")) or (
            isinstance(row.get("decision"), str) and row.get("decision") == "abstain"
        )
        if cohort not in report.cohorts:
            report.cohorts[cohort] = CohortMetrics(cohort=cohort)
        accepted_n = (
            accepted if isinstance(accepted, bool) or accepted is None else bool(accepted)
        )
        valid_n = valid if isinstance(valid, bool) or valid is None else bool(valid)
        _update(
            report.cohorts[cohort],
            accepted=accepted_n,
            valid=valid_n,
            abstain=abstain,
            failed=failed,
        )
        _update(
            report.overall,
            accepted=accepted_n,
            valid=valid_n,
            abstain=abstain,
            failed=failed,
        )
    return report
