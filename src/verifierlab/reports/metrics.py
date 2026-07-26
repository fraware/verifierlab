"""Metrics: FAR/FRR, abstention, missingness, stratified by cohort/access."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from verifierlab.api.decision import DecisionKind, kind_to_accepted, parse_decision_token


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
    pool_overall: bool = False

    def as_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "schema_version": "1",
            "access_model": self.access_model,
            "pool_overall": self.pool_overall,
            "cohorts": {k: v.as_dict() for k, v in sorted(self.cohorts.items())},
        }
        if self.pool_overall:
            body["overall"] = self.overall.as_dict()
        else:
            body["overall"] = None
        return body


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


class MetricsIngestError(ValueError):
    """Raised when accepted/valid labels are not bool or a recognized decision enum."""


def _normalize_label_bool(value: Any, *, field: str) -> bool | None:
    """Fail-closed bool/enum ingestion — never ``bool(\"false\")`` / ``bool(\"reject\")``."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, DecisionKind):
        return kind_to_accepted(value)
    if isinstance(value, str):
        kind = parse_decision_token(value)
        if kind is None:
            raise MetricsIngestError(
                f"invalid {field} value {value!r}: expected bool or decision enum, "
                "refusing truthiness coercion"
            )
        return kind_to_accepted(kind)
    raise MetricsIngestError(
        f"invalid {field} type {type(value).__name__}: expected bool or decision enum, "
        "refusing truthiness coercion"
    )


def compute_metrics(
    results: list[dict[str, Any]],
    *,
    access_model: str = "black-box",
    pool_overall: bool = False,
) -> MetricsReport:
    """Compute FAR/FRR stratified by cohort; never pool across access models.

    Overall cohort pooling is **disabled by default** (VAL-C14). Pass
    ``pool_overall=True`` only when an explicit analysis requests it.
    """
    return compute_metrics_iter(results, access_model=access_model, pool_overall=pool_overall)


def compute_metrics_iter(
    results: Any,
    *,
    access_model: str = "black-box",
    pool_overall: bool = False,
) -> MetricsReport:
    """Streaming FAR/FRR; refuses silent pooling across access-model classes."""
    report = MetricsReport(access_model=access_model, pool_overall=pool_overall)
    for row in results:
        row_access = row.get("access_model")
        if row_access is not None and str(row_access) != access_model:
            raise AccessModelPoolError(
                f"refusing to pool metrics across access models: "
                f"report={access_model!r} row={row_access!r} unit={row.get('unit_id')}"
            )
        cohort = str(row.get("cohort") or "unknown")
        failed = bool(row.get("error")) or row.get("status") == "failed"
        accepted_raw = row.get("verifier_accepted")
        if accepted_raw is None and "decision" in row and not failed:
            accepted_raw = row["decision"]
        valid_raw = row.get("gt_valid")
        if valid_raw is None and "label" in row and isinstance(row["label"], dict):
            valid_raw = row["label"].get("valid")
        abstain = bool(row.get("abstain")) or (
            isinstance(row.get("decision"), str) and row.get("decision") == "abstain"
        )
        if not failed:
            accepted_n = _normalize_label_bool(accepted_raw, field="verifier_accepted")
            valid_n = _normalize_label_bool(valid_raw, field="gt_valid")
        else:
            accepted_n = None
            valid_n = None
        if cohort not in report.cohorts:
            report.cohorts[cohort] = CohortMetrics(cohort=cohort)
        _update(
            report.cohorts[cohort],
            accepted=accepted_n,
            valid=valid_n,
            abstain=abstain,
            failed=failed,
        )
        if pool_overall:
            _update(
                report.overall,
                accepted=accepted_n,
                valid=valid_n,
                abstain=abstain,
                failed=failed,
            )
    if not pool_overall:
        # Leave overall empty (n=0) so callers do not silently use pooled rates.
        report.overall = CohortMetrics(cohort="overall")
    return report
