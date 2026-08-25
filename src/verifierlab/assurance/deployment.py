"""Prospective deployment calibration capability (WP-15).

Registers predictions before outcomes, anchors chronology via an append-only
hash-chain store (self-authored timestamps alone are insufficient), and builds
calibration reports. Synthetic fixtures must set
``synthetic_non_deployment_evidence=True`` and cannot promote
``deployment_calibrated``.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from verifierlab.artifacts.canonical import digest_of

GENESIS_PREV = "0" * 64

OutcomeKind = Literal["binary", "continuous", "time_to_event", "categorical"]
CalibrationMetric = Literal["brier", "log_loss", "reliability", "ece", "custom"]


class ChronologyStoreEvent(BaseModel):
    """One append-only chronology event (hash-chained)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    event_id: str = Field(min_length=1)
    event_kind: str = Field(min_length=1)
    payload_digest: str = Field(min_length=64, max_length=64)
    prev_event_digest: str = Field(min_length=64, max_length=64)
    recorded_at: float
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class AppendOnlyChronologyStore:
    """Externally auditable chronology via hash-chained events on disk.

    A lone ``registered_at`` float on a prediction is never sufficient to claim
    prospective registration; callers must append through this store.
    """

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._index = self.root / "chain.jsonl"
        self._tip = self.root / "tip.json"

    def tip_digest(self) -> str:
        if not self._tip.is_file():
            return GENESIS_PREV
        data = json.loads(self._tip.read_text(encoding="utf-8"))
        return str(data.get("tip_digest") or GENESIS_PREV)

    def append(
        self,
        *,
        event_kind: str,
        payload: dict[str, Any],
        event_id: str | None = None,
        recorded_at: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ChronologyStoreEvent:
        payload_digest = digest_of(payload)
        prev = self.tip_digest()
        ts = float(time.time() if recorded_at is None else recorded_at)
        eid = event_id or f"{event_kind}-{payload_digest[:16]}"
        event = ChronologyStoreEvent(
            event_id=eid,
            event_kind=event_kind,
            payload_digest=payload_digest,
            prev_event_digest=prev,
            recorded_at=ts,
            metadata=dict(metadata or {}),
        )
        line = json.dumps(
            {**event.model_dump(mode="json"), "content_digest": event.digest},
            sort_keys=True,
        )
        with self._index.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        self._tip.write_text(
            json.dumps(
                {"tip_digest": event.digest, "event_id": eid, "event_kind": event_kind},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        # Persist payload beside the chain for reconstruction.
        (self.root / "payloads").mkdir(parents=True, exist_ok=True)
        (self.root / "payloads" / f"{eid}.json").write_text(
            json.dumps({**payload, "content_digest": payload_digest}, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        return event

    def events(self) -> list[ChronologyStoreEvent]:
        if not self._index.is_file():
            return []
        out: list[ChronologyStoreEvent] = []
        prev = GENESIS_PREV
        for line in self._index.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            body = json.loads(line)
            event = ChronologyStoreEvent.model_validate(
                {k: v for k, v in body.items() if k != "content_digest"}
            )
            if event.prev_event_digest != prev:
                raise ValueError("chronology hash-chain broken (tamper or reorder)")
            if body.get("content_digest") != event.digest:
                raise ValueError("chronology event digest mismatch (tamper)")
            out.append(event)
            prev = event.digest
        return out

    def first_event_of_kind(self, kind: str) -> ChronologyStoreEvent | None:
        for event in self.events():
            if event.event_kind == kind:
                return event
        return None

    def verify_prediction_before_outcome(
        self,
        *,
        prediction_event_id: str,
        outcome_event_id: str,
    ) -> None:
        """Fail closed if outcome appears at or before prediction in the chain."""
        order = {e.event_id: i for i, e in enumerate(self.events())}
        if prediction_event_id not in order:
            raise ValueError("prediction event missing from chronology store")
        if outcome_event_id not in order:
            raise ValueError("outcome event missing from chronology store")
        if order[outcome_event_id] <= order[prediction_event_id]:
            raise ValueError(
                "retrospective registration rejected: outcome chronology precedes "
                "or equals prediction (self-authored timestamp alone is insufficient)"
            )


class DeploymentPredictionRegistration(BaseModel):
    """Prospective prediction registered before outcome access."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    prediction_id: str = Field(min_length=1)
    study_id: str = Field(min_length=1)
    environment_assurance_digest: str = Field(min_length=64, max_length=64)
    verifier_assurance_digest: str = Field(min_length=64, max_length=64)
    agent_configuration_digest: str = Field(min_length=64, max_length=64)
    applicability_regime: str = Field(min_length=1)
    outcome_definition: str = Field(min_length=1)
    outcome_window: str = Field(min_length=1)
    predicted_probability: float | None = Field(default=None, ge=0.0, le=1.0)
    predicted_distribution: dict[str, float] | None = None
    risk_score: float | None = None
    prediction_method: str = Field(min_length=1)
    prediction_method_version: str = Field(min_length=1)
    assumptions: tuple[str, ...] = Field(min_length=1)
    chronology_event_digest: str = Field(min_length=64, max_length=64)
    registered_at: float
    synthetic_non_deployment_evidence: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _prediction_present(self) -> DeploymentPredictionRegistration:
        if (
            self.predicted_probability is None
            and self.predicted_distribution is None
            and self.risk_score is None
        ):
            raise ValueError("prediction requires probability, distribution, or risk_score")
        if any(not a.strip() for a in self.assumptions):
            raise ValueError("assumptions must be non-empty")
        return self

    @property
    def digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class DeploymentOutcomeRecord(BaseModel):
    """Observed deployment outcome; must not mutate the prior prediction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    outcome_id: str = Field(min_length=1)
    prediction_id: str = Field(min_length=1)
    study_id: str = Field(min_length=1)
    outcome_value: Any
    outcome_kind: OutcomeKind = "binary"
    observation_window: str = Field(min_length=1)
    provenance_digest: str = Field(min_length=64, max_length=64)
    missing_or_censored: bool = False
    censoring_reason: str | None = None
    source_identity: str | None = None
    chronology_event_digest: str = Field(min_length=64, max_length=64)
    observed_at: float
    synthetic_non_deployment_evidence: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _censor_rule(self) -> DeploymentOutcomeRecord:
        if self.missing_or_censored and not self.censoring_reason:
            raise ValueError("censored outcomes require censoring_reason")
        return self

    @property
    def digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class DeploymentCalibrationPlan(BaseModel):
    """Preregistered calibration analysis plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    plan_id: str = Field(min_length=1)
    study_id: str = Field(min_length=1)
    primary_metrics: tuple[CalibrationMetric, ...] = Field(min_length=1)
    grouping_keys: tuple[str, ...] = ()
    outcome_kind: OutcomeKind = "binary"
    allow_discrimination: bool = False
    registered_before_outcomes: bool = True
    synthetic_non_deployment_evidence: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class DeploymentCalibrationReport(BaseModel):
    """Links predictions to later outcomes with honest claim boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    report_id: str = Field(min_length=1)
    study_id: str = Field(min_length=1)
    plan_digest: str = Field(min_length=64, max_length=64)
    prediction_digests: tuple[str, ...] = ()
    outcome_digests: tuple[str, ...] = ()
    chronology_tip_digest: str = Field(min_length=64, max_length=64)
    n_predictions: int = Field(ge=0)
    n_outcomes: int = Field(ge=0)
    n_matched: int = Field(ge=0)
    n_censored: int = Field(ge=0)
    metrics: dict[str, Any] = Field(default_factory=dict)
    applicability_strata: dict[str, Any] = Field(default_factory=dict)
    supports_deployment_calibrated_claim: bool = False
    synthetic_non_deployment_evidence: bool = False
    blockers: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def register_prediction(
    deployment_root: Path | str,
    *,
    prediction: dict[str, Any],
    chronology: AppendOnlyChronologyStore | None = None,
) -> DeploymentPredictionRegistration:
    """Register a prospective prediction and append a chronology event."""
    root = Path(deployment_root)
    root.mkdir(parents=True, exist_ok=True)
    store = chronology or AppendOnlyChronologyStore(root / "chronology")
    # Refuse if outcomes already present for this prediction_id.
    pred_id = str(prediction.get("prediction_id") or "")
    if not pred_id:
        raise ValueError("prediction_id required")
    outcomes_dir = root / "outcomes"
    if outcomes_dir.is_dir():
        for path in outcomes_dir.glob("*.json"):
            body = json.loads(path.read_text(encoding="utf-8"))
            if body.get("prediction_id") == pred_id:
                raise ValueError(
                    "retrospective registration rejected: outcome already exists "
                    "for this prediction_id"
                )

    payload = dict(prediction)
    payload.setdefault("registered_at", time.time())
    event = store.append(
        event_kind="deployment_prediction",
        payload=payload,
        event_id=f"pred-{pred_id}",
        recorded_at=float(payload["registered_at"]),
    )
    rec = DeploymentPredictionRegistration.model_validate(
        {**payload, "chronology_event_digest": event.digest}
    )
    out = root / "predictions"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{rec.prediction_id}.json").write_text(
        json.dumps(
            {**rec.model_dump(mode="json"), "content_digest": rec.digest}, indent=2, sort_keys=True
        )
        + "\n",
        encoding="utf-8",
    )
    # Research registration tip for EvidenceResolver.
    regs = root / "registrations"
    regs.mkdir(parents=True, exist_ok=True)
    tip = {
        "registration_kind": "deployment_prediction",
        "prediction_id": rec.prediction_id,
        "content_digest": rec.digest,
        "chronology_event_digest": event.digest,
        "synthetic_non_deployment_evidence": rec.synthetic_non_deployment_evidence,
        "before_outcomes": True,
    }
    (regs / f"deployment_prediction-{rec.prediction_id}.json").write_text(
        json.dumps(tip, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return rec


def ingest_outcome(
    deployment_root: Path | str,
    *,
    outcome: dict[str, Any],
    chronology: AppendOnlyChronologyStore | None = None,
) -> DeploymentOutcomeRecord:
    """Ingest an outcome after verifying chronology against the prediction."""
    root = Path(deployment_root)
    store = chronology or AppendOnlyChronologyStore(root / "chronology")
    pred_id = str(outcome.get("prediction_id") or "")
    pred_path = root / "predictions" / f"{pred_id}.json"
    if not pred_path.is_file():
        raise ValueError(f"prediction {pred_id!r} not registered")
    pred_body = json.loads(pred_path.read_text(encoding="utf-8"))
    pred_event_id = f"pred-{pred_id}"
    if store.first_event_of_kind("deployment_prediction") is None:
        raise ValueError("prediction chronology event missing (self-authored ts insufficient)")

    payload = dict(outcome)
    payload.setdefault("observed_at", time.time())
    # Inherit synthetic flag from prediction if not set.
    if "synthetic_non_deployment_evidence" not in payload:
        payload["synthetic_non_deployment_evidence"] = bool(
            pred_body.get("synthetic_non_deployment_evidence")
        )
    event = store.append(
        event_kind="deployment_outcome",
        payload=payload,
        event_id=f"out-{payload.get('outcome_id')}",
        recorded_at=float(payload["observed_at"]),
    )
    store.verify_prediction_before_outcome(
        prediction_event_id=pred_event_id,
        outcome_event_id=event.event_id,
    )
    # Also reject if wall-clock observed_at precedes prediction registered_at
    # (ambiguous chronology).
    if float(payload["observed_at"]) < float(pred_body.get("registered_at") or 0.0):
        raise ValueError("outcome timestamp earlier than prediction registration (fail closed)")

    rec = DeploymentOutcomeRecord.model_validate(
        {**payload, "chronology_event_digest": event.digest}
    )
    out = root / "outcomes"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{rec.outcome_id}.json").write_text(
        json.dumps(
            {**rec.model_dump(mode="json"), "content_digest": rec.digest}, indent=2, sort_keys=True
        )
        + "\n",
        encoding="utf-8",
    )
    return rec


def _brier(pairs: list[tuple[float, float]]) -> float | None:
    if not pairs:
        return None
    return sum((p - y) ** 2 for p, y in pairs) / len(pairs)


def build_calibration_report(
    deployment_root: Path | str,
    *,
    plan: DeploymentCalibrationPlan | dict[str, Any],
    report_id: str | None = None,
) -> DeploymentCalibrationReport:
    """Build a calibration report; synthetic/retrospective cannot claim calibrated."""
    root = Path(deployment_root)
    plan_obj = (
        plan
        if isinstance(plan, DeploymentCalibrationPlan)
        else DeploymentCalibrationPlan.model_validate(plan)
    )
    store = AppendOnlyChronologyStore(root / "chronology")
    tip = store.tip_digest()

    predictions: list[DeploymentPredictionRegistration] = []
    pred_dir = root / "predictions"
    if pred_dir.is_dir():
        for path in sorted(pred_dir.glob("*.json")):
            body = json.loads(path.read_text(encoding="utf-8"))
            predictions.append(
                DeploymentPredictionRegistration.model_validate(
                    {k: v for k, v in body.items() if k != "content_digest"}
                )
            )

    outcomes: list[DeploymentOutcomeRecord] = []
    out_dir = root / "outcomes"
    if out_dir.is_dir():
        for path in sorted(out_dir.glob("*.json")):
            body = json.loads(path.read_text(encoding="utf-8"))
            outcomes.append(
                DeploymentOutcomeRecord.model_validate(
                    {k: v for k, v in body.items() if k != "content_digest"}
                )
            )

    by_pred = {o.prediction_id: o for o in outcomes}
    matched: list[tuple[DeploymentPredictionRegistration, DeploymentOutcomeRecord]] = []
    censored = 0
    for pred in predictions:
        outcome = by_pred.get(pred.prediction_id)
        if outcome is None:
            continue
        # Chronology check per pair.
        try:
            store.verify_prediction_before_outcome(
                prediction_event_id=f"pred-{pred.prediction_id}",
                outcome_event_id=f"out-{outcome.outcome_id}",
            )
        except ValueError:
            continue
        if outcome.missing_or_censored:
            censored += 1
            continue
        matched.append((pred, outcome))

    blockers: list[str] = []
    synthetic = (
        bool(plan_obj.synthetic_non_deployment_evidence)
        or any(p.synthetic_non_deployment_evidence for p in predictions)
        or any(o.synthetic_non_deployment_evidence for o in outcomes)
    )
    if synthetic:
        blockers.append("synthetic_non_deployment_evidence")
    if not predictions:
        blockers.append("no_predictions_registered")
    if not matched:
        blockers.append("no_matched_prospective_outcomes")
    if tip == GENESIS_PREV:
        blockers.append("chronology_store_empty")

    metrics: dict[str, Any] = {}
    if plan_obj.outcome_kind == "binary" and "brier" in plan_obj.primary_metrics:
        pairs: list[tuple[float, float]] = []
        for pred, outcome in matched:
            if pred.predicted_probability is None:
                continue
            y = float(outcome.outcome_value)
            pairs.append((float(pred.predicted_probability), y))
        metrics["brier"] = _brier(pairs)
        metrics["n_scored"] = len(pairs)

    strata: dict[str, Any] = {}
    for key in plan_obj.grouping_keys:
        buckets: dict[str, int] = {}
        for pred, _outcome in matched:
            val = str((pred.metadata or {}).get(key) or pred.applicability_regime)
            buckets[val] = buckets.get(val, 0) + 1
        strata[key] = buckets

    supports = not blockers and not synthetic and len(matched) > 0
    rid = report_id or f"calib-{plan_obj.plan_id}"
    report = DeploymentCalibrationReport(
        report_id=rid,
        study_id=plan_obj.study_id,
        plan_digest=plan_obj.digest,
        prediction_digests=tuple(p.digest for p in predictions),
        outcome_digests=tuple(o.digest for o in outcomes),
        chronology_tip_digest=tip,
        n_predictions=len(predictions),
        n_outcomes=len(outcomes),
        n_matched=len(matched),
        n_censored=censored,
        metrics=metrics,
        applicability_strata=strata,
        supports_deployment_calibrated_claim=supports,
        synthetic_non_deployment_evidence=synthetic,
        blockers=tuple(blockers),
        metadata={"plan_id": plan_obj.plan_id},
    )
    (root / "calibration_report.json").write_text(
        json.dumps(
            {**report.model_dump(mode="json"), "content_digest": report.digest},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "calibration_plan.json").write_text(
        json.dumps(
            {**plan_obj.model_dump(mode="json"), "content_digest": plan_obj.digest},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    # Applicability declaration for EvidenceResolver deployment facts.
    (root / "applicability.json").write_text(
        json.dumps(
            {
                "study_id": plan_obj.study_id,
                "regimes": sorted({p.applicability_regime for p in predictions}),
                "content_digest": digest_of({"study_id": plan_obj.study_id, "n": len(predictions)}),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    # Aggregate outcomes file for legacy resolver path.
    (root / "outcomes.json").write_text(
        json.dumps(
            {
                "outcomes": [o.model_dump(mode="json") for o in outcomes],
                "n": len(outcomes),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return report


__all__ = [
    "GENESIS_PREV",
    "AppendOnlyChronologyStore",
    "CalibrationMetric",
    "ChronologyStoreEvent",
    "DeploymentCalibrationPlan",
    "DeploymentCalibrationReport",
    "DeploymentOutcomeRecord",
    "DeploymentPredictionRegistration",
    "OutcomeKind",
    "build_calibration_report",
    "ingest_outcome",
    "register_prediction",
]
