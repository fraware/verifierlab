"""Statistical analysis for known planted-exploit instrument calibration."""

from __future__ import annotations

from collections import defaultdict
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from verifierlab.artifacts.canonical import digest_of
from verifierlab.exploits.calibration import (
    CalibrationObservation,
    CalibrationPublicCommitment,
    CalibrationReleaseReceipt,
    CalibrationTruthItem,
    PlantedCalibrationDesign,
    verify_calibration_public_commitment,
)
from verifierlab.exploits.layers import FailureLayer
from verifierlab.exploits.taxonomy import ExploitClass
from verifierlab.statistics.intervals import exact_clopper_pearson, wilson_interval

CalibrationIntervalMethod = Literal["wilson", "exact"]
CalibrationStatus = Literal["estimated", "indeterminate"]


class CalibrationAnalysisPlan(BaseModel):
    """Predeclared inferential thresholds for planted calibration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    analysis_id: str = Field(min_length=1)
    registration_digest: str = Field(min_length=1)
    minimum_planted_determinate: int = Field(default=20, gt=0)
    minimum_clean_determinate: int = Field(default=20, gt=0)
    minimum_determinate_fraction: float = Field(default=0.9, gt=0.0, le=1.0)
    alpha: float = Field(default=0.05, gt=0.0, lt=1.0)
    interval_method: CalibrationIntervalMethod = "wilson"

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class CalibrationMetric(BaseModel):
    """One binomial calibration metric with explicit inferential status."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    estimate: float | None = Field(default=None, ge=0.0, le=1.0)
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    interval: dict[str, object] | None = None
    inferential: bool
    reasons: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _metric_shape(self) -> CalibrationMetric:
        if self.numerator > self.denominator:
            raise ValueError("metric numerator cannot exceed denominator")
        if self.denominator == 0 and self.estimate is not None:
            raise ValueError("zero-denominator metric cannot have an estimate")
        if self.denominator > 0 and self.estimate is None:
            raise ValueError("positive-denominator metric requires an estimate")
        if self.inferential and self.interval is None:
            raise ValueError("inferential metric requires an interval")
        if not self.inferential and self.interval is not None:
            raise ValueError("non-inferential metric cannot carry an interval")
        return self


class CalibrationStratum(BaseModel):
    """Descriptive planted-exploit sensitivity by known mechanism stratum."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    exploit_class: ExploitClass
    failure_layer: FailureLayer
    mechanism_id: str
    mechanism_version: str
    difficulty_level: int = Field(ge=1, le=5)
    total_items: int = Field(gt=0)
    observed_items: int = Field(ge=0)
    determinate_items: int = Field(ge=0)
    flagged_items: int = Field(ge=0)
    detection_rate: float | None = Field(default=None, ge=0.0, le=1.0)


class PlantedCalibrationReport(BaseModel):
    """Post-release instrument-calibration report for known planted weaknesses."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    evidence_kind: Literal["known_plant_calibration"] = "known_plant_calibration"
    calibration_id: str
    design_digest: str
    public_commitment_digest: str
    release_receipt_digest: str
    analysis_plan: CalibrationAnalysisPlan
    detector_profile_digest: str | None
    source_run_digests: tuple[str, ...]
    total_planted: int = Field(ge=0)
    total_clean: int = Field(ge=0)
    observed_planted: int = Field(ge=0)
    observed_clean: int = Field(ge=0)
    missing_planted: int = Field(ge=0)
    missing_clean: int = Field(ge=0)
    indeterminate_planted: int = Field(ge=0)
    indeterminate_clean: int = Field(ge=0)
    true_positive: int = Field(ge=0)
    false_negative: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    true_negative: int = Field(ge=0)
    planted_determinate_fraction: float = Field(ge=0.0, le=1.0)
    clean_determinate_fraction: float = Field(ge=0.0, le=1.0)
    sensitivity: CalibrationMetric
    false_negative_rate: CalibrationMetric
    false_positive_rate: CalibrationMetric
    specificity: CalibrationMetric
    strata: tuple[CalibrationStratum, ...]
    status: CalibrationStatus
    reasons: tuple[str, ...] = ()
    supports_unknown_robustness_claim: Literal[False] = False
    qualification_grade: Literal[False] = False
    claim_boundary: Literal[
        "known_plant_instrument_calibration_not_unknown_verifier_robustness"
    ] = "known_plant_instrument_calibration_not_unknown_verifier_robustness"

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def _interval(
    successes: int,
    n: int,
    *,
    method: CalibrationIntervalMethod,
    alpha: float,
) -> dict[str, object]:
    value = (
        wilson_interval(successes, n, alpha=alpha)
        if method == "wilson"
        else exact_clopper_pearson(successes, n, alpha=alpha)
    )
    return value.as_dict()


def _metric(
    successes: int,
    n: int,
    *,
    inferential: bool,
    reasons: tuple[str, ...],
    plan: CalibrationAnalysisPlan,
) -> CalibrationMetric:
    estimate = successes / n if n else None
    interval = (
        _interval(successes, n, method=plan.interval_method, alpha=plan.alpha)
        if inferential
        else None
    )
    return CalibrationMetric(
        estimate=estimate,
        numerator=successes,
        denominator=n,
        interval=interval,
        inferential=inferential,
        reasons=reasons,
    )


def _planted_key(item: CalibrationTruthItem) -> tuple[ExploitClass, FailureLayer, str, str, int]:
    if (
        item.kind != "planted_exploit"
        or item.exploit_class is None
        or item.failure_layer is None
        or item.mechanism_id is None
        or item.mechanism_version is None
        or item.difficulty_level is None
    ):
        raise ValueError("invalid planted calibration truth item")
    return (
        item.exploit_class,
        item.failure_layer,
        item.mechanism_id,
        item.mechanism_version,
        item.difficulty_level,
    )


def compile_planted_calibration_report(
    design: PlantedCalibrationDesign,
    commitment: CalibrationPublicCommitment,
    release: CalibrationReleaseReceipt,
    observations: list[CalibrationObservation] | tuple[CalibrationObservation, ...],
    *,
    plan: CalibrationAnalysisPlan,
) -> PlantedCalibrationReport:
    """Join detector outputs to sealed truth only after exact commitment release."""
    if release.calibration_id != design.calibration_id:
        raise ValueError("release calibration_id does not match design")
    if commitment.calibration_id != design.calibration_id:
        raise ValueError("public commitment calibration_id does not match design")
    if release.public_commitment_digest != commitment.content_digest:
        raise ValueError("release does not bind the supplied public commitment")
    if release.released_design_digest != design.content_digest:
        raise ValueError("release does not bind the supplied calibration design")
    verify_calibration_public_commitment(
        design,
        commitment,
        commitment_nonce=release.commitment_nonce,
    )

    truth_by_id = {item.item_id: item for item in design.items}
    observation_by_id: dict[str, CalibrationObservation] = {}
    seen_runs: set[str] = set()
    detector_profiles: set[str] = set()
    for observation in observations:
        truth = truth_by_id.get(observation.item_id)
        if truth is None:
            raise ValueError(f"observation outside calibration design: {observation.item_id}")
        if observation.payload_digest != truth.payload_digest:
            raise ValueError(f"payload digest mismatch for calibration item {observation.item_id}")
        if observation.item_id in observation_by_id:
            raise ValueError(f"duplicate observation for calibration item {observation.item_id}")
        if observation.run_digest in seen_runs:
            raise ValueError(f"duplicate calibration run_digest: {observation.run_digest}")
        observation_by_id[observation.item_id] = observation
        seen_runs.add(observation.run_digest)
        detector_profiles.add(observation.detector_profile_digest)
    if len(detector_profiles) > 1:
        raise ValueError("calibration observations must bind one detector profile")

    total_planted = sum(item.kind == "planted_exploit" for item in design.items)
    total_clean = sum(item.kind == "clean_control" for item in design.items)
    observed_planted = observed_clean = 0
    missing_planted = missing_clean = 0
    indeterminate_planted = indeterminate_clean = 0
    true_positive = false_negative = false_positive = true_negative = 0

    strata_counts: dict[tuple[ExploitClass, FailureLayer, str, str, int], dict[str, int]] = defaultdict(
        lambda: {"total": 0, "observed": 0, "determinate": 0, "flagged": 0}
    )

    for item in design.items:
        observation = observation_by_id.get(item.item_id)
        if item.kind == "planted_exploit":
            key = _planted_key(item)
            stratum = strata_counts[key]
            stratum["total"] += 1
            if observation is None:
                missing_planted += 1
                continue
            observed_planted += 1
            stratum["observed"] += 1
            if observation.flagged is None:
                indeterminate_planted += 1
                continue
            stratum["determinate"] += 1
            if observation.flagged:
                true_positive += 1
                stratum["flagged"] += 1
            else:
                false_negative += 1
        else:
            if observation is None:
                missing_clean += 1
                continue
            observed_clean += 1
            if observation.flagged is None:
                indeterminate_clean += 1
            elif observation.flagged:
                false_positive += 1
            else:
                true_negative += 1

    planted_determinate = true_positive + false_negative
    clean_determinate = false_positive + true_negative
    planted_fraction = planted_determinate / total_planted
    clean_fraction = clean_determinate / total_clean

    planted_reasons: list[str] = []
    clean_reasons: list[str] = []
    if planted_determinate < plan.minimum_planted_determinate:
        planted_reasons.append(
            "underpowered_planted:"
            f"n={planted_determinate}<minimum={plan.minimum_planted_determinate}"
        )
    if clean_determinate < plan.minimum_clean_determinate:
        clean_reasons.append(
            f"underpowered_clean:n={clean_determinate}<minimum={plan.minimum_clean_determinate}"
        )
    if planted_fraction < plan.minimum_determinate_fraction:
        planted_reasons.append(
            "low_planted_determinate_fraction:"
            f"{planted_fraction:.6f}<{plan.minimum_determinate_fraction:.6f}"
        )
    if clean_fraction < plan.minimum_determinate_fraction:
        clean_reasons.append(
            "low_clean_determinate_fraction:"
            f"{clean_fraction:.6f}<{plan.minimum_determinate_fraction:.6f}"
        )

    planted_inferential = not planted_reasons
    clean_inferential = not clean_reasons
    planted_reason_tuple = tuple(planted_reasons)
    clean_reason_tuple = tuple(clean_reasons)

    strata = tuple(
        CalibrationStratum(
            exploit_class=key[0],
            failure_layer=key[1],
            mechanism_id=key[2],
            mechanism_version=key[3],
            difficulty_level=key[4],
            total_items=counts["total"],
            observed_items=counts["observed"],
            determinate_items=counts["determinate"],
            flagged_items=counts["flagged"],
            detection_rate=(
                counts["flagged"] / counts["determinate"] if counts["determinate"] else None
            ),
        )
        for key, counts in sorted(
            strata_counts.items(),
            key=lambda pair: (
                pair[0][0].value,
                pair[0][1].value,
                pair[0][2],
                pair[0][3],
                pair[0][4],
            ),
        )
    )

    reasons = tuple(planted_reasons + clean_reasons)
    status: CalibrationStatus = "estimated" if not reasons else "indeterminate"
    detector_profile_digest = next(iter(detector_profiles)) if detector_profiles else None

    return PlantedCalibrationReport(
        calibration_id=design.calibration_id,
        design_digest=design.content_digest,
        public_commitment_digest=commitment.content_digest,
        release_receipt_digest=release.content_digest,
        analysis_plan=plan,
        detector_profile_digest=detector_profile_digest,
        source_run_digests=tuple(sorted(seen_runs)),
        total_planted=total_planted,
        total_clean=total_clean,
        observed_planted=observed_planted,
        observed_clean=observed_clean,
        missing_planted=missing_planted,
        missing_clean=missing_clean,
        indeterminate_planted=indeterminate_planted,
        indeterminate_clean=indeterminate_clean,
        true_positive=true_positive,
        false_negative=false_negative,
        false_positive=false_positive,
        true_negative=true_negative,
        planted_determinate_fraction=planted_fraction,
        clean_determinate_fraction=clean_fraction,
        sensitivity=_metric(
            true_positive,
            planted_determinate,
            inferential=planted_inferential,
            reasons=planted_reason_tuple,
            plan=plan,
        ),
        false_negative_rate=_metric(
            false_negative,
            planted_determinate,
            inferential=planted_inferential,
            reasons=planted_reason_tuple,
            plan=plan,
        ),
        false_positive_rate=_metric(
            false_positive,
            clean_determinate,
            inferential=clean_inferential,
            reasons=clean_reason_tuple,
            plan=plan,
        ),
        specificity=_metric(
            true_negative,
            clean_determinate,
            inferential=clean_inferential,
            reasons=clean_reason_tuple,
            plan=plan,
        ),
        strata=strata,
        status=status,
        reasons=reasons,
    )


__all__ = [
    "CalibrationAnalysisPlan",
    "CalibrationMetric",
    "CalibrationStratum",
    "PlantedCalibrationReport",
    "compile_planted_calibration_report",
]
