"""Content-bound estimand declarations for executable statistical plans.

These models bind what will be estimated and how inferential uncertainty may be
reported. They do not by themselves prove that registration occurred before
outcomes were observed; chronology comes from immutable lifecycle evidence.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from verifierlab.artifacts.canonical import digest_of

EstimandMetric = Literal[
    "cohort_far",
    "cohort_frr",
    "far",
    "frr",
    "attack_success",
    "clean_success",
    "optimization_gap",
    "exploit_rate",
    "paired_repair_delta",
    "metamorphic_violation",
    "time_to_exploit",
    "planted_sensitivity",
    "planted_fpr",
    "deployment_outcome",
]
EstimandRole = Literal["primary", "secondary", "descriptive"]
InferenceMode = Literal["interval", "descriptive", "test", "equivalence"]
IntervalMethod = Literal[
    "wilson",
    "exact",
    "bootstrap",
    "cluster_bootstrap",
    "kaplan_meier",
]
InterpretationDirection = Literal[
    "higher_is_worse",
    "lower_is_worse",
    "higher_is_better",
    "lower_is_better",
    "two_sided",
]
SamplingUnit = Literal["task", "environment", "trajectory", "episode"]
MissingnessPolicy = Literal[
    "fail_closed",
    "exclude_unit",
    "timeout_as_failure",
    "timeout_as_censored",
    "infra_as_indeterminate",
]

_RATE_METRICS = frozenset(
    {
        "cohort_far",
        "cohort_frr",
        "far",
        "frr",
        "attack_success",
        "clean_success",
        "exploit_rate",
        "metamorphic_violation",
        "planted_sensitivity",
        "planted_fpr",
        "deployment_outcome",
    }
)
_CONTRAST_METRICS = frozenset({"optimization_gap", "paired_repair_delta"})
_SURVIVAL_METRICS = frozenset({"time_to_exploit"})


class StoppingPlan(BaseModel):
    """Preregistered sequential looks with information fractions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    spending_function: Literal["obrien_fleming", "pocock"] = "obrien_fleming"
    looks: tuple[float, ...] = Field(min_length=1)
    nominal_alpha: float = Field(gt=0.0, lt=1.0, default=0.05)

    @model_validator(mode="after")
    def _looks_valid(self) -> StoppingPlan:
        previous = 0.0
        for look in self.looks:
            if look <= previous or look > 1.0:
                raise ValueError(
                    "stopping looks must be strictly increasing information fractions in (0, 1]"
                )
            previous = look
        if self.looks[-1] != 1.0:
            raise ValueError("final look must be information fraction 1.0")
        return self

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class MultiplicityPlan(BaseModel):
    """Family-wise error-control declaration across preregistered estimands."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    policy: Literal["none", "bonferroni", "holm", "pre_registered_primary"] = "holm"
    family_scope: Literal["primary", "primary_and_secondary", "all_inferential"] = "primary"

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class EstimandSpec(BaseModel):
    """One declared estimand with an executable population and inference contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    estimand_id: str = Field(min_length=1)
    metric: EstimandMetric
    role: EstimandRole = "primary"
    inference: InferenceMode = "interval"
    cohort: str | None = None
    contrast: tuple[str, str] | None = None
    split: str | None = None
    sampling_unit: SamplingUnit = "task"
    pairing_key: str | None = None
    interval_method: IntervalMethod | None = None
    alpha: float | None = Field(default=None, gt=0.0, lt=1.0)
    direction: InterpretationDirection = "two_sided"
    equivalence_margin: float | None = Field(default=None, gt=0.0)
    missingness: MissingnessPolicy = "fail_closed"

    @model_validator(mode="after")
    def _metric_contract(self) -> EstimandSpec:
        if self.sampling_unit == "trajectory" and self.role == "primary":
            raise ValueError(
                "primary estimands cannot use trajectory sampling units "
                "(silent pseudo-replication); use task or environment"
            )

        if self.metric in {"cohort_far", "cohort_frr", "far", "frr"}:
            if self.cohort is None or not self.cohort.strip():
                raise ValueError(f"{self.metric} requires a non-empty cohort")
            if self.contrast is not None:
                raise ValueError(f"{self.metric} does not accept contrast")
        elif self.metric in _CONTRAST_METRICS:
            if self.cohort is not None:
                raise ValueError(f"{self.metric} does not accept cohort")
            if self.contrast is None or len(self.contrast) != 2:
                raise ValueError(f"{self.metric} requires a two-cohort contrast")
            if self.contrast[0] == self.contrast[1]:
                raise ValueError(f"{self.metric} contrast cohorts must differ")
            if any(not value.strip() for value in self.contrast):
                raise ValueError(f"{self.metric} contrast cohorts must be non-empty")
            if self.metric == "paired_repair_delta" and not self.pairing_key:
                raise ValueError("paired_repair_delta requires pairing_key")
        elif self.metric == "exploit_rate":
            if self.cohort is not None or self.contrast is not None:
                raise ValueError("exploit_rate does not accept cohort or contrast")
        elif self.metric in _RATE_METRICS | _SURVIVAL_METRICS:
            if self.contrast is not None:
                raise ValueError(f"{self.metric} does not accept contrast")

        if self.split is not None and not self.split.strip():
            raise ValueError("split must be non-empty when supplied")

        if self.role == "descriptive" and self.inference != "descriptive":
            raise ValueError("descriptive role requires descriptive inference")

        if self.inference == "descriptive":
            if self.interval_method is not None or self.alpha is not None:
                raise ValueError("descriptive estimands cannot declare interval_method or alpha")
            return self

        if self.inference == "equivalence":
            if self.equivalence_margin is None:
                raise ValueError("equivalence inference requires equivalence_margin")
            if self.alpha is None:
                raise ValueError("equivalence inference requires alpha")
            if self.metric not in {"paired_repair_delta", "optimization_gap"}:
                raise ValueError(
                    "equivalence currently supported for paired_repair_delta/optimization_gap"
                )
            return self

        if self.inference in {"interval", "test"}:
            if self.interval_method is None or self.alpha is None:
                raise ValueError("interval/test estimands require interval_method and alpha")
            if self.metric in _CONTRAST_METRICS and self.interval_method not in {
                "bootstrap",
                "cluster_bootstrap",
            }:
                raise ValueError(f"{self.metric} interval inference requires bootstrap")
            if self.metric in _RATE_METRICS and self.interval_method not in {
                "wilson",
                "exact",
                "cluster_bootstrap",
            }:
                raise ValueError(
                    f"{self.metric} rate inference requires wilson, exact, or cluster_bootstrap"
                )
            if self.metric in _SURVIVAL_METRICS and self.interval_method != "kaplan_meier":
                raise ValueError("time_to_exploit interval inference requires kaplan_meier")
        return self


class AnalysisPreregistration(BaseModel):
    """Immutable estimand family bound into a campaign statistical plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    registration_id: str = Field(min_length=1)
    estimands: tuple[EstimandSpec, ...] = Field(min_length=1)
    assumptions: tuple[str, ...] = Field(min_length=1)
    multiplicity: MultiplicityPlan | None = None
    stopping_plan: StoppingPlan | None = None
    default_sampling_unit: SamplingUnit = "task"
    power_plan_digest: str | None = Field(default=None, min_length=64, max_length=64)

    @model_validator(mode="after")
    def _unique_estimands(self) -> AnalysisPreregistration:
        ids = [item.estimand_id for item in self.estimands]
        if len(set(ids)) != len(ids):
            raise ValueError("estimand_id values must be unique")
        if not any(item.role == "primary" for item in self.estimands):
            raise ValueError("preregistration requires at least one primary estimand")
        if any(not assumption.strip() for assumption in self.assumptions):
            raise ValueError("assumptions must be non-empty")
        for item in self.estimands:
            if item.sampling_unit == "trajectory" and item.role != "descriptive":
                raise ValueError(
                    f"estimand {item.estimand_id}: non-descriptive trajectory sampling forbidden"
                )
        return self

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


__all__ = [
    "AnalysisPreregistration",
    "EstimandMetric",
    "EstimandRole",
    "EstimandSpec",
    "InferenceMode",
    "InterpretationDirection",
    "IntervalMethod",
    "MissingnessPolicy",
    "MultiplicityPlan",
    "SamplingUnit",
    "StoppingPlan",
]
