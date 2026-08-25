"""Content-bound estimand declarations for executable statistical plans.

These models bind what will be estimated and how inferential uncertainty may be
reported. They do not by themselves prove that registration occurred before
outcomes were observed; temporal ordering must come from the campaign lifecycle
and immutable artifact history.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from verifierlab.artifacts.canonical import digest_of

EstimandMetric = Literal[
    "cohort_far",
    "cohort_frr",
    "optimization_gap",
    "exploit_rate",
]
EstimandRole = Literal["primary", "secondary"]
InferenceMode = Literal["interval", "descriptive"]
IntervalMethod = Literal["wilson", "exact", "bootstrap"]
InterpretationDirection = Literal["higher_is_worse", "lower_is_better", "two_sided"]


class EstimandSpec(BaseModel):
    """One declared estimand with an executable population and interval contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    estimand_id: str = Field(min_length=1)
    metric: EstimandMetric
    role: EstimandRole = "primary"
    inference: InferenceMode = "interval"
    cohort: str | None = None
    contrast: tuple[str, str] | None = None
    split: str | None = None
    interval_method: IntervalMethod | None = None
    alpha: float | None = Field(default=None, gt=0.0, lt=1.0)
    direction: InterpretationDirection = "two_sided"

    @model_validator(mode="after")
    def _metric_contract(self) -> EstimandSpec:
        if self.metric in {"cohort_far", "cohort_frr"}:
            if self.cohort is None or not self.cohort.strip():
                raise ValueError(f"{self.metric} requires a non-empty cohort")
            if self.contrast is not None:
                raise ValueError(f"{self.metric} does not accept contrast")
        elif self.metric == "optimization_gap":
            if self.cohort is not None:
                raise ValueError("optimization_gap does not accept cohort")
            if self.contrast is None or len(self.contrast) != 2:
                raise ValueError("optimization_gap requires a two-cohort contrast")
            if self.contrast[0] == self.contrast[1]:
                raise ValueError("optimization_gap contrast cohorts must differ")
            if any(not value.strip() for value in self.contrast):
                raise ValueError("optimization_gap contrast cohorts must be non-empty")
        else:
            if self.cohort is not None or self.contrast is not None:
                raise ValueError("exploit_rate does not accept cohort or contrast")

        if self.split is not None and not self.split.strip():
            raise ValueError("split must be non-empty when supplied")

        if self.inference == "descriptive":
            if self.interval_method is not None or self.alpha is not None:
                raise ValueError("descriptive estimands cannot declare interval_method or alpha")
            return self

        if self.interval_method is None or self.alpha is None:
            raise ValueError("interval estimands require interval_method and alpha")
        if self.metric == "optimization_gap" and self.interval_method != "bootstrap":
            raise ValueError("optimization_gap interval inference requires bootstrap")
        if self.metric != "optimization_gap" and self.interval_method == "bootstrap":
            raise ValueError("rate estimands require wilson or exact intervals")
        return self


class AnalysisPreregistration(BaseModel):
    """Immutable estimand family bound into a campaign's statistical plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    registration_id: str = Field(min_length=1)
    estimands: tuple[EstimandSpec, ...] = Field(min_length=1)
    assumptions: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_estimands(self) -> AnalysisPreregistration:
        ids = [item.estimand_id for item in self.estimands]
        if len(set(ids)) != len(ids):
            raise ValueError("estimand_id values must be unique")
        if not any(item.role == "primary" for item in self.estimands):
            raise ValueError("preregistration requires at least one primary estimand")
        if any(not assumption.strip() for assumption in self.assumptions):
            raise ValueError("assumptions must be non-empty")
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
]
