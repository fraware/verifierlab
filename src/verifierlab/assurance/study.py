"""Flagship preregistered scientific study registration (WP-13)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from verifierlab.artifacts.canonical import digest_of

StudyPartition = Literal[
    "discovery",
    "clean_regression",
    "repair_holdout",
    "final_sealed_evaluation",
    "transfer_corpus",
    "planted_calibration",
]


class ScientificStudyRegistration(BaseModel):
    """Immutable pre-outcome registration for a flagship scientific study."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    study_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    preregistration_digest: str = Field(min_length=64, max_length=64)
    partition_digests: dict[str, str] = Field(default_factory=dict)
    task_family_refs: tuple[str, ...] = Field(min_length=1)
    attack_portfolio_digest: str | None = Field(default=None, min_length=64, max_length=64)
    response_surface_plan_digest: str | None = Field(default=None, min_length=64, max_length=64)
    environment_assurance_digest: str | None = Field(default=None, min_length=64, max_length=64)
    assurance_chain_digest: str | None = Field(default=None, min_length=64, max_length=64)
    power_plan_digest: str | None = Field(default=None, min_length=64, max_length=64)
    primary_estimand_ids: tuple[str, ...] = Field(min_length=1)
    registered_at: float
    chronology_event_digest: str | None = Field(default=None, min_length=64, max_length=64)
    claim_boundary: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _partitions(self) -> ScientificStudyRegistration:
        required = {
            "discovery",
            "clean_regression",
            "repair_holdout",
            "final_sealed_evaluation",
            "transfer_corpus",
            "planted_calibration",
        }
        missing = required - set(self.partition_digests)
        if missing:
            raise ValueError(f"partition_digests missing required keys: {sorted(missing)}")
        for key, dig in self.partition_digests.items():
            if len(dig) != 64:
                raise ValueError(f"partition digest for {key} must be 64 hex chars")
        return self

    @property
    def digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


__all__ = ["ScientificStudyRegistration", "StudyPartition"]
