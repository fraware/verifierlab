"""AttackIdentity: immutable binding for one attacker instance (WP-09)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import AccessModel

AttackDepth = Literal[
    "shallow_search",
    "budgeted_search",
    "model_assisted",
    "transfer_replay",
    "planted_calibration_only",
]


class AttackBudgetContract(BaseModel):
    """Declared query/time budget the attacker must not exceed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_queries: int = Field(gt=0)
    max_candidate_evals: int | None = Field(default=None, gt=0)
    wall_clock_seconds: float | None = Field(default=None, gt=0.0)

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class AttackIdentity(BaseModel):
    """Content-addressed attacker identity for freeze / surface / HFS binding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    strategy_name: str = Field(min_length=1)
    strategy_version: str = Field(min_length=1)
    source_digest: str = Field(min_length=1)
    configuration_digest: str = Field(min_length=1)
    seed: int
    model_id: str | None = None
    model_version: str | None = None
    program_digest: str | None = None
    state_lineage_head: str | None = None
    access_model: AccessModel
    budget: AttackBudgetContract
    depth: AttackDepth = "budgeted_search"
    supports_unknown_robustness_claim: Literal[False] | bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _model_and_claim_shape(self) -> AttackIdentity:
        if (self.model_id is None) != (self.model_version is None):
            raise ValueError("model_id and model_version must be supplied together")
        if self.depth == "planted_calibration_only" and self.supports_unknown_robustness_claim:
            raise ValueError(
                "planted_calibration_only attackers cannot support unknown-robustness claims"
            )
        return self

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def build_attack_identity(
    *,
    strategy_name: str,
    strategy_version: str,
    source_digest: str,
    configuration: dict[str, Any],
    seed: int,
    access_model: AccessModel | str,
    budget: AttackBudgetContract,
    depth: AttackDepth = "budgeted_search",
    model_id: str | None = None,
    model_version: str | None = None,
    program_digest: str | None = None,
    state_lineage_head: str | None = None,
    supports_unknown_robustness_claim: bool = False,
    metadata: dict[str, Any] | None = None,
) -> AttackIdentity:
    """Build an AttackIdentity with a canonical configuration digest."""
    access = AccessModel(access_model) if isinstance(access_model, str) else access_model
    return AttackIdentity(
        strategy_name=strategy_name,
        strategy_version=strategy_version,
        source_digest=source_digest,
        configuration_digest=digest_of(configuration),
        seed=seed,
        model_id=model_id,
        model_version=model_version,
        program_digest=program_digest,
        state_lineage_head=state_lineage_head,
        access_model=access,
        budget=budget,
        depth=depth,
        supports_unknown_robustness_claim=supports_unknown_robustness_claim,
        metadata=dict(metadata or {}),
    )


__all__ = [
    "AttackBudgetContract",
    "AttackDepth",
    "AttackIdentity",
    "build_attack_identity",
]
