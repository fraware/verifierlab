"""Pre-reattack repair candidate commitments.

A final repair qualification artifact cannot be the parent commitment of the
fresh reattack that it later incorporates: that would be circular. This module
creates the immutable commitment *before* the fresh campaign starts.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from verifierlab.artifacts.canonical import digest_of
from verifierlab.verifiers.profile import VerifierProfile


class RepairCandidateBinding(BaseModel):
    """Content-addressed repair candidate frozen before fresh reattack."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1"
    campaign_id: str = Field(min_length=1)
    old_verifier_profile_digest: str = Field(min_length=64, max_length=64)
    new_verifier_profile_digest: str = Field(min_length=64, max_length=64)
    regression_corpus_digest: str = Field(min_length=64, max_length=64)
    holdout_corpus_digest: str = Field(min_length=64, max_length=64)
    required_minimum_query_budget: int = Field(gt=0)
    protocol: str = "fresh_reattack_v1"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def build_repair_candidate_binding(
    *,
    campaign_id: str,
    old_profile: VerifierProfile,
    new_profile: VerifierProfile,
    regression_trajectories: list[dict[str, Any]],
    holdout_trajectories: list[dict[str, Any]],
    required_minimum_query_budget: int,
    metadata: dict[str, Any] | None = None,
) -> RepairCandidateBinding:
    """Freeze the exact repair candidate that a later fresh run must cite."""
    if required_minimum_query_budget <= 0:
        raise ValueError("required_minimum_query_budget must be positive")
    if not holdout_trajectories:
        raise ValueError("repair candidate requires a caller-supplied holdout corpus")
    return RepairCandidateBinding(
        campaign_id=campaign_id,
        old_verifier_profile_digest=old_profile.content_digest(),
        new_verifier_profile_digest=new_profile.content_digest(),
        regression_corpus_digest=digest_of(regression_trajectories),
        holdout_corpus_digest=digest_of(holdout_trajectories),
        required_minimum_query_budget=int(required_minimum_query_budget),
        metadata=dict(metadata or {}),
    )


__all__ = ["RepairCandidateBinding", "build_repair_candidate_binding"]
