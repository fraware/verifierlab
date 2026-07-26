"""Append-only lifecycle artifact records (VAL-R05)."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import ArtifactBase


class AttackRunManifest(ArtifactBase):
    """Immutable tip after the attack plane finishes."""

    kind: str = "attack_run"
    run_id: str
    campaign_digest: str
    status: str
    work_unit_digests: list[str] = Field(default_factory=list)
    ledger_digest: str | None = None
    overrun: bool = False
    prev_digest: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class AdjudicationRecord(ArtifactBase):
    """Append-only record of post-freeze hidden-GT adjudication."""

    kind: str = "adjudication"
    adjudication_id: str
    run_id: str
    prev_digest: str
    freeze_digest: str
    sealed_commitments: list[str] = Field(default_factory=list)
    unit_count: int = 0
    exploit_count: int = 0
    adjudicated_at: float
    metadata: dict[str, Any] = Field(default_factory=dict)

    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class AdjudicationReleaseRecord(ArtifactBase):
    """Append-only label-release unlock after adjudication."""

    kind: str = "adjudication_release"
    release_id: str
    run_id: str
    prev_digest: str
    adjudication_digest: str | None = None
    released_at: float
    commitment_digests: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class AnalysisManifest(ArtifactBase):
    """Optional analysis tip after labels are released (reports / stats)."""

    kind: str = "analysis"
    analysis_id: str
    run_id: str
    prev_digest: str
    report_digest: str | None = None
    created_at: float
    metadata: dict[str, Any] = Field(default_factory=dict)

    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class LifecycleTipIndex(ArtifactBase):
    """Mutable pointer file body — not content-addressed as a tip itself.

    ``manifest.json`` stores this index so prior CAS tip objects remain
    immutable while clients resolve the latest lifecycle tip.
    """

    run_id: str
    tip_digest: str
    tip_kind: str
    lifecycle: str
    campaign_digest: str | None = None
    chain: list[str] = Field(default_factory=list)
    status: str | None = None
    work_unit_digests: list[str] = Field(default_factory=list)
    ledger_digest: str | None = None
    overrun: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class SealedRunManifest(ArtifactBase):
    """Immutable seal over a frozen run bundle (VALAB-05).

    Digests campaign definition, verifier/attack digests, environment
    fingerprint, seeds, budget, I/O, vault tip (not plaintext labels), and
    report configuration. Mutation of sealed CAS objects or freeze records
    after seal must raise.
    """

    schema_version: str = "1"
    kind: str = "sealed_run"
    seal_id: str
    run_id: str
    freeze_digest: str
    campaign_digest: str
    verifier_digest: str | None = None
    attack_digests: list[str] = Field(default_factory=list)
    environment_fingerprint: str | None = None
    random_seeds: dict[str, Any] = Field(default_factory=dict)
    budget_digest: str | None = None
    inputs_digest: str | None = None
    outputs_digest: str | None = None
    vault_tip_digest: str | None = None
    report_config_digest: str | None = None
    sealed_at: float
    metadata: dict[str, Any] = Field(default_factory=dict)

    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def assert_sealed_immutable(original: SealedRunManifest, candidate: dict[str, Any]) -> None:
    """Reject any mutation of a sealed-run manifest payload."""
    if digest_of(original.model_dump(mode="json")) != digest_of(candidate):
        raise ValueError("SealedRunManifest mutation rejected")
