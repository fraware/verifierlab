"""Freeze records and immutability checks."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import ArtifactBase


class FreezeRecord(ArtifactBase):
    """Immutable freeze marker for a campaign run."""

    freeze_id: str
    run_id: str
    campaign_digest: str
    commitment_digests: list[str] = Field(default_factory=list)
    frozen_at: float
    metadata: dict[str, Any] = Field(default_factory=dict)

    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def assert_freeze_immutable(original: FreezeRecord, candidate: dict[str, Any]) -> None:
    """Reject any mutation of a freeze record payload."""
    if digest_of(original.model_dump(mode="json")) != digest_of(candidate):
        raise ValueError("FreezeRecord mutation rejected")
