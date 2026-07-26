"""Freeze records and immutability checks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import Field

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.lifecycle_records import SealedRunManifest, assert_sealed_immutable
from verifierlab.artifacts.records import ArtifactBase


class FreezeRecord(ArtifactBase):
    """Immutable freeze marker for a campaign run (append-only tip)."""

    kind: str = "freeze"
    freeze_id: str
    run_id: str
    campaign_digest: str
    prev_digest: str | None = None
    commitment_digests: list[str] = Field(default_factory=list)
    frozen_at: float
    metadata: dict[str, Any] = Field(default_factory=dict)

    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def assert_freeze_immutable(original: FreezeRecord, candidate: dict[str, Any]) -> None:
    """Reject any mutation of a freeze record payload."""
    if digest_of(original.model_dump(mode="json")) != digest_of(candidate):
        raise ValueError("FreezeRecord mutation rejected")


def assert_run_sealed_immutable(run_dir: Path) -> None:
    """Raise if sealed freeze.json / sealed_run.json digests were mutated."""
    run_dir = Path(run_dir)
    sealed_path = run_dir / "sealed_run.json"
    freeze_path = run_dir / "freeze.json"
    if sealed_path.is_file():
        sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
        sealed_body = {k: v for k, v in sealed.items() if k != "content_digest"}
        sealed_original = SealedRunManifest.model_validate(sealed_body)
        assert_sealed_immutable(sealed_original, sealed_body)
        if sealed.get("content_digest") != sealed_original.content_digest():
            raise ValueError("SealedRunManifest content_digest mismatch")
    if freeze_path.is_file():
        freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
        freeze_body = {k: v for k, v in freeze.items() if k not in {"content_digest"}}
        freeze_original = FreezeRecord.model_validate(freeze_body)
        assert_freeze_immutable(freeze_original, freeze_body)
