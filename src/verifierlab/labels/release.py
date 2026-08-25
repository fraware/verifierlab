"""Label release receipts binding sealed runs to released label sets (WP-04)."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import ArtifactBase


class LabelReleaseReceipt(ArtifactBase):
    """Immutable receipt binding an exact sealed run to a released label set.

    Reports that claim post-release labels must cite this receipt. The receipt
    digests the sealed-run identity and the ordered commitment set so a later
    label inject or seal rebind fails closed.
    """

    schema_version: str = "1"
    kind: str = "label_release_receipt"
    receipt_id: str
    run_id: str
    sealed_run_digest: str = Field(min_length=64, max_length=64)
    freeze_digest: str = Field(min_length=64, max_length=64)
    adjudication_digest: str | None = None
    label_set_digest: str = Field(min_length=64, max_length=64)
    commitment_digests: list[str] = Field(default_factory=list)
    released_at: float
    chronology: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def label_set_digest(commitment_digests: list[str]) -> str:
    """Canonical digest over the exact released commitment set."""
    return digest_of({"commitments": sorted(str(c) for c in commitment_digests)})


def assert_receipt_binds_seal(
    receipt: LabelReleaseReceipt,
    *,
    sealed_run_digest: str,
    freeze_digest: str,
) -> None:
    """Reject a receipt that does not bind the sealed run under analysis."""
    if receipt.sealed_run_digest != sealed_run_digest:
        raise ValueError("LabelReleaseReceipt sealed_run_digest mismatch")
    if receipt.freeze_digest != freeze_digest:
        raise ValueError("LabelReleaseReceipt freeze_digest mismatch")
    expected = label_set_digest(receipt.commitment_digests)
    if receipt.label_set_digest != expected:
        raise ValueError("LabelReleaseReceipt label_set_digest mismatch")


__all__ = [
    "LabelReleaseReceipt",
    "assert_receipt_binds_seal",
    "label_set_digest",
]
