"""Opaque content-addressed attacker state envelopes (WP-03).

Workers return state through the one-shot protocol. Coordinators store envelopes
content-addressed and may pass only an authorized parent digest to a subsequent
unit. No shared writable filesystem is required for security-grade execution.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.cas import ContentAddressedStore

AttackMode = Literal["persistent_attack", "fresh_attack"]

# Hard cap on opaque state bytes transferred through the one-shot channel.
DEFAULT_MAX_STATE_BYTES = 1_048_576  # 1 MiB


class AttackerStateEnvelope(BaseModel):
    """Opaque attacker state with append-only lineage metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    state_digest: str = Field(min_length=64, max_length=64)
    opaque_payload_digest: str = Field(min_length=64, max_length=64)
    strategy_identity_digest: str = Field(min_length=1)
    program_identity_digest: str = Field(min_length=1)
    attack_mode: AttackMode
    parent_state_digest: str | None = None
    campaign_digest: str = Field(min_length=1)
    run_digest: str = Field(min_length=1)
    round_index: int = Field(ge=0)
    runtime_identity_digest: str = Field(min_length=1)
    size_bytes: int = Field(ge=0, le=DEFAULT_MAX_STATE_BYTES)
    integrity_digest: str = Field(min_length=64, max_length=64)
    confidentiality_envelope_digest: str | None = None
    branch_id: str = Field(min_length=1)
    lineage_index: int = Field(ge=0)

    @model_validator(mode="after")
    def _mode_shape(self) -> AttackerStateEnvelope:
        if self.attack_mode == "fresh_attack":
            if self.parent_state_digest is not None:
                raise ValueError("fresh_attack requires parent_state_digest=null")
            if self.lineage_index != 0:
                raise ValueError("fresh_attack requires lineage_index=0")
        elif self.parent_state_digest is None and self.lineage_index > 0:
            raise ValueError("persistent_attack continuation requires parent_state_digest")
        return self

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class AttackerStateLineage(BaseModel):
    """Append-only lineage heads keyed by explicit branch_id (no last-write-wins)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    campaign_digest: str
    run_digest: str
    branch_heads: dict[str, str] = Field(default_factory=dict)
    envelopes: tuple[str, ...] = ()

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def scan_envelope_payload(payload: bytes, *, max_bytes: int = DEFAULT_MAX_STATE_BYTES) -> None:
    """Reject oversize or protocol-violating opaque payloads."""
    if len(payload) > max_bytes:
        raise ValueError(f"attacker state exceeds size cap: {len(payload)}>{max_bytes}")
    # Workers never possess hidden labels; still reject obvious vault/label markers.
    lowered = payload.lower()
    for token in (b"gt_valid", b"label_vault", b"hidden_label", b"commitment_nonce"):
        if token in lowered:
            raise ValueError(f"attacker state payload contains forbidden token: {token!r}")


def make_attacker_state_envelope(
    *,
    opaque_payload: bytes,
    strategy_identity_digest: str,
    program_identity_digest: str,
    attack_mode: AttackMode,
    campaign_digest: str,
    run_digest: str,
    round_index: int,
    runtime_identity_digest: str,
    branch_id: str,
    lineage_index: int,
    parent_state_digest: str | None = None,
    confidentiality_envelope_digest: str | None = None,
    max_bytes: int = DEFAULT_MAX_STATE_BYTES,
) -> AttackerStateEnvelope:
    """Build an envelope after scanning and digesting opaque state bytes."""
    scan_envelope_payload(opaque_payload, max_bytes=max_bytes)
    opaque_digest = digest_of({"opaque": opaque_payload.hex()})
    integrity = digest_of(
        {
            "opaque_payload_digest": opaque_digest,
            "strategy_identity_digest": strategy_identity_digest,
            "program_identity_digest": program_identity_digest,
            "attack_mode": attack_mode,
            "parent_state_digest": parent_state_digest,
            "campaign_digest": campaign_digest,
            "run_digest": run_digest,
            "round_index": round_index,
            "runtime_identity_digest": runtime_identity_digest,
            "branch_id": branch_id,
            "lineage_index": lineage_index,
        }
    )
    envelope = AttackerStateEnvelope(
        state_digest=integrity,  # provisional; rebound to full body digest below
        opaque_payload_digest=opaque_digest,
        strategy_identity_digest=strategy_identity_digest,
        program_identity_digest=program_identity_digest,
        attack_mode=attack_mode,
        parent_state_digest=parent_state_digest,
        campaign_digest=campaign_digest,
        run_digest=run_digest,
        round_index=round_index,
        runtime_identity_digest=runtime_identity_digest,
        size_bytes=len(opaque_payload),
        integrity_digest=integrity,
        confidentiality_envelope_digest=confidentiality_envelope_digest,
        branch_id=branch_id,
        lineage_index=lineage_index,
    )
    return envelope.model_copy(update={"state_digest": envelope.content_digest})


def append_envelope(
    lineage: AttackerStateLineage,
    envelope: AttackerStateEnvelope,
) -> AttackerStateLineage:
    """Append an envelope on an explicit branch. Concurrent heads must not collide."""
    if envelope.campaign_digest != lineage.campaign_digest:
        raise ValueError("envelope campaign_digest does not match lineage")
    if envelope.run_digest != lineage.run_digest:
        raise ValueError("envelope run_digest does not match lineage")
    if envelope.content_digest in lineage.envelopes:
        raise ValueError("envelope already present in lineage (append-only duplicate)")
    head = lineage.branch_heads.get(envelope.branch_id)
    if envelope.attack_mode == "persistent_attack" and envelope.lineage_index > 0:
        if head is None:
            raise ValueError("persistent continuation requires existing branch head")
        if envelope.parent_state_digest != head:
            raise ValueError("parent_state_digest does not match branch head (no last-write-wins)")
    if envelope.attack_mode == "fresh_attack" and head is not None:
        raise ValueError("fresh_attack cannot reuse an existing branch head")
    heads = dict(lineage.branch_heads)
    heads[envelope.branch_id] = envelope.content_digest
    return AttackerStateLineage(
        campaign_digest=lineage.campaign_digest,
        run_digest=lineage.run_digest,
        branch_heads=heads,
        envelopes=(*lineage.envelopes, envelope.content_digest),
    )


def store_envelope_payload(
    store: ContentAddressedStore,
    opaque_payload: bytes,
    *,
    max_bytes: int = DEFAULT_MAX_STATE_BYTES,
) -> str:
    """CAS-put opaque bytes (hex JSON wrapper) and return the store digest."""
    scan_envelope_payload(opaque_payload, max_bytes=max_bytes)
    return store.put_json({"opaque_hex": opaque_payload.hex(), "size_bytes": len(opaque_payload)})


def assert_fresh_attack_qualification(
    envelope: AttackerStateEnvelope,
    *,
    inherited_parent: str | None,
) -> None:
    """Fresh reattack inheritance is a qualification blocker."""
    if envelope.attack_mode != "fresh_attack":
        return
    if inherited_parent is not None or envelope.parent_state_digest is not None:
        raise ValueError("fresh_reattack_inheritance_blocker: parent state must be null")


def work_unit_state_binding(envelope: AttackerStateEnvelope | None) -> dict[str, Any]:
    """Coordinator-mediated state binding for a subsequent work unit."""
    if envelope is None:
        return {
            "attack_mode": "fresh_attack",
            "attacker_state_digest": None,
            "parent_state_digest": None,
        }
    return {
        "attack_mode": envelope.attack_mode,
        "attacker_state_digest": envelope.content_digest,
        "parent_state_digest": envelope.parent_state_digest,
        "branch_id": envelope.branch_id,
        "runtime_identity_digest": envelope.runtime_identity_digest,
    }


__all__ = [
    "DEFAULT_MAX_STATE_BYTES",
    "AttackMode",
    "AttackerStateEnvelope",
    "AttackerStateLineage",
    "append_envelope",
    "assert_fresh_attack_qualification",
    "make_attacker_state_envelope",
    "scan_envelope_payload",
    "store_envelope_payload",
    "work_unit_state_binding",
]
