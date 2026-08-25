"""Lifecycle chronology evidence and research registration hooks (WP-04)."""

from __future__ import annotations

import json
import time
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import Field

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import ArtifactBase


class ResearchRegistrationKind(str, Enum):
    PLANTED_CALIBRATION = "planted_calibration"
    METAMORPHIC_SUITE = "metamorphic_suite"
    HACKER_FIXER_SOLVER = "hacker_fixer_solver"
    RESPONSE_SURFACE = "response_surface"
    DEPLOYMENT_PREDICTION = "deployment_prediction"
    ANALYSIS_PREREGISTRATION = "analysis_preregistration"


class ChronologyEvidence(ArtifactBase):
    """Machine-checkable ordering claims for freeze / attack / registration.

    Stronger external timestamp / transparency-log anchors may be attached in
    ``anchors`` when available; self-authored wall-clock alone is insufficient
    for deployment-calibration independence claims (WP-15).
    """

    schema_version: str = "1"
    kind: str = "chronology_evidence"
    run_id: str
    sealed_before_attack: bool = False
    registered_before_outcomes: bool = False
    attack_started_at: float | None = None
    sealed_at: float | None = None
    registration_digests: list[str] = Field(default_factory=list)
    outcome_digests: list[str] = Field(default_factory=list)
    anchors: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class ResearchRegistration(ArtifactBase):
    """Pre-outcome registration tip for research instruments (stubs OK for WP-15)."""

    schema_version: str = "1"
    kind: str = "research_registration"
    registration_id: str
    run_id: str
    registration_kind: ResearchRegistrationKind
    payload_digest: str = Field(min_length=64, max_length=64)
    registered_at: float
    before_outcomes: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)

    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class FreezeSealBundle(ArtifactBase):
    """Digests sealed at freeze — attack evidence becomes immutable afterward."""

    schema_version: str = "2"
    kind: str = "freeze_seal_bundle"
    run_id: str
    campaign_digest: str = Field(min_length=64, max_length=64)
    split_manifest_digest: str | None = None
    public_split_view_digest: str | None = None
    custody_digest: str | None = None
    verifier_profile_digest: str | None = None
    attacker_identity_digests: list[str] = Field(default_factory=list)
    budget_digest: str | None = None
    work_unit_cas_digest: str | None = None
    execution_boundary_digests: list[str] = Field(default_factory=list)
    attack_state_head_digests: list[str] = Field(default_factory=list)
    public_commitment_digests: list[str] = Field(default_factory=list)
    preregistration_digest: str | None = None
    research_registration_digests: list[str] = Field(default_factory=list)
    chronology_digest: str | None = None
    sealed_at: float
    metadata: dict[str, Any] = Field(default_factory=dict)

    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def register_research_instrument(
    run_dir: Path,
    *,
    run_id: str,
    registration_kind: ResearchRegistrationKind | str,
    payload: dict[str, Any],
    registration_id: str | None = None,
    allow_after_outcomes: bool = False,
) -> ResearchRegistration:
    """Append a pre-outcome research registration under ``run_dir/registrations/``.

    Fail closed if outcomes already exist unless ``allow_after_outcomes`` is set
    (tests / explicit amendment only).
    """
    run_dir = Path(run_dir)
    kind = ResearchRegistrationKind(registration_kind)
    outcomes_marker = run_dir / "analysis" / "work_units"
    has_outcomes = outcomes_marker.is_dir() and any(outcomes_marker.glob("*.json"))
    if has_outcomes and not allow_after_outcomes:
        raise ValueError(
            f"registered_before_outcomes violated for {kind.value}: outcomes already present"
        )

    payload_digest = digest_of(payload)
    rid = registration_id or f"{kind.value}-{payload_digest[:16]}"
    rec = ResearchRegistration(
        registration_id=rid,
        run_id=run_id,
        registration_kind=kind,
        payload_digest=payload_digest,
        registered_at=time.time(),
        before_outcomes=not has_outcomes,
        metadata={"payload_keys": sorted(payload.keys())},
    )
    out_dir = run_dir / "registrations"
    out_dir.mkdir(parents=True, exist_ok=True)
    body = rec.model_dump(mode="json")
    digest = rec.content_digest()
    (out_dir / f"{rid}.json").write_text(
        json.dumps({**body, "content_digest": digest}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / f"{rid}.payload.json").write_text(
        json.dumps({**payload, "content_digest": payload_digest}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return rec


def list_registration_digests(run_dir: Path) -> list[str]:
    run_dir = Path(run_dir)
    reg_dir = run_dir / "registrations"
    if not reg_dir.is_dir():
        return []
    digests: list[str] = []
    for path in sorted(reg_dir.glob("*.json")):
        if path.name.endswith(".payload.json"):
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        dig = data.get("content_digest")
        if dig:
            digests.append(str(dig))
    return digests


def build_chronology_evidence(
    run_dir: Path,
    *,
    run_id: str,
    attack_started_at: float | None = None,
    sealed_at: float | None = None,
    anchors: dict[str, Any] | None = None,
) -> ChronologyEvidence:
    """Derive chronology claims from on-disk lifecycle artifacts."""
    run_dir = Path(run_dir)
    registrations = list_registration_digests(run_dir)
    sealed_path = run_dir / "sealed_run.json"
    sealed_present = sealed_path.is_file()
    sealed_ts = sealed_at
    if sealed_present and sealed_ts is None:
        sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
        sealed_ts = float(sealed.get("sealed_at") or 0.0) or None

    meta_path = run_dir / "manifest.json"
    attack_ts = attack_started_at
    if attack_ts is None and meta_path.is_file():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        attack_ts = (meta.get("metadata") or {}).get("attack_started_at")

    # Ordinary campaigns seal after attack (False). Planted instruments may seal
    # a design before attack (True). Surface the measured relation honestly.
    sealed_before_attack = (
        sealed_ts is not None and attack_ts is not None and float(sealed_ts) < float(attack_ts)
    )

    outcomes: list[str] = []
    analysis = run_dir / "analysis" / "work_units"
    if analysis.is_dir():
        for path in sorted(analysis.glob("*.json")):
            outcomes.append(digest_of(json.loads(path.read_text(encoding="utf-8"))))

    registered_before = True
    if registrations and outcomes:
        # Registrations file mtimes are weak; require explicit before_outcomes flag.
        for path in sorted((run_dir / "registrations").glob("*.json")):
            if path.name.endswith(".payload.json"):
                continue
            body = json.loads(path.read_text(encoding="utf-8"))
            if not body.get("before_outcomes", False):
                registered_before = False
                break
    elif not registrations:
        registered_before = False

    return ChronologyEvidence(
        run_id=run_id,
        sealed_before_attack=sealed_before_attack,
        registered_before_outcomes=registered_before if registrations else False,
        attack_started_at=float(attack_ts) if attack_ts is not None else None,
        sealed_at=float(sealed_ts) if sealed_ts is not None else None,
        registration_digests=registrations,
        outcome_digests=outcomes,
        anchors=dict(anchors or {}),
        metadata={"source": "lifecycle_artifacts"},
    )


def assert_attack_plane_immutable(run_dir: Path, *, expected_work_unit_digest: str) -> None:
    """Reject post-freeze mutation of attack-plane work units."""
    from verifierlab.campaigns.engine import _digest_tree

    current = _digest_tree(Path(run_dir) / "work_units")
    if current != expected_work_unit_digest:
        raise ValueError("post-freeze attack evidence mutation rejected")


def assert_label_inject_before_release_rejected(
    *,
    frozen: bool,
    released: bool,
    role: str,
) -> None:
    """Policy helper for adversarial label-inject tests."""
    if released:
        raise RuntimeError("label inject after release rejected")
    if frozen and role != "adjudicator":
        raise RuntimeError("label inject before adjudication/release rejected")
    if not frozen:
        raise RuntimeError("label inject before freeze rejected for sealed-holdout path")


__all__ = [
    "ChronologyEvidence",
    "FreezeSealBundle",
    "ResearchRegistration",
    "ResearchRegistrationKind",
    "assert_attack_plane_immutable",
    "assert_label_inject_before_release_rejected",
    "build_chronology_evidence",
    "list_registration_digests",
    "register_research_instrument",
]
