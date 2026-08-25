"""Independent reconstruction interface (WP-21).

``valab reproduce BUNDLE`` loads a self-contained reproduction bundle and emits
a ``ReconstructionReport``. Signed ``ExternalAssuranceAttestation`` objects are
verified against configured trust roots; self-issued and subject-mismatched
attestations are rejected. Internal clean-room dry-runs validate mechanics and
are explicitly marked NOT independent.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from verifierlab.artifacts.canonical import digest_of
from verifierlab.assurance.maturity import AssuranceClaim
from verifierlab.assurance.resolver import (
    ExternalAssuranceAttestation,
    verify_external_attestation,
)

REPRO_BUNDLE_SCHEMA = "1"


class ReproductionBundle(BaseModel):
    """Self-contained reproduction package for independent reconstruction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    bundle_id: str = Field(min_length=1)
    subject_digest: str = Field(min_length=64, max_length=64)
    claim_digest: str = Field(min_length=64, max_length=64)
    study_or_run_digest: str = Field(min_length=64, max_length=64)
    artifact_digests: tuple[str, ...] = ()
    instruction_digest: str = Field(min_length=64, max_length=64)
    trust_root_ids: tuple[str, ...] = ()
    clean_room_protocol_ref: str = "docs/clean-room-protocol.md"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class ReconstructionReport(BaseModel):
    """Result of attempting to reconstruct a study/run from a reproduction bundle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    report_id: str = Field(min_length=1)
    bundle_digest: str = Field(min_length=64, max_length=64)
    subject_digest: str = Field(min_length=64, max_length=64)
    reconstructed: bool
    independent: bool
    attestation_verified: bool
    mechanics_ok: bool
    blockers: tuple[str, ...] = ()
    satisfied: tuple[str, ...] = ()
    clean_room_dry_run: bool = False
    notes: tuple[str, ...] = ()
    reconstructed_at: float
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def load_reproduction_bundle(path: Path | str) -> tuple[ReproductionBundle, Path]:
    """Load bundle JSON from a file or directory containing ``bundle.json``."""
    root = Path(path)
    if root.is_dir():
        bundle_path = root / "bundle.json"
    else:
        bundle_path = root
        root = bundle_path.parent
    if not bundle_path.is_file():
        raise ValueError(f"reproduction bundle missing: {bundle_path}")
    body = json.loads(bundle_path.read_text(encoding="utf-8"))
    if str(body.get("schema_version") or "") != REPRO_BUNDLE_SCHEMA:
        raise ValueError(
            f"unsupported reproduction bundle schema_version={body.get('schema_version')!r}; "
            f"expected {REPRO_BUNDLE_SCHEMA}"
        )
    bundle = ReproductionBundle.model_validate(
        {k: v for k, v in body.items() if k != "content_digest"}
    )
    declared = body.get("content_digest")
    if declared is not None and str(declared) != bundle.digest:
        raise ValueError("reproduction bundle digest tamper detected")
    return bundle, root


def reproduce_bundle(
    bundle_path: Path | str,
    *,
    claim: AssuranceClaim | dict[str, Any] | Path | str | None = None,
    trust_roots: dict[str, str] | None = None,
    attestation: ExternalAssuranceAttestation | dict[str, Any] | Path | str | None = None,
    clean_room_dry_run: bool = False,
) -> ReconstructionReport:
    """Reproduce from a bundle; independent only with verified external attestation."""
    bundle, root = load_reproduction_bundle(bundle_path)
    blockers: list[str] = []
    satisfied: list[str] = []
    notes: list[str] = []

    # Mechanics: required artifact digests present as files or cas pointers.
    artifacts_dir = root / "artifacts"
    missing: list[str] = []
    for dig in bundle.artifact_digests:
        hit = False
        if artifacts_dir.is_dir():
            for path in artifacts_dir.rglob("*"):
                if path.is_file() and dig in path.name:
                    hit = True
                    break
            if not hit:
                # Also accept digest manifest.
                manifest = artifacts_dir / "digests.json"
                if manifest.is_file():
                    listed = json.loads(manifest.read_text(encoding="utf-8"))
                    if dig in listed or dig in (listed.get("digests") or []):
                        hit = True
        if not hit:
            missing.append(dig)
    mechanics_ok = not missing
    if mechanics_ok:
        satisfied.append("artifact_digests_present")
    else:
        blockers.append("missing_artifacts")
        notes.append(f"missing_artifact_count={len(missing)}")

    claim_obj: AssuranceClaim | None = None
    if claim is not None:
        if isinstance(claim, str | Path):
            claim_obj = AssuranceClaim.model_validate(
                json.loads(Path(claim).read_text(encoding="utf-8"))
            )
        elif isinstance(claim, dict):
            claim_obj = AssuranceClaim.model_validate(claim)
        else:
            claim_obj = claim
        if claim_obj.digest != bundle.claim_digest:
            blockers.append("claim_digest_mismatch")
        else:
            satisfied.append("claim_bound")
    else:
        claim_path = root / "claim.json"
        if claim_path.is_file():
            claim_obj = AssuranceClaim.model_validate(
                json.loads(claim_path.read_text(encoding="utf-8"))
            )
            if claim_obj.digest != bundle.claim_digest:
                blockers.append("claim_digest_mismatch")
            else:
                satisfied.append("claim_bound")
        else:
            blockers.append("claim_missing")

    attestation_verified = False
    att_obj: ExternalAssuranceAttestation | None = None
    if attestation is not None:
        if isinstance(attestation, str | Path):
            att_obj = ExternalAssuranceAttestation.model_validate(
                json.loads(Path(attestation).read_text(encoding="utf-8"))
            )
        elif isinstance(attestation, dict):
            att_obj = ExternalAssuranceAttestation.model_validate(attestation)
        else:
            att_obj = attestation
    else:
        att_path = root / "attestation.json"
        if att_path.is_file():
            att_obj = ExternalAssuranceAttestation.model_validate(
                json.loads(att_path.read_text(encoding="utf-8"))
            )

    if clean_room_dry_run:
        notes.append("internal_clean_room_dry_run_NOT_independent")
        blockers.append("not_independent_clean_room")
        independent = False
    elif att_obj is None:
        blockers.append("external_attestation_missing")
        independent = False
    elif claim_obj is None:
        blockers.append("claim_required_for_attestation")
        independent = False
    elif not trust_roots:
        blockers.append("trust_roots_not_configured")
        independent = False
    else:
        try:
            verify_external_attestation(
                att_obj,
                claim=claim_obj,
                trust_roots=trust_roots,
                subject_digest=bundle.subject_digest,
            )
            if att_obj.subject_digest != bundle.subject_digest:
                raise ValueError("attestation subject mismatch")
            attestation_verified = True
            satisfied.append("external_attestation_verified")
            if att_obj.reconstruction_digest:
                satisfied.append("reconstruction_digest_bound")
            else:
                blockers.append("reconstruction_digest_missing")
            independent = attestation_verified and "reconstruction_digest_missing" not in blockers
        except ValueError as exc:
            blockers.append(f"attestation_rejected:{exc}")
            independent = False

    reconstructed = mechanics_ok and "claim_digest_mismatch" not in blockers
    report = ReconstructionReport(
        report_id=f"recon-{bundle.bundle_id}",
        bundle_digest=bundle.digest,
        subject_digest=bundle.subject_digest,
        reconstructed=reconstructed,
        independent=independent and not clean_room_dry_run,
        attestation_verified=attestation_verified,
        mechanics_ok=mechanics_ok,
        blockers=tuple(blockers),
        satisfied=tuple(satisfied),
        clean_room_dry_run=clean_room_dry_run,
        notes=tuple(notes),
        reconstructed_at=time.time(),
        metadata={"bundle_id": bundle.bundle_id, "root": str(root)},
    )
    out = root / "reconstruction_report.json"
    out.write_text(
        json.dumps(
            {**report.model_dump(mode="json"), "content_digest": report.digest},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return report


def build_reproduction_bundle(
    out_dir: Path | str,
    *,
    bundle_id: str,
    subject_digest: str,
    claim: AssuranceClaim,
    study_or_run_digest: str,
    artifact_digests: tuple[str, ...] | list[str] = (),
    instructions: dict[str, Any] | None = None,
    trust_root_ids: tuple[str, ...] = (),
    clean_room: bool = False,
) -> ReproductionBundle:
    """Materialize a self-contained reproduction bundle directory."""
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    instr = instructions or {
        "steps": [
            "Verify artifact digests under artifacts/",
            "Load claim.json and confirm claim_digest",
            "Verify ExternalAssuranceAttestation against external trust roots",
            "Re-run sealed evaluation under declared execution boundary",
        ],
        "clean_room_protocol": "docs/clean-room-protocol.md",
    }
    if clean_room:
        instr = {
            **instr,
            "independence": "NOT_independent",
            "note": "Internal clean-room dry-run validates mechanics only",
        }
    instruction_digest = digest_of(instr)
    (root / "instructions.json").write_text(
        json.dumps({**instr, "content_digest": instruction_digest}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    (root / "claim.json").write_text(
        json.dumps(
            {**claim.model_dump(mode="json"), "content_digest": claim.digest},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    artifacts = root / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    digests = tuple(artifact_digests)
    (artifacts / "digests.json").write_text(
        json.dumps({"digests": list(digests)}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    bundle = ReproductionBundle(
        bundle_id=bundle_id,
        subject_digest=subject_digest,
        claim_digest=claim.digest,
        study_or_run_digest=study_or_run_digest,
        artifact_digests=digests,
        instruction_digest=instruction_digest,
        trust_root_ids=trust_root_ids,
        metadata={"clean_room": clean_room},
    )
    (root / "bundle.json").write_text(
        json.dumps(
            {**bundle.model_dump(mode="json"), "content_digest": bundle.digest},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return bundle


__all__ = [
    "REPRO_BUNDLE_SCHEMA",
    "ReconstructionReport",
    "ReproductionBundle",
    "build_reproduction_bundle",
    "load_reproduction_bundle",
    "reproduce_bundle",
]
