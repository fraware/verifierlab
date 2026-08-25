"""WP-21 independent reconstruction interface tests."""

from __future__ import annotations

from pathlib import Path

from verifierlab.assurance.maturity import AssuranceClaim
from verifierlab.assurance.reproduce import (
    build_reproduction_bundle,
    reproduce_bundle,
)
from verifierlab.assurance.resolver import sign_external_attestation


def _claim() -> AssuranceClaim:
    return AssuranceClaim(
        proposition="reconstruct study evidence",
        scope="flagship-2026 clean-room",
        assumptions=("artifacts complete",),
        trust_boundary="external reviewer",
        specification_refs=("cas:study:flagship",),
    )


def test_clean_room_mechanics_ok_but_not_independent(tmp_path: Path) -> None:
    claim = _claim()
    digests = ("a" * 64, "b" * 64)
    root = tmp_path / "bundle"
    build_reproduction_bundle(
        root,
        bundle_id="repro-1",
        subject_digest="c" * 64,
        claim=claim,
        study_or_run_digest="d" * 64,
        artifact_digests=digests,
        clean_room=True,
    )
    report = reproduce_bundle(root, claim=claim, clean_room_dry_run=True)
    assert report.mechanics_ok is True
    assert report.reconstructed is True
    assert report.independent is False
    assert report.clean_room_dry_run is True
    assert "not_independent_clean_room" in report.blockers


def test_self_issued_attestation_rejected(tmp_path: Path) -> None:
    claim = _claim()
    subject = "e" * 64
    root = tmp_path / "bundle"
    build_reproduction_bundle(
        root,
        bundle_id="repro-2",
        subject_digest=subject,
        claim=claim,
        study_or_run_digest="f" * 64,
        artifact_digests=("a" * 64,),
        trust_root_ids=("ext-root",),
    )
    # Self-issued reviewer_id == trust_root_id is rejected by verify_external_attestation.
    bad = sign_external_attestation(
        attestation_id="att-1",
        subject_digest=subject,
        claim=claim,
        reviewer_id="ext-root",
        trust_root_id="ext-root",
        trust_root_secret="secret",
        reconstruction_digest="r" * 64,
    )
    report = reproduce_bundle(
        root,
        claim=claim,
        trust_roots={"ext-root": "secret"},
        attestation=bad,
    )
    assert report.attestation_verified is False
    assert report.independent is False
    assert any("attestation_rejected" in b for b in report.blockers)


def test_valid_external_attestation_marks_independent(tmp_path: Path) -> None:
    claim = _claim()
    subject = "1" * 64
    root = tmp_path / "bundle"
    build_reproduction_bundle(
        root,
        bundle_id="repro-3",
        subject_digest=subject,
        claim=claim,
        study_or_run_digest="2" * 64,
        artifact_digests=("3" * 64,),
        trust_root_ids=("reviewer-root",),
    )
    att = sign_external_attestation(
        attestation_id="att-ok",
        subject_digest=subject,
        claim=claim,
        reviewer_id="external-reviewer-1",
        trust_root_id="reviewer-root",
        trust_root_secret="root-secret",
        reconstruction_digest="4" * 64,
    )
    report = reproduce_bundle(
        root,
        claim=claim,
        trust_roots={"reviewer-root": "root-secret"},
        attestation=att,
    )
    assert report.attestation_verified is True
    assert report.independent is True
    assert report.reconstructed is True


def test_subject_mismatch_rejected(tmp_path: Path) -> None:
    claim = _claim()
    root = tmp_path / "bundle"
    build_reproduction_bundle(
        root,
        bundle_id="repro-4",
        subject_digest="5" * 64,
        claim=claim,
        study_or_run_digest="6" * 64,
        artifact_digests=("7" * 64,),
    )
    att = sign_external_attestation(
        attestation_id="att-mismatch",
        subject_digest="8" * 64,
        claim=claim,
        reviewer_id="external-reviewer-1",
        trust_root_id="reviewer-root",
        trust_root_secret="root-secret",
        reconstruction_digest="9" * 64,
    )
    report = reproduce_bundle(
        root,
        claim=claim,
        trust_roots={"reviewer-root": "root-secret"},
        attestation=att,
    )
    assert report.independent is False
    assert report.attestation_verified is False
