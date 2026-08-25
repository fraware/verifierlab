"""WP-05 artifact-validated EvidenceResolver qualification tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from verifierlab.assurance import (
    SEED_NOT_QUALIFICATION_PATH,
    AssuranceClaim,
    AssuranceLevel,
    EvidenceResolver,
    qualify_run,
    sign_external_attestation,
)
from verifierlab.campaigns.engine import (
    adjudicate_campaign,
    freeze_run,
    init_workspace,
    release_labels,
    run_campaign,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FAKE_SMOKE = REPO_ROOT / "campaigns" / "fake-smoke.yaml"


def _claim() -> AssuranceClaim:
    return AssuranceClaim(
        proposition="verifier remains valid under declared optimization regime",
        scope="campaign family A; black-box access; query budget <= 1000",
        assumptions=(
            "hidden adjudication labels remain outside the attack plane",
            "declared verifier profile is immutable during the run",
        ),
        trust_boundary="isolated worker plane; separate adjudication trust domain",
        specification_refs=("cas:verifier-profile:abc123", "cas:campaign-spec:def456"),
    )


def test_seed_path_flag_still_clear() -> None:
    import verifierlab.assurance as assurance

    assert SEED_NOT_QUALIFICATION_PATH is True
    assert "qualify_run" in assurance.__all__
    assert "EvidenceResolver" in assurance.__all__
    assert "AssuranceEvidence" not in assurance.__all__


def test_manual_boolean_bag_cannot_qualify(tmp_path: Path) -> None:
    run = tmp_path / "empty"
    run.mkdir()
    (run / "assurance_evidence_booleans.json").write_text(
        json.dumps(
            {
                "implemented": True,
                "internal_tests_passed": True,
                "independent_review": True,
                "security_grade": True,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="boolean bags are not a qualification path"):
        qualify_run(run, claim=_claim())


def test_empty_run_stays_not_implemented(tmp_path: Path) -> None:
    run = tmp_path / "empty"
    run.mkdir()
    result = qualify_run(run, claim=_claim())
    assert result.level == AssuranceLevel.NOT_IMPLEMENTED.label
    assert "implementation_missing" in result.blockers
    assert result.resolver_version == "2"
    assert result.security_grade_execution is False
    assert "0" * 64 not in result.artifact_refs


def test_local_sealed_run_caps_below_scientific(tmp_path: Path) -> None:
    ws = init_workspace(tmp_path / "ws")
    result = run_campaign(FAKE_SMOKE, workspace=ws, use_processes=False)
    freeze_run(result.run_dir)
    adjudicate_campaign(result.run_dir, campaign_path=FAKE_SMOKE)
    release_labels(result.run_dir)
    q = qualify_run(result.run_dir, claim=_claim())
    assert q.ordinal <= AssuranceLevel.INTERNALLY_VERIFIED
    assert q.security_grade_execution is False
    assert "security_grade_execution" not in q.satisfied
    assert "0" * 64 not in q.artifact_refs


def test_tamper_sealed_digest_blocks_maturity(tmp_path: Path) -> None:
    ws = init_workspace(tmp_path / "ws")
    result = run_campaign(FAKE_SMOKE, workspace=ws, use_processes=False)
    freeze_run(result.run_dir)
    adjudicate_campaign(result.run_dir, campaign_path=FAKE_SMOKE)
    release_labels(result.run_dir)
    sealed_path = result.run_dir / "sealed_run.json"
    sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
    sealed["budget_digest"] = "0" * 64
    sealed["metadata"] = {**(sealed.get("metadata") or {}), "security_grade": True}
    # Deliberately retain the stale content_digest. A content-addressed resolver
    # must reject this mutation before consulting the security-shaped metadata.
    sealed_path.write_text(json.dumps(sealed, indent=2), encoding="utf-8")
    q = qualify_run(result.run_dir, claim=_claim())
    assert q.ordinal < AssuranceLevel.INTERNALLY_VERIFIED
    assert q.security_grade_execution is False


def test_forged_evidence_shaped_stubs_cannot_promote(tmp_path: Path) -> None:
    """Arbitrary digest-looking JSON must never become qualification evidence."""
    run = tmp_path / "study"
    run.mkdir()
    sealed = {
        "schema_version": "2",
        "kind": "sealed_run",
        "seal_id": "s",
        "run_id": "r",
        "freeze_digest": "a" * 64,
        "campaign_digest": "b" * 64,
        "budget_digest": "c" * 64,
        "custody_digest": "d" * 64,
        "preregistration_digest": "e" * 64,
        "vault_tip_digest": "f" * 64,
        "content_digest": "1" * 64,
        "sealed_at": 1.0,
        "metadata": {
            "execution_mode": "docker_rootless",
            "security_grade": True,
            "execution_boundary_digests": ["a" * 64],
        },
        "execution_boundary_digests": ["a" * 64],
    }
    (run / "sealed_run.json").write_text(json.dumps(sealed), encoding="utf-8")
    (run / "freeze.json").write_text(
        json.dumps({"content_digest": "a" * 64, "freeze_id": "f"}), encoding="utf-8"
    )
    (run / "release.json").write_text(
        json.dumps({"content_digest": "b" * 64, "release_id": "r"}), encoding="utf-8"
    )
    (run / "label_release_receipt.json").write_text(
        json.dumps({"content_digest": "c" * 64}), encoding="utf-8"
    )
    (run / "custody").mkdir()
    (run / "custody" / "hidden_split.json").write_text(
        json.dumps({"content_digest": "d" * 64}), encoding="utf-8"
    )
    (run / "vault" / "commitments").mkdir(parents=True)

    claim = _claim()
    roots = {"ext-root": "secret-root-material"}
    att = sign_external_attestation(
        attestation_id="att-1",
        subject_digest="1" * 64,
        claim=claim,
        reviewer_id="external-reviewer-1",
        trust_root_id="ext-root",
        trust_root_secret="secret-root-material",
        reconstruction_digest="2" * 64,
    )
    qualification = EvidenceResolver(
        run,
        claim=claim,
        trust_roots=roots,
        attestations=[att],
    ).qualify()
    assert qualification.ordinal < AssuranceLevel.INTERNALLY_VERIFIED
    assert qualification.security_grade_execution is False
    assert "0" * 64 not in qualification.artifact_refs


def test_self_issued_attestation_rejected(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "sealed_run.json").write_text(
        json.dumps({"content_digest": "1" * 64, "metadata": {}}),
        encoding="utf-8",
    )
    claim = _claim()
    att = sign_external_attestation(
        attestation_id="att-self",
        subject_digest="1" * 64,
        claim=claim,
        reviewer_id="self",
        trust_root_id="ext-root",
        trust_root_secret="secret",
        reconstruction_digest="2" * 64,
    )
    q = EvidenceResolver(
        run, claim=claim, trust_roots={"ext-root": "secret"}, attestations=[att]
    ).qualify()
    assert "independent_review_missing" in q.blockers or q.ordinal < (
        AssuranceLevel.INDEPENDENTLY_VERIFIED
    )


def test_wrong_subject_attestation_rejected() -> None:
    from verifierlab.assurance import verify_external_attestation

    claim = _claim()
    att = sign_external_attestation(
        attestation_id="att-x",
        subject_digest="1" * 64,
        claim=claim,
        reviewer_id="reviewer-a",
        trust_root_id="ext-root",
        trust_root_secret="secret",
    )
    with pytest.raises(ValueError, match="subject mismatch"):
        verify_external_attestation(
            att,
            claim=claim,
            trust_roots={"ext-root": "secret"},
            subject_digest="2" * 64,
        )


def test_cli_assurance_qualify(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from verifierlab.cli import app

    run = tmp_path / "run"
    run.mkdir()
    claim_path = tmp_path / "claim.json"
    claim_path.write_text(json.dumps(_claim().model_dump(mode="json")), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["assurance", "qualify", str(run), "--claim", str(claim_path)],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["level"] == "not_implemented"
    assert payload["resolver_version"] == "2"
