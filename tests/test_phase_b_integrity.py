"""Phase B integrity: broker, vault v2, isolation, append-only lifecycle."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.budgets import Budget, OverrunPolicy, ProvenanceLedger
from verifierlab.campaigns.engine import (
    adjudicate_campaign,
    freeze_run,
    init_workspace,
    release_labels,
    run_campaign,
)
from verifierlab.campaigns.episode import run_episode, trajectory_commitment
from verifierlab.campaigns.lifecycle import LifecycleState, lifecycle_of
from verifierlab.campaigns.worker import execute_work_unit
from verifierlab.labels.vault import fresh_ephemeral_vault
from verifierlab.reports.html import build_report
from verifierlab.targets.fake import FakeEnvironment, fake_refund_verifier
from verifierlab.verifiers.broker import VerifierBroker
from verifierlab.verifiers.capabilities import AccessDenied
from verifierlab.verifiers.profile import VerifierProfile

REPO = Path(__file__).resolve().parents[1]
FAKE_SMOKE = REPO / "campaigns" / "fake-smoke.yaml"
WORKER_PATH = REPO / "src" / "verifierlab" / "campaigns" / "worker.py"


def test_worker_source_has_no_gt_imports() -> None:
    """Attack worker module must not import PlantedOracleGroundTruth / _is_valid."""
    tree = ast.parse(WORKER_PATH.read_text(encoding="utf-8"))
    forbidden = {"PlantedOracleGroundTruth", "_is_valid", "GroundTruthProvider"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                assert alias.name not in forbidden, f"worker imports {alias.name}"
        if isinstance(node, ast.Name) and node.id in {"PlantedOracleGroundTruth"}:
            pytest.fail("worker references PlantedOracleGroundTruth")


def test_execute_work_unit_no_gt_valid_on_disk(tmp_path: Path) -> None:
    unit = {
        "unit_id": "iso-u0",
        "seed": 3,
        "unit_index": 0,
        "max_steps": 2,
        "cohort": "ordinary",
        "access_model": "black-box",
        "strategy": "ordinary",
        "strategy_config": {"actions": [{"op": "noop"}]},
        "environment_kind": "fake",
        "verifier_ref": "verifierlab.targets.fake:fake_refund_verifier",
        "commitment_nonce": "nonce-iso-u0",
        "ground_truth_ref": "should-be-ignored",
    }
    result = execute_work_unit(unit)
    assert result["gt_valid"] is None
    assert result["exploit"] is None
    assert result["label"] is None
    assert "valid" not in json.dumps(result.get("commitment"))
    # Commitment must not embed validity (traj||nonce only).
    expected = trajectory_commitment(result["trajectory"], "nonce-iso-u0")
    assert result["commitment"] == expected


def test_campaign_no_pre_freeze_gt_valid(tmp_path: Path) -> None:
    workspace = init_workspace(tmp_path / ".valab")
    result = run_campaign(FAKE_SMOKE, workspace=workspace, max_workers=1, use_processes=False)
    for path in (result.run_dir / "work_units").glob("*.json"):
        row = json.loads(path.read_text(encoding="utf-8"))
        assert row.get("gt_valid") is None
        assert row.get("exploit") is None
    assert lifecycle_of(result.run_dir) == LifecycleState.ATTACK.value
    with pytest.raises(PermissionError, match="report blocked"):
        build_report(result.run_dir)


def test_full_lifecycle_report_gate(tmp_path: Path) -> None:
    workspace = init_workspace(tmp_path / ".valab")
    result = run_campaign(FAKE_SMOKE, workspace=workspace, max_workers=1, use_processes=False)
    attack_tip = result.run_digest

    freeze = freeze_run(result.run_dir)
    assert freeze.prev_digest == attack_tip
    assert lifecycle_of(result.run_dir) == LifecycleState.FREEZE.value
    with pytest.raises(PermissionError):
        build_report(result.run_dir)

    adj = adjudicate_campaign(result.run_dir, campaign_path=FAKE_SMOKE)
    assert adj.unit_count >= 1
    assert lifecycle_of(result.run_dir) == LifecycleState.ADJUDICATION.value
    # Still no gt_valid on attack work units.
    for path in (result.run_dir / "work_units").glob("*.json"):
        row = json.loads(path.read_text(encoding="utf-8"))
        assert row.get("gt_valid") is None
    assert list((result.run_dir / "adjudications").glob("*.json"))
    with pytest.raises(PermissionError):
        build_report(result.run_dir)

    release = release_labels(result.run_dir)
    assert release.prev_digest
    assert lifecycle_of(result.run_dir) == LifecycleState.LABEL_RELEASE.value
    report = build_report(result.run_dir)
    assert "metrics" in report

    # Append-only: tip chain includes the attack tip.
    index = json.loads((result.run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert attack_tip in index["chain"]
    assert index["tip_kind"] == "adjudication_release"


def test_vault_commitment_bruteforce_fails(tmp_path: Path) -> None:
    vault = fresh_ephemeral_vault(tmp_path / "vault")
    traj = {"steps": [{"op": "refund", "amount": 120}]}
    c = vault.commit(traj, {"valid": False}, role="adjudicator")
    assert vault.offline_guess_fails(traj, commitment=c, trials=32)


def test_vault_role_denial_and_audit_chain(tmp_path: Path) -> None:
    vault = fresh_ephemeral_vault(tmp_path / "vault")
    traj = {"steps": [{"op": "noop"}]}
    with pytest.raises(PermissionError):
        vault.commit(traj, {"valid": True}, role="attacker")
    c = vault.commit(traj, {"valid": True}, role="coordinator")
    with pytest.raises(PermissionError):
        vault.get_label(c, role="attacker")
    vault.freeze(role="coordinator")
    with pytest.raises(PermissionError):
        vault.get_label(c, role="analyst")
    vault.release(role="coordinator")
    with pytest.raises(PermissionError):
        vault.get_label(c, role="attacker")
    assert vault.get_label(c, role="analyst")["valid"] is True
    assert vault.verify_audit_chain() == []

    # Tamper detection.
    lines = vault.audit_log()
    assert lines
    bad = dict(lines[0])
    bad["event"] = "tampered"
    with vault._audit_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(bad, sort_keys=True) + "\n")
    assert vault.verify_audit_chain()


def test_broker_meters_actual_queries() -> None:
    ledger = ProvenanceLedger(budget=Budget(max_queries=10, overrun_policy=OverrunPolicy.STOP))
    profile = VerifierProfile.for_callable(fake_refund_verifier)
    broker = VerifierBroker(
        profile=profile,
        verifier=fake_refund_verifier,
        access_model="black-box",
        caller="test",
        ledger=ledger,
    )
    traj = {"steps": [{"op": "refund", "amount": 50}], "seed": 1}
    broker.query(traj)
    broker.query(traj)
    assert ledger.queries == 2
    assert len(broker.events) == 2
    assert all(e.input_digest == digest_of(traj) for e in broker.events)

    with pytest.raises(AccessDenied):
        broker.profile_mount()


def test_run_episode_via_broker_no_gt() -> None:
    from verifierlab.attacks.fuzzing import StructuredFuzzAttack

    env = FakeEnvironment(max_steps=1)
    profile = VerifierProfile.for_callable(fake_refund_verifier)
    broker = VerifierBroker(
        profile=profile,
        verifier=fake_refund_verifier,
        access_model="black-box",
        caller="test",
    )
    strategy = StructuredFuzzAttack()
    result = run_episode(
        unit_id="u-broker",
        seed=7,
        max_steps=1,
        env=env,
        broker=broker,
        strategy=strategy,
        strategy_config={"seed": 7, "seeds": [{"op": "refund", "amount": 120}]},
        cohort="optimized",
        access_model="black-box",
        strategy_name="structured_fuzz",
        commitment_nonce="n-7",
    )
    assert result["gt_valid"] is None
    assert result["query_count"] == 1
    assert len(broker.events) == 1


def test_labels_encrypted_at_rest(tmp_path: Path) -> None:
    vault = fresh_ephemeral_vault(tmp_path / "vault")
    c = vault.commit({"steps": []}, {"valid": False, "secret": "hidden"}, role="adjudicator")
    raw = (vault.root / "labels" / f"{c}.json").read_text(encoding="utf-8")
    assert "hidden" not in raw
    assert "encryption" in raw
    vault.freeze()
    vault.release()
    assert vault.get_label(c)["secret"] == "hidden"
