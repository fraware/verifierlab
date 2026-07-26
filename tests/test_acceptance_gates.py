"""Executable RC acceptance gates (§11) for VerifierLab 0.2.0rc1.

Each gate is a named test class. Failures here are ship blockers for claiming
scientific RC readiness — not cosmetic regressions.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from verifierlab.api.verifier import normalize_decision
from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import AccessModel
from verifierlab.attacks.registry import create_strategy
from verifierlab.budgets import Budget, ProvenanceLedger
from verifierlab.campaigns.engine import (
    adjudicate_campaign,
    freeze_run,
    init_workspace,
    release_labels,
    run_campaign,
)
from verifierlab.campaigns.episode import public_attack_feedback
from verifierlab.campaigns.lifecycle import LifecycleState, lifecycle_of
from verifierlab.campaigns.worker import execute_work_unit
from verifierlab.config.campaign import StatsPlan
from verifierlab.labels.vault import LabelVault, fresh_ephemeral_vault
from verifierlab.repairs import run_repair_campaign
from verifierlab.reports.html import build_report
from verifierlab.statistics.plan import compile_stats_plan
from verifierlab.targets.fake import FakeEnvironment, PlantedOracleGroundTruth, fake_refund_verifier
from verifierlab.verifiers.broker import VerifierBroker
from verifierlab.verifiers.capabilities import AccessDenied, capabilities_for
from verifierlab.verifiers.profile import VerifierProfile

ALL_ACCESS_MODELS = [m.value for m in AccessModel]

REPO = Path(__file__).resolve().parents[1]
FAKE_SMOKE = REPO / "campaigns" / "fake-smoke.yaml"
REFUND_CI = REPO / "campaigns" / "refund-ci-smoke.yaml"
WORKER_PATH = REPO / "src" / "verifierlab" / "campaigns" / "worker.py"
REPRO_SCRIPT = REPO / "scripts" / "repro_bundle_check.py"


# ---------------------------------------------------------------------------
# Gate 1 — Isolation
# ---------------------------------------------------------------------------


class TestGate1Isolation:
    def test_worker_ast_has_no_gt_symbols(self) -> None:
        tree = ast.parse(WORKER_PATH.read_text(encoding="utf-8"))
        forbidden = {"PlantedOracleGroundTruth", "GroundTruthProvider"}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    assert alias.name not in forbidden
            if isinstance(node, ast.Name) and node.id in forbidden:
                pytest.fail(f"worker references {node.id}")

    def test_worker_refuses_gt_like_refs(self) -> None:
        with pytest.raises(PermissionError, match="GT-like"):
            execute_work_unit(
                {
                    "unit_id": "gt-reject",
                    "seed": 1,
                    "max_steps": 1,
                    "environment_kind": "python",
                    "environment_ref": "verifierlab.targets.fake:PlantedOracleGroundTruth",
                    "verifier_ref": "verifierlab.targets.fake:fake_refund_verifier",
                    "strategy": "ordinary",
                    "strategy_config": {"actions": [{"op": "noop"}]},
                    "commitment_nonce": "n0",
                }
            )

    def test_attack_artifacts_have_no_gt_valid(self, tmp_path: Path) -> None:
        workspace = init_workspace(tmp_path / ".valab")
        result = run_campaign(FAKE_SMOKE, workspace=workspace, max_workers=1, use_processes=False)
        for path in (result.run_dir / "work_units").glob("*.json"):
            row = json.loads(path.read_text(encoding="utf-8"))
            assert row.get("gt_valid") is None
            assert row.get("label") is None

    def test_vault_encrypted_salted_bruteforce_fails(self, tmp_path: Path) -> None:
        vault = fresh_ephemeral_vault(tmp_path / "vault")
        traj = {"steps": [{"op": "refund", "amount": 120}]}
        c = vault.commit(traj, {"valid": False}, role="adjudicator", nonce="n1")
        for guess in (True, False):
            forged = digest_of({"schema_version": "1", "trajectory": traj, "valid": guess})
            assert forged != c
        with pytest.raises(PermissionError):
            vault.get_label(c, role="analyst")

    def test_label_release_only_after_freeze(self, tmp_path: Path) -> None:
        workspace = init_workspace(tmp_path / ".valab")
        result = run_campaign(FAKE_SMOKE, workspace=workspace, max_workers=1, use_processes=False)
        vault = LabelVault.open(result.run_dir / "vault", workspace=workspace)
        with pytest.raises(RuntimeError):
            vault.release(role="coordinator")
        freeze_run(result.run_dir)
        adjudicate_campaign(result.run_dir, campaign_path=FAKE_SMOKE)
        release_labels(result.run_dir)
        assert lifecycle_of(result.run_dir) == LifecycleState.LABEL_RELEASE.value

    def test_black_box_cannot_read_source(self) -> None:
        broker = VerifierBroker(
            profile=VerifierProfile.for_callable(fake_refund_verifier),
            verifier=fake_refund_verifier,
            access_model="black-box",
            capabilities=capabilities_for("black-box"),
        )
        with pytest.raises(AccessDenied):
            broker.read_source()

    @pytest.mark.parametrize("model", ALL_ACCESS_MODELS)
    def test_gate1_broker_across_all_access_models(self, model: str) -> None:
        """VALAB-03: Gate 1 covers all ten access models (source + channel strip)."""
        assert len(ALL_ACCESS_MODELS) == 10
        caps = capabilities_for(model)
        broker = VerifierBroker(
            profile=VerifierProfile.for_callable(fake_refund_verifier),
            verifier=fake_refund_verifier,
            access_model=model,
            capabilities=caps,
        )
        if model == AccessModel.WHITE_BOX.value:
            src = broker.read_source()
            assert "implementation_digest" in src
        else:
            with pytest.raises(AccessDenied):
                broker.read_source()
        decision = broker.query({"steps": [{"op": "refund", "amount": 50}]})
        if model == AccessModel.SCORE_ONLY.value:
            assert decision.accepted is None
            assert decision.score is not None or decision.kind.value == "score"
        elif model == AccessModel.LABEL_ONLY.value:
            assert decision.accepted is not None
            assert decision.score is None
        if model == AccessModel.STATEFUL.value:
            broker.retain_episode_state("k", 1)
            assert broker.read_episode_state("k") == 1
        else:
            with pytest.raises(AccessDenied):
                broker.retain_episode_state("k", 1)

    def test_observe_strips_gt(self) -> None:
        fb = public_attack_feedback({"verifier_accepted": True, "gt_valid": False, "reward": 1.0})
        assert "gt_valid" not in fb
        assert fb["verifier_accepted"] is True

    def test_planted_oracle_v2_not_boolean_guessable(self) -> None:
        traj = {"steps": [{"op": "refund", "amount": 120}]}
        c = PlantedOracleGroundTruth().commit(traj, nonce="fixed")
        assert c != digest_of({"schema_version": "1", "trajectory": traj, "valid": True})
        assert c != digest_of({"schema_version": "1", "trajectory": traj, "valid": False})


# ---------------------------------------------------------------------------
# Gate 2 — Optimization
# ---------------------------------------------------------------------------


class TestGate2Optimization:
    def test_bon_candidate_queries_via_broker(self) -> None:
        strategy = create_strategy("best_of_n", {"seed": 1, "n": 4})
        env = FakeEnvironment(max_steps=2)
        env.reset(seed=1)
        ledger = ProvenanceLedger(budget=Budget(max_queries=100))
        broker = VerifierBroker(
            profile=VerifierProfile.for_callable(fake_refund_verifier),
            verifier=fake_refund_verifier,
            access_model="black-box",
            ledger=ledger,
        )
        strategy.bind_runtime(broker=broker, env=env, learning=True)
        strategy.propose()
        assert strategy.checkpoint()["queries"] == 4
        assert ledger.queries == 4
        assert len(broker.events) == 4

    def test_beam_candidate_queries_via_broker(self) -> None:
        strategy = create_strategy("beam", {"seed": 2, "beam_width": 3})
        env = FakeEnvironment(max_steps=2)
        env.reset(seed=2)
        broker = VerifierBroker(
            profile=VerifierProfile.for_callable(fake_refund_verifier),
            verifier=fake_refund_verifier,
            access_model="black-box",
        )
        strategy.bind_runtime(broker=broker, env=env, learning=True)
        strategy.propose()
        assert strategy.checkpoint()["queries"] == 3
        assert len(broker.events) == 3

    def test_rl_probes_broker_by_default(self) -> None:
        strategy = create_strategy("rl_tabular", {"seed": 5, "epsilon": 1.0})
        env = FakeEnvironment(max_steps=2)
        broker = VerifierBroker(
            profile=VerifierProfile.for_callable(fake_refund_verifier),
            verifier=fake_refund_verifier,
            access_model="black-box",
        )
        strategy.bind_runtime(broker=broker, env=env, learning=True)
        strategy.propose()
        assert strategy.checkpoint()["probe_broker"] is True
        assert strategy.checkpoint()["queries"] >= 1
        assert len(broker.events) >= 1

    def test_brokerless_does_not_invent_query_counts(self) -> None:
        strategy = create_strategy("best_of_n", {"seed": 3, "n": 5})
        strategy.propose()
        assert strategy.checkpoint()["queries"] == 0

    def test_worker_budget_voucher_meters(self) -> None:
        result = execute_work_unit(
            {
                "unit_id": "voucher-u0",
                "seed": 9,
                "max_steps": 2,
                "cohort": "optimized",
                "access_model": "black-box",
                "strategy": "best_of_n",
                "strategy_config": {"seed": 9, "n": 3},
                "environment_kind": "fake",
                "commitment_nonce": "vn0",
                "query_budget_remaining": 50,
                "budget_overrun_policy": "stop",
                "learning": True,
            }
        )
        assert result.get("budget_metered") is True
        assert result["query_count"] >= 3
        assert result["budget_voucher_queries"] == result["query_count"]
        assert len(result["verifier_invocations"]) == result["query_count"]

    def test_worker_budget_voucher_stops(self) -> None:
        result = execute_work_unit(
            {
                "unit_id": "voucher-stop",
                "seed": 11,
                "max_steps": 2,
                "cohort": "optimized",
                "access_model": "black-box",
                "strategy": "best_of_n",
                "strategy_config": {"seed": 11, "n": 8},
                "environment_kind": "fake",
                "commitment_nonce": "vs0",
                "query_budget_remaining": 2,
                "budget_overrun_policy": "stop",
                "learning": True,
            }
        )
        assert result.get("budget_stopped") is True
        assert result["query_count"] <= 2

    def test_persistent_attacker_checkpoint(self, tmp_path: Path) -> None:
        from verifierlab.attacks.runtime import PersistentAttacker
        from verifierlab.campaigns.episode import run_episode

        run_dir = tmp_path / "run"
        run_dir.mkdir()
        attacker = PersistentAttacker.open(
            run_dir, strategy_name="best_of_n", seed=7, config={"seed": 7, "n": 2}
        )
        env = FakeEnvironment(max_steps=2)
        broker = VerifierBroker(
            profile=VerifierProfile.for_callable(fake_refund_verifier),
            verifier=fake_refund_verifier,
            access_model="black-box",
        )
        run_episode(
            unit_id="u0",
            seed=1,
            max_steps=2,
            env=env,
            strategy=attacker.strategy,
            strategy_config={"seed": 7, "n": 2},
            cohort="optimized",
            access_model="black-box",
            strategy_name="best_of_n",
            commitment_nonce="n0",
            broker=broker,
            learning=True,
        )
        attacker.note_episode()
        cp = attacker.checkpoint()
        assert cp["queries"] >= 2
        assert (run_dir / "attackers" / "best_of_n" / "7" / "state.json").is_file()


# ---------------------------------------------------------------------------
# Gate 3 — Measurement
# ---------------------------------------------------------------------------


class TestGate3Measurement:
    def test_typed_reject_string_fail_closed(self) -> None:
        d = normalize_decision("reject")
        assert d.accepted is False
        assert d.status == "reject"
        # Truthiness bug must never count as accept.
        assert bool("reject") is True
        assert normalize_decision("reject").accepted is not True

    def test_stats_plan_cis_and_no_pooling(self) -> None:
        rows = [
            {
                "unit_id": "a",
                "cohort": "ordinary",
                "verifier_accepted": True,
                "gt_valid": False,
            },
            {
                "unit_id": "b",
                "cohort": "ordinary",
                "verifier_accepted": False,
                "gt_valid": False,
            },
            {
                "unit_id": "c",
                "cohort": "optimized",
                "verifier_accepted": True,
                "gt_valid": False,
            },
            {
                "unit_id": "d",
                "cohort": "optimized",
                "verifier_accepted": True,
                "gt_valid": False,
            },
        ]
        plan = StatsPlan(methods=["wilson", "exact"], bootstrap_samples=200, alpha=0.05)
        stats = compile_stats_plan(rows, plan=plan, pool_overall=False)
        assert stats["overall"] is None
        assert "ordinary" in stats["cohorts"]
        assert "optimized" in stats["cohorts"]
        ordinary = stats["cohorts"]["ordinary"]
        assert "far_ci" in ordinary
        assert "wilson" in ordinary["far_ci"]["intervals"]
        assert "missingness_detail" in ordinary
        gap = stats["optimization_gap"]
        assert gap is not None
        assert gap["gap"] is not None
        assert gap["gap_ci"] is not None
        assert gap["gap_ci"]["method"] == "unpaired_bootstrap_far_gap"

    def test_report_blocked_until_release(self, tmp_path: Path) -> None:
        workspace = init_workspace(tmp_path / ".valab")
        result = run_campaign(FAKE_SMOKE, workspace=workspace, max_workers=1, use_processes=False)
        with pytest.raises(PermissionError, match="report blocked"):
            build_report(result.run_dir)
        freeze_run(result.run_dir)
        adjudicate_campaign(result.run_dir, campaign_path=FAKE_SMOKE)
        release_labels(result.run_dir)
        report = build_report(result.run_dir)
        assert report["metadata"]["assurance_grade"] == "post_release"

    def test_ungated_report_stamped_non_assurance(self, tmp_path: Path) -> None:
        workspace = init_workspace(tmp_path / ".valab")
        result = run_campaign(FAKE_SMOKE, workspace=workspace, max_workers=1, use_processes=False)
        report = build_report(result.run_dir, require_labels_released=False)
        assert report["metadata"]["assurance_grade"] == "research_ungated"
        assert "NON-ASSURANCE" in report.get("assurance_disclaimer", "")

    def test_adjudication_seals_dimensions(self, tmp_path: Path) -> None:
        workspace = init_workspace(tmp_path / ".valab")
        result = run_campaign(FAKE_SMOKE, workspace=workspace, max_workers=1, use_processes=False)
        freeze_run(result.run_dir)
        adjudicate_campaign(result.run_dir, campaign_path=FAKE_SMOKE)
        sides = list((result.run_dir / "adjudications").glob("*.json"))
        assert sides
        body = json.loads(sides[0].read_text(encoding="utf-8"))
        assert "dimensions" in body
        assert body["dimensions"]["outcome"] in {"pass", "fail"}


# ---------------------------------------------------------------------------
# Gate 4 — Repair
# ---------------------------------------------------------------------------


class TestGate4Repair:
    def test_repair_artifact_has_regression_fresh_holdout(self) -> None:
        known = [
            {"steps": [{"op": "refund", "amount": 120}]},
            {"steps": [{"op": "refund", "amount": 200}]},
            {"steps": [{"op": "refund", "amount": 50}]},
            {"steps": [{"op": "noop"}]},
            {"steps": [{"op": "refund", "amount": 80}]},
            {"steps": [{"op": "refund", "amount": 10}]},
        ]

        def old_v(traj: dict) -> bool:
            return True  # always accept → exploits on invalids

        def new_v(traj: dict) -> bool:
            for step in traj.get("steps", []):
                if step.get("op") == "refund" and int(step.get("amount", 0)) > 100:
                    return False
            return True

        def is_valid(traj: dict) -> bool:
            for step in traj.get("steps", []):
                if step.get("op") == "refund" and int(step.get("amount", 0)) > 100:
                    return False
            return True

        artifact = run_repair_campaign(
            old_verifier=old_v,
            new_verifier=new_v,
            is_valid=is_valid,
            regression_trajectories=known,
            campaign_id="gate4-repair",
            fresh_episodes=3,
            budget_queries=3,
        )
        assert artifact.schema_version == "3"
        assert artifact.regression
        assert artifact.fresh_attack
        assert artifact.holdout is not None
        assert artifact.mandatory_fresh_attacker is True
        assert artifact.old_profile and artifact.new_profile
        assert artifact.status == "pass"
        assert artifact.trivial_reject_detected is False

    def test_trivial_reject_repair_fails(self) -> None:
        known = [
            {"steps": [{"op": "refund", "amount": 50}]},
            {"steps": [{"op": "refund", "amount": 40}]},
            {"steps": [{"op": "noop"}]},
            {"steps": [{"op": "refund", "amount": 30}]},
        ]

        def old_v(traj: dict) -> bool:
            return True

        def reject_all(traj: dict) -> bool:
            return False

        def is_valid(traj: dict) -> bool:
            return True

        artifact = run_repair_campaign(
            old_verifier=old_v,
            new_verifier=reject_all,
            is_valid=is_valid,
            regression_trajectories=known,
            campaign_id="gate4-trivial",
            fresh_episodes=2,
            budget_queries=2,
        )
        assert artifact.trivial_reject_detected is True
        assert artifact.status == "fail"


# ---------------------------------------------------------------------------
# Gate 5 — Reproduction
# ---------------------------------------------------------------------------


class TestGate5Reproduction:
    @pytest.mark.integration
    def test_repro_bundle_script_exists_and_runs(self, tmp_path: Path) -> None:
        assert REPRO_SCRIPT.is_file()
        proc = subprocess.run(
            [sys.executable, str(REPRO_SCRIPT), str(FAKE_SMOKE)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
        assert "OK:" in proc.stdout or "match" in proc.stdout.lower()


# ---------------------------------------------------------------------------
# Gate 6 — Developer ten-minute tutorial lifecycle
# ---------------------------------------------------------------------------


class TestGate6Developer:
    @pytest.mark.integration
    def test_ten_minute_lifecycle(self, tmp_path: Path) -> None:
        """run → freeze → adjudicate → release → report."""
        campaign = REFUND_CI if REFUND_CI.is_file() else FAKE_SMOKE
        workspace = init_workspace(tmp_path / ".valab")
        result = run_campaign(campaign, workspace=workspace, max_workers=2, use_processes=False)
        assert result.manifest.status in {"completed", "cancelled"}
        assert lifecycle_of(result.run_dir) == LifecycleState.ATTACK.value

        freeze_run(result.run_dir)
        assert lifecycle_of(result.run_dir) == LifecycleState.FREEZE.value

        adjudicate_campaign(result.run_dir, campaign_path=campaign)
        assert lifecycle_of(result.run_dir) == LifecycleState.ADJUDICATION.value

        release_labels(result.run_dir)
        assert lifecycle_of(result.run_dir) == LifecycleState.LABEL_RELEASE.value

        report = build_report(result.run_dir)
        assert "metrics" in report
        assert report["metadata"]["assurance_grade"] == "post_release"
