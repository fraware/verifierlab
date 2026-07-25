"""Adversarial self-tests for integrity invariants (§30.2-style).

These tests are designed to FAIL if security/integrity boundaries regress:
- public attack feedback must not carry ground truth
- label vault seals until freeze+release
- freeze records reject mutation
- workers never receive sealed labels
- FAR/FRR denominators respect missingness/abstention
- report rebuild is deterministic from immutable work-unit artifacts
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.attacks.evolutionary import EvolutionarySearch
from verifierlab.attacks.fuzzing import StructuredFuzzAttack
from verifierlab.campaigns.episode import (
    enrich_episode_with_gt,
    public_attack_feedback,
    run_episode,
)
from verifierlab.labels.freeze import FreezeRecord, assert_freeze_immutable
from verifierlab.reports.html import build_report
from verifierlab.reports.metrics import compute_metrics
from verifierlab.statistics.intervals import exact_clopper_pearson, wilson_interval
from verifierlab.targets.fake import FakeEnvironment, PlantedOracleGroundTruth, fake_refund_verifier


def test_public_attack_feedback_strips_gt() -> None:
    raw = {
        "verifier_accepted": True,
        "reward": 10.0,
        "gt_valid": False,
        "label": {"valid": False},
        "hidden_label": "secret",
        "trajectory": {"steps": []},
        "coverage": ["a"],
        "score": 1.0,
        "cost": 1.0,
        "novel": False,
        "observation": {},
        "reason_codes": ["a"],
    }
    pub = public_attack_feedback(raw)
    assert "gt_valid" not in pub
    assert "label" not in pub
    assert "hidden_label" not in pub
    assert pub["verifier_accepted"] is True
    assert pub["trajectory"] == {"steps": []}


def test_strategies_ignore_injected_gt_keys() -> None:
    """Even if a caller smuggles gt_valid, strategies must not require it."""
    fuzz = StructuredFuzzAttack()
    fuzz.initialize({"seed": 1, "seeds": [{"op": "refund", "amount": 120}]})
    before = len(fuzz._seeds)
    fuzz.observe(
        public_attack_feedback(
            {
                "verifier_accepted": True,
                "gt_valid": False,  # would be stripped
                "trajectory": {"steps": [{"op": "refund", "amount": 120}]},
                "reward": 1.0,
                "score": 1.0,
                "cost": 1.0,
                "coverage": [],
                "reason_codes": [],
                "observation": {},
                "novel": False,
            }
        )
    )
    assert len(fuzz._seeds) >= before

    evo = EvolutionarySearch()
    evo.initialize({"seed": 2, "population": 4})
    evo._last_proposed = {"op": "refund", "amount": 120}
    evo.observe(
        public_attack_feedback(
            {
                "verifier_accepted": True,
                "gt_valid": False,
                "reward": 5.0,
                "score": 5.0,
                "cost": 1.0,
                "coverage": [],
                "reason_codes": [],
                "observation": {},
                "trajectory": {"steps": []},
                "novel": False,
            }
        )
    )


def test_run_episode_does_not_evaluate_gt() -> None:
    from verifierlab.verifiers.broker import VerifierBroker
    from verifierlab.verifiers.profile import VerifierProfile

    env = FakeEnvironment(max_steps=1)
    strategy = StructuredFuzzAttack()
    broker = VerifierBroker(
        profile=VerifierProfile.for_callable(fake_refund_verifier),
        verifier=fake_refund_verifier,
        access_model="black-box",
    )
    result = run_episode(
        unit_id="u-integrity",
        seed=7,
        max_steps=1,
        env=env,
        broker=broker,
        strategy=strategy,
        strategy_config={"seed": 7, "seeds": [{"op": "refund", "amount": 120}]},
        cohort="optimized",
        access_model="black-box",
        strategy_name="structured_fuzz",
        commitment_nonce="n-integrity",
    )
    assert result["gt_valid"] is None
    assert result["exploit"] is None
    assert result["worker_safe"]["label"] is None
    assert result["label"] is None

    enriched = enrich_episode_with_gt(
        result,
        is_valid=PlantedOracleGroundTruth._is_valid,
        cohort="optimized",
        access_model="black-box",
    )
    assert enriched["gt_valid"] is False
    assert enriched["exploit"] is not None


def test_run_episode_reject_string_not_accept() -> None:
    """Episode path must route through normalize_decision (no bool(\"reject\"))."""

    def reject_verifier(_trajectory: dict) -> dict:  # type: ignore[type-arg]
        return {"decision": "reject"}

    from verifierlab.verifiers.broker import VerifierBroker
    from verifierlab.verifiers.profile import VerifierProfile

    env = FakeEnvironment(max_steps=1)
    strategy = StructuredFuzzAttack()
    broker = VerifierBroker(
        profile=VerifierProfile.for_callable(reject_verifier, name="reject_verifier"),
        verifier=reject_verifier,
        access_model="black-box",
    )
    result = run_episode(
        unit_id="u-reject-str",
        seed=3,
        max_steps=1,
        env=env,
        broker=broker,
        strategy=strategy,
        strategy_config={"seed": 3, "seeds": [{"op": "noop"}]},
        cohort="ordinary",
        access_model="black-box",
        strategy_name="structured_fuzz",
        commitment_nonce="n-reject",
    )
    assert bool("reject") is True
    assert result["verifier_accepted"] is False
    assert result["verifier_status"] == "reject"


def test_label_vault_isolation_and_freeze(tmp_path: Path) -> None:
    from verifierlab.labels.vault import fresh_ephemeral_vault

    vault = fresh_ephemeral_vault(tmp_path / "vault")
    c = vault.commit({"steps": [{"op": "refund", "amount": 120}]}, {"valid": False})
    payload = vault.worker_payload(c)
    assert payload["label"] is None
    assert "valid" not in payload

    with pytest.raises(PermissionError):
        vault.get_label(c)

    vault.freeze()
    with pytest.raises(RuntimeError, match="post-freeze"):
        vault.commit({"steps": []}, {"valid": True}, role="coordinator")

    with pytest.raises(PermissionError):
        vault.get_label(c)

    vault.release()
    assert vault.get_label(c)["valid"] is False

    audit = vault.audit_log()
    events = {e["event"] for e in audit}
    assert "commit" in events
    assert "freeze" in events
    assert "release" in events
    assert "label_denied" in events


def test_freeze_record_immutability() -> None:
    fr = FreezeRecord(
        freeze_id="f1",
        run_id="r1",
        campaign_digest="a" * 64,
        commitment_digests=["b" * 64],
        frozen_at=1.0,
    )
    good = fr.model_dump(mode="json")
    assert_freeze_immutable(fr, good)
    bad = {**good, "frozen_at": 2.0}
    with pytest.raises(ValueError, match="mutation rejected"):
        assert_freeze_immutable(fr, bad)


def test_metrics_abstention_vs_missing_vs_failed() -> None:
    rows = [
        {"cohort": "ordinary", "verifier_accepted": True, "gt_valid": True},
        {"cohort": "ordinary", "verifier_accepted": None, "gt_valid": True, "abstain": True},
        {"cohort": "ordinary", "verifier_accepted": True, "gt_valid": None},  # missing GT
        {"cohort": "optimized", "verifier_accepted": True, "gt_valid": False},
        {"cohort": "optimized", "error": "boom", "status": "failed"},
    ]
    report = compute_metrics(rows, access_model="black-box")
    ordinary = report.cohorts["ordinary"]
    assert ordinary.tp == 1
    assert ordinary.abstentions == 1
    assert ordinary.missing == 1
    assert ordinary.n == 3
    # Abstention must not enter FAR/FRR denominators.
    assert ordinary.frr == 0.0  # 0 fn / (0 fn + 1 tp)

    optimized = report.cohorts["optimized"]
    assert optimized.fp == 1
    assert optimized.failed == 1
    assert optimized.far == 1.0
    assert optimized.failed == 1
    pooled = compute_metrics(rows, access_model="black-box", pool_overall=True)
    assert pooled.overall.failed == 1


def test_clopper_pearson_known_vector() -> None:
    # Classic: 0 successes in 20 trials, 95% CI upper should be ~0.168 (rule of 3 ≈ 0.15).
    iv = exact_clopper_pearson(0, 20, alpha=0.05)
    assert iv.low == 0.0
    assert 0.15 < iv.high < 0.18
    # Symmetric: all successes.
    iv2 = exact_clopper_pearson(20, 20, alpha=0.05)
    assert iv2.high == 1.0
    assert 0.82 < iv2.low < 0.85
    # Interior point monotonicity vs Wilson.
    w = wilson_interval(2, 10, alpha=0.05)
    e = exact_clopper_pearson(2, 10, alpha=0.05)
    assert e.low <= w.estimate <= e.high
    assert e.low <= e.estimate <= e.high


def test_report_rebuild_deterministic(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    wu = run_dir / "work_units"
    wu.mkdir(parents=True)
    rows = [
        {
            "unit_id": "u0",
            "cohort": "ordinary",
            "verifier_accepted": True,
            "gt_valid": True,
        },
        {
            "unit_id": "u1",
            "cohort": "optimized",
            "verifier_accepted": True,
            "gt_valid": False,
        },
    ]
    for row in rows:
        (wu / f"{row['unit_id']}.json").write_text(
            json.dumps(row, sort_keys=True) + "\n", encoding="utf-8"
        )
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": "r-golden",
                "run_digest": "d" * 64,
                "metadata": {"access_model": "black-box"},
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    a = build_report(run_dir, require_labels_released=False)
    b = build_report(run_dir, require_labels_released=False)
    assert a == b
    assert a["exploit_count"] == 1
    assert digest_of(a["metrics"]) == digest_of(b["metrics"])


def test_delta_debug_preserves_exploit_predicate() -> None:
    from examples.refunds.verifier import grade, refund_is_valid

    from verifierlab.minimization import minimize_exploit

    traj: dict[str, Any] = {
        "steps": [
            {"op": "noop"},
            {"op": "refund", "amount": 120, "user_id": "eve"},
            {"op": "noop"},
        ]
    }
    out = minimize_exploit(traj, verifier=grade, is_valid=refund_is_valid)
    mini = out["minimized_steps"]
    assert grade({"steps": mini}) is True
    assert refund_is_valid({"steps": mini}) is False
    assert len(mini) <= len(traj["steps"])
    assert any(s.get("amount") == 120 for s in mini)


def test_budget_undercount_detected() -> None:
    from verifierlab.budgets import Budget, BudgetUndercount, OverrunPolicy, ProvenanceLedger

    ledger = ProvenanceLedger(budget=Budget(max_queries=100, overrun_policy=OverrunPolicy.RECORD))
    ledger.add_queries(3)
    ledger.add_steps(2)
    ledger.assert_consistent()
    # Simulate silent counter inflation without a matching event (undercount of events).
    ledger.queries += 5
    with pytest.raises(BudgetUndercount, match="queries"):
        ledger.assert_consistent()


def test_secret_scan_blocks_report_emit(tmp_path: Path) -> None:
    from verifierlab.security import assert_no_secrets, scan_for_secrets

    clean = {"run_id": "r1", "metrics": {"far": 0.1}}
    assert scan_for_secrets(clean) == []
    assert_no_secrets(clean)

    dirty = {"note": "token VAULT_SECRET leaked", "key": "AKIAIOSFODNN7EXAMPLE"}
    hits = scan_for_secrets(dirty)
    assert "vault_secret_marker" in hits
    assert "aws_access_key" in hits
    with pytest.raises(ValueError, match="secret patterns"):
        assert_no_secrets(dirty)

    run_dir = tmp_path / "run"
    wu = run_dir / "work_units"
    wu.mkdir(parents=True)
    (wu / "u0.json").write_text(
        json.dumps(
            {
                "unit_id": "u0",
                "cohort": "optimized",
                "verifier_accepted": True,
                "gt_valid": False,
                "note": "LABEL_PRE_FREEZE must not reach report",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (run_dir / "manifest.json").write_text(
        json.dumps({"run_id": "r-secret", "run_digest": "e" * 64, "metadata": {}}, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="secret patterns"):
        build_report(run_dir, require_labels_released=False)


def test_label_leakage_absent_from_worker_and_public_feedback() -> None:
    """§30.2: sealed labels / gt must not appear in worker-safe or public feedback."""
    from verifierlab.verifiers.broker import VerifierBroker
    from verifierlab.verifiers.profile import VerifierProfile

    env = FakeEnvironment(max_steps=1)
    strategy = StructuredFuzzAttack()
    broker = VerifierBroker(
        profile=VerifierProfile.for_callable(fake_refund_verifier),
        verifier=fake_refund_verifier,
        access_model="black-box",
    )
    result = run_episode(
        unit_id="u-leak",
        seed=1,
        max_steps=1,
        env=env,
        broker=broker,
        strategy=strategy,
        strategy_config={"seed": 1, "seeds": [{"op": "refund", "amount": 120}]},
        cohort="optimized",
        access_model="black-box",
        strategy_name="structured_fuzz",
        commitment_nonce="n-leak",
    )
    blob = json.dumps(result, sort_keys=True, default=str)
    assert 'gt_valid": null' in blob or '"gt_valid": null' in blob
    assert result["worker_safe"]["label"] is None
    assert result.get("label") is None
    # Public feedback path must strip injected GT even if smuggled.
    smuggled = public_attack_feedback(
        {
            "verifier_accepted": True,
            "gt_valid": False,
            "label": {"valid": False},
            "LABEL_PRE_FREEZE": "x",
            "reward": 1.0,
            "trajectory": {"steps": []},
            "coverage": [],
            "reason_codes": [],
            "observation": {},
            "score": 1.0,
            "cost": 1.0,
            "novel": False,
        }
    )
    assert "gt_valid" not in smuggled
    assert "label" not in smuggled
    assert "LABEL_PRE_FREEZE" not in smuggled


def test_vault_worker_credentials_isolation(tmp_path: Path) -> None:
    from verifierlab.labels.vault import fresh_ephemeral_vault

    vault = fresh_ephemeral_vault(tmp_path / "vault")
    c = vault.commit(
        {"steps": [{"op": "refund", "amount": 120}]}, {"valid": False, "secret": "nope"}
    )
    payload = vault.worker_payload(c)
    assert payload["label"] is None
    # Worker view must not serialize sealed label fields.
    assert "secret" not in json.dumps(payload)
    assert "valid" not in json.dumps(payload)
