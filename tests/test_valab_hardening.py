"""VALAB-02…09 hardening tests (contracts, access, budget, seal, labels, repair, stats, adapters)."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from verifierlab.api.verifier import get_verifier_spec, verifier
from verifierlab.artifacts.lifecycle_records import SealedRunManifest, assert_sealed_immutable
from verifierlab.artifacts.records import (
    AbstentionBehavior,
    AccessModel,
    DecisionSpace,
    LabelTier,
    SideEffects,
    VerifierSpec,
)
from verifierlab.budgets import Budget, BudgetExceeded, OverrunPolicy, ProvenanceLedger
from verifierlab.campaigns.engine import (
    freeze_run,
    init_workspace,
    release_labels,
    run_campaign,
)
from verifierlab.campaigns.splits import materialize_split_manifest, resolve_label_tier
from verifierlab.config.campaign import (
    CampaignSpec,
    SplitSpec,
    StatsPlan,
    load_campaign_dict,
)
from verifierlab.labels.freeze import (
    FreezeRecord,
    assert_freeze_immutable,
    assert_run_sealed_immutable,
)
from verifierlab.labels.vault import fresh_ephemeral_vault
from verifierlab.repairs import run_repair_campaign
from verifierlab.reports.html import build_report
from verifierlab.statistics.plan import compile_stats_plan, validate_stats_report_schema
from verifierlab.targets.conformance import run_conformance
from verifierlab.targets.fake import fake_refund_verifier
from verifierlab.targets.trainer_adapter import TrainerAdapter, run_trainer_loop
from verifierlab.verifiers.broker import VerifierBroker
from verifierlab.verifiers.capabilities import AccessDenied, capabilities_for
from verifierlab.verifiers.profile import VerifierProfile

REPO = Path(__file__).resolve().parents[1]
FAKE_SMOKE = REPO / "campaigns" / "fake-smoke.yaml"

ALL_ACCESS_MODELS = [m.value for m in AccessModel]


# ---------------------------------------------------------------------------
# VALAB-02 — Verifier contract
# ---------------------------------------------------------------------------


def test_verifier_contract_round_trip() -> None:
    @verifier(
        name="contracted",
        decision_space=DecisionSpace.BINARY,
        input_schema={"type": "object"},
        output_schema={"type": "boolean"},
        stochastic=False,
        allowed_exceptions=["TimeoutError"],
        score_range=(0.0, 1.0),
        abstention=AbstentionBehavior.UNSUPPORTED,
        timeout_s=1.5,
        side_effects=SideEffects.NONE,
        external_resources=[],
        version="1.2.3",
        access_model=AccessModel.BLACK_BOX,
    )
    def grade(traj: dict) -> bool:
        return True

    spec = get_verifier_spec(grade)
    assert isinstance(spec, VerifierSpec)
    assert spec.contract_complete()
    assert spec.version == "1.2.3"
    assert spec.score_range == (0.0, 1.0)
    assert spec.input_schema == {"type": "object"}
    dumped = spec.model_dump(mode="json")
    again = VerifierSpec.model_validate(dumped)
    assert again.callable_digest == spec.callable_digest


def test_campaign_rejects_incomplete_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    @verifier(name="incomplete")
    def bare(traj: dict) -> bool:
        return True

    assert bare.__verifier_spec__.contract_gaps() == ["input_schema", "output_schema"]  # type: ignore[attr-defined]
    assert fake_refund_verifier.__verifier_spec__.legacy_contract()  # type: ignore[attr-defined]
    assert fake_refund_verifier.__verifier_spec__.contract_complete()  # type: ignore[attr-defined]

    # End-to-end: campaign validate must ERROR on incomplete contracts.
    mod_path = tmp_path / "incomplete_verifier_mod.py"
    mod_path.write_text(
        "from verifierlab.api.verifier import verifier\n"
        "@verifier(name='bare_incomplete')\n"
        "def grade(traj: dict) -> bool:\n"
        "    return True\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    raw = __import__("yaml").safe_load(FAKE_SMOKE.read_text(encoding="utf-8"))
    raw = json.loads(json.dumps(raw, default=str))
    raw["verifier"] = {"kind": "python", "ref": "incomplete_verifier_mod:grade"}
    from verifierlab.config.campaign import CampaignSpecError, load_campaign

    spec, diags = load_campaign_dict(raw)
    errors = [d for d in diags if d.severity.value == "error"]
    assert any(d.code == "VALAB.CAMPAIGN.VERIFIER_CONTRACT" for d in errors), diags
    assert spec is not None  # model validates; semantic ERROR blocks load_campaign
    camp = tmp_path / "bad.yaml"
    camp.write_text(__import__("yaml").safe_dump(raw), encoding="utf-8")
    with pytest.raises(CampaignSpecError):
        load_campaign(camp)


def test_legacy_planted_verifiers_validate() -> None:
    raw = json.loads(
        json.dumps(
            __import__("yaml").safe_load(FAKE_SMOKE.read_text(encoding="utf-8")),
            default=str,
        )
    )
    # Ensure YAML still validates with planted legacy_contract verifier.
    spec, diags = load_campaign_dict(raw)
    assert spec is not None
    errors = [d for d in diags if d.severity.value == "error"]
    assert not errors, errors


# ---------------------------------------------------------------------------
# VALAB-03 — Access models
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("model", ALL_ACCESS_MODELS)
def test_all_ten_access_models_have_capabilities(model: str) -> None:
    caps = capabilities_for(model)
    assert caps.access_model == model
    body = caps.as_dict()
    assert "may_retain_episode_state" in body


def test_score_only_strips_accepted() -> None:
    broker = VerifierBroker(
        profile=VerifierProfile.for_callable(fake_refund_verifier),
        verifier=fake_refund_verifier,
        access_model="score_only",
    )
    d = broker.query({"steps": [{"op": "refund", "amount": 50}]})
    assert d.accepted is None
    assert d.score is not None or d.kind.value == "score"
    with pytest.raises(AccessDenied):
        broker.read_source()


def test_label_only_strips_score() -> None:
    broker = VerifierBroker(
        profile=VerifierProfile.for_callable(fake_refund_verifier),
        verifier=fake_refund_verifier,
        access_model="label_only",
    )
    d = broker.query({"steps": [{"op": "refund", "amount": 50}]})
    assert d.accepted is not None
    assert d.score is None


def test_partial_feedback_allowlists_reasons() -> None:
    caps = capabilities_for("partial_feedback")
    assert caps.may_read_reason_codes is True
    filtered = caps.filter_reason_codes(["policy", "secret_source"])
    assert "policy" in filtered
    assert "secret_source" not in filtered


def test_stateful_episode_state() -> None:
    broker = VerifierBroker(
        profile=VerifierProfile.for_callable(fake_refund_verifier),
        verifier=fake_refund_verifier,
        access_model="stateful",
    )
    broker.retain_episode_state("seen", 1)
    assert broker.read_episode_state("seen") == 1
    with pytest.raises(AccessDenied):
        VerifierBroker(
            profile=VerifierProfile.for_callable(fake_refund_verifier),
            verifier=fake_refund_verifier,
            access_model="black-box",
        ).retain_episode_state("x", 1)


@pytest.mark.parametrize("model", ALL_ACCESS_MODELS)
def test_gate1_broker_source_denied_except_white_box(model: str) -> None:
    broker = VerifierBroker(
        profile=VerifierProfile.for_callable(fake_refund_verifier),
        verifier=fake_refund_verifier,
        access_model=model,
    )
    if model == "white-box":
        src = broker.read_source()
        assert "implementation_digest" in src
    else:
        with pytest.raises(AccessDenied):
            broker.read_source()


# ---------------------------------------------------------------------------
# VALAB-04 — Budget
# ---------------------------------------------------------------------------


def test_budget_candidates_and_compute_units() -> None:
    budget = Budget(max_candidates=2, max_compute_units=5.0, overrun_policy=OverrunPolicy.STOP)
    ledger = ProvenanceLedger(budget=budget)
    ledger.add_candidates(1)
    ledger.add_compute_units(2.5)
    assert ledger.candidates == 1
    assert ledger.compute_units == pytest.approx(2.5)
    ledger.add_candidates(1)
    with pytest.raises(BudgetExceeded):
        ledger.add_candidates(1)


def test_concurrent_thread_budget_exact_stop() -> None:
    budget = Budget(max_queries=50, overrun_policy=OverrunPolicy.STOP)
    ledger = ProvenanceLedger(budget=budget)
    errors: list[Exception] = []

    def worker() -> None:
        try:
            for _ in range(100):
                ledger.add_queries(1)
        except BudgetExceeded as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert ledger.queries == 50
    assert errors
    ledger.assert_consistent()


def test_voucher_merge_no_refund(tmp_path: Path) -> None:
    budget = Budget(max_queries=100, overrun_policy=OverrunPolicy.STOP)
    coordinator = ProvenanceLedger(budget=budget, persist_path=tmp_path / "spend.json")
    voucher = ProvenanceLedger(budget=Budget(max_queries=10, overrun_policy=OverrunPolicy.STOP))
    voucher.add_queries(3)
    voucher.add_candidates(2)
    # Simulate crash after reserve: persist voucher events, then merge without refund.
    voucher.persist_path = tmp_path / "voucher.json"
    voucher.flush()
    coordinator.merge_events(list(voucher.events), refund=False)
    assert coordinator.queries == 3
    assert coordinator.candidates == 2
    with pytest.raises(ValueError, match="never refund"):
        coordinator.merge_events([], refund=True)
    # Reload persisted spend — completed queries remain charged.
    recovered = ProvenanceLedger(
        budget=Budget(max_queries=100), persist_path=tmp_path / "voucher.json"
    )
    recovered.load_persisted()
    assert recovered.queries == 3


def test_candidate_meter_via_evaluate(tmp_path: Path) -> None:
    from verifierlab.attacks.runtime import evaluate_candidate_trajectory
    from verifierlab.targets.fake import FakeEnvironment

    env = FakeEnvironment(max_steps=2)
    env.reset(seed=1)
    ledger = ProvenanceLedger(budget=Budget(max_queries=100, max_candidates=10))
    broker = VerifierBroker(
        profile=VerifierProfile.for_callable(fake_refund_verifier),
        verifier=fake_refund_verifier,
        access_model="black-box",
        ledger=ledger,
    )
    evaluate_candidate_trajectory(env, {"op": "refund", "amount": 50}, broker, caller="test")
    assert ledger.candidates == 1
    assert ledger.queries == 1  # verifier invocation ≡ query


# ---------------------------------------------------------------------------
# VALAB-05 — Sealed run
# ---------------------------------------------------------------------------


def test_sealed_run_manifest_and_immutable(tmp_path: Path) -> None:
    workspace = init_workspace(tmp_path / ".valab")
    result = run_campaign(FAKE_SMOKE, workspace=workspace, max_workers=1, use_processes=False)
    freeze = freeze_run(result.run_dir)
    sealed_path = result.run_dir / "sealed_run.json"
    assert sealed_path.is_file()
    sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
    body = {k: v for k, v in sealed.items() if k != "content_digest"}
    manifest = SealedRunManifest.model_validate(body)
    assert manifest.freeze_digest
    assert manifest.campaign_digest
    assert_sealed_immutable(manifest, body)
    with pytest.raises(ValueError):
        assert_sealed_immutable(manifest, {**body, "run_id": "mutated"})
    assert_run_sealed_immutable(result.run_dir)
    # Mutating freeze.json content_digest check.
    freeze_path = result.run_dir / "freeze.json"
    fr = json.loads(freeze_path.read_text(encoding="utf-8"))
    fr_body = {k: v for k, v in fr.items() if k != "content_digest"}
    assert_freeze_immutable(FreezeRecord.model_validate(fr_body), fr_body)
    assert freeze.freeze_id


def test_byte_identical_report_rebuild(tmp_path: Path) -> None:
    workspace = init_workspace(tmp_path / ".valab")
    result = run_campaign(FAKE_SMOKE, workspace=workspace, max_workers=1, use_processes=False)
    freeze_run(result.run_dir)
    from verifierlab.campaigns.engine import adjudicate_campaign

    adjudicate_campaign(result.run_dir, campaign_path=FAKE_SMOKE)
    release_labels(result.run_dir)
    a = build_report(result.run_dir)
    canon_a = (result.run_dir / "report" / "report.canonical.json").read_bytes()
    b = build_report(result.run_dir)
    canon_b = (result.run_dir / "report" / "report.canonical.json").read_bytes()
    assert canon_a == canon_b
    assert a["canonical_digest"] == b["canonical_digest"]


def test_incomplete_run_resume_no_duplicate_queries(tmp_path: Path) -> None:
    """VALAB-05: killed mid-run resume must not double-charge completed queries."""
    import asyncio

    from verifierlab.artifacts.cas import ContentAddressedStore
    from verifierlab.budgets import OverrunPolicy
    from verifierlab.execution.local import LocalLauncher

    store = ContentAddressedStore(tmp_path / "store")
    run_dir = tmp_path / "run"
    budget = Budget(max_queries=100, overrun_policy=OverrunPolicy.STOP)
    launcher = LocalLauncher(
        store=store,
        run_dir=run_dir,
        budget=budget,
        max_workers=1,
        use_processes=False,
    )
    units = [
        {"unit_id": "u0", "seed": 1, "unit_index": 0, "max_steps": 2},
        {"unit_id": "u1", "seed": 2, "unit_index": 1, "max_steps": 2},
        {"unit_id": "u2", "seed": 3, "unit_index": 2, "max_steps": 2},
    ]
    first = asyncio.run(launcher.run_all(units[:2]))
    assert first["status"] == "completed"
    charged_after_partial = int(launcher.ledger.queries)
    assert charged_after_partial >= 2
    assert (run_dir / "budget_spend.json").is_file()
    assert (run_dir / "checkpoint.json").is_file()
    # No freeze → incomplete-run recovery path.
    assert not (run_dir / "freeze.json").is_file()

    launcher2 = LocalLauncher(
        store=store,
        run_dir=run_dir,
        budget=budget,
        max_workers=1,
        use_processes=False,
    )
    assert launcher2.ledger.queries == charged_after_partial
    second = asyncio.run(launcher2.run_all(units))
    assert second["status"] == "completed"
    # Completed units not re-executed: digests stable; total queries = sum of unit meters.
    unit_queries = 0
    for path in (run_dir / "work_units").glob("*.json"):
        row = json.loads(path.read_text(encoding="utf-8"))
        unit_queries += int(row.get("query_count") or 0)
    assert launcher2.ledger.queries == unit_queries
    assert launcher2.ledger.queries == charged_after_partial + int(
        json.loads((run_dir / "work_units" / "u2.json").read_text(encoding="utf-8")).get(
            "query_count"
        )
        or 0
    )


# ---------------------------------------------------------------------------
# VALAB-06 — Label tiers
# ---------------------------------------------------------------------------


def test_label_tier_private_holdout_denied(tmp_path: Path) -> None:
    vault = fresh_ephemeral_vault(tmp_path / "vault")
    traj = {"steps": [{"op": "refund", "amount": 10}]}
    c = vault.commit(
        traj,
        {"valid": True},
        role="adjudicator",
        label_tier=LabelTier.PRIVATE_HOLDOUT.value,
    )
    assert (tmp_path / "vault" / "private" / "labels" / f"{c}.json").is_file()
    vault.freeze(role="coordinator")
    vault.release(role="coordinator")
    with pytest.raises(PermissionError, match=r"private_holdout|attack"):
        vault.get_label(c, role="attacker")
    with pytest.raises(PermissionError, match=r"private_holdout"):
        vault.get_label(c, role="analyst")
    label = vault.get_label(c, role="adjudicator")
    assert label["valid"] is True
    assert label["label_tier"] == "private_holdout"


def test_split_manifest_binds_tiers() -> None:
    from verifierlab.config.campaign import (
        AttackSpec,
        BaselineSpec,
        GroundTruthSpec,
        TargetRef,
    )

    spec = CampaignSpec(
        name="tier-test",
        access_model=AccessModel.BLACK_BOX,
        budget=Budget(max_queries=10),
        environment=TargetRef(kind="fake", ref="x"),
        verifier=TargetRef(kind="python", ref="y"),
        ground_truth=GroundTruthSpec(provider="planted"),
        baseline=BaselineSpec(),
        attacks=[AttackSpec(name="a", strategy="ordinary")],
        splits=[
            SplitSpec(name="train", count=2, label_tier="development"),
            SplitSpec(name="private_holdout", count=1, label_tier="private_holdout"),
        ],
        pinned_versions={"verifierlab": "0.2.0rc1", "campaign": "t"},
    )
    manifest = materialize_split_manifest(spec, unit_ids=["u0", "u1", "u2"])
    tiers = {u["unit_id"]: u["label_tier"] for u in manifest["units"]}
    assert LabelTier.DEVELOPMENT.value in tiers.values()
    assert LabelTier.PRIVATE_HOLDOUT.value in tiers.values()
    assert resolve_label_tier("private_holdout") is LabelTier.PRIVATE_HOLDOUT


def test_report_omits_raw_private_holdout_labels(tmp_path: Path) -> None:
    """VALAB-06: reports may aggregate metrics; must not emit vault private plaintext."""
    vault = fresh_ephemeral_vault(tmp_path / "vault")
    secret_label = {"valid": True, "secret_note": "PRIVATE_HOLDOUT_PLAINTEXT_MARKER"}
    traj = {"steps": [{"op": "refund", "amount": 10}]}
    c = vault.commit(
        traj,
        secret_label,
        role="adjudicator",
        label_tier=LabelTier.PRIVATE_HOLDOUT.value,
    )
    vault.freeze(role="coordinator")
    vault.release(role="coordinator")
    private_blob = (tmp_path / "vault" / "private" / "labels" / f"{c}.json").read_text(
        encoding="utf-8"
    )
    assert "PRIVATE_HOLDOUT_PLAINTEXT_MARKER" not in private_blob  # encrypted at rest
    # Attack / analyst scrape of released report-shaped aggregates must not include marker.
    workspace = init_workspace(tmp_path / ".valab")
    result = run_campaign(FAKE_SMOKE, workspace=workspace, max_workers=1, use_processes=False)
    freeze_run(result.run_dir)
    from verifierlab.campaigns.engine import adjudicate_campaign

    adjudicate_campaign(result.run_dir, campaign_path=FAKE_SMOKE)
    release_labels(result.run_dir)
    report = build_report(result.run_dir)
    report_text = json.dumps(report, sort_keys=True)
    assert "PRIVATE_HOLDOUT_PLAINTEXT_MARKER" not in report_text
    canon = (result.run_dir / "report" / "report.canonical.json").read_text(encoding="utf-8")
    assert "PRIVATE_HOLDOUT_PLAINTEXT_MARKER" not in canon
    # Attack work units remain without plaintext labels.
    for path in (result.run_dir / "work_units").glob("*.json"):
        body = path.read_text(encoding="utf-8")
        assert "PRIVATE_HOLDOUT_PLAINTEXT_MARKER" not in body
        row = json.loads(body)
        assert row.get("gt_valid") is None


# ---------------------------------------------------------------------------
# VALAB-07 — Repair trivial reject
# ---------------------------------------------------------------------------


def test_repair_trivial_reject_fails() -> None:
    known = [
        {"steps": [{"op": "refund", "amount": 50}]},
        {"steps": [{"op": "refund", "amount": 40}]},
        {"steps": [{"op": "noop"}]},
        {"steps": [{"op": "refund", "amount": 120}]},
    ]

    def old_v(traj: dict) -> bool:
        return True

    def block_everything(traj: dict) -> bool:
        return False

    def is_valid(traj: dict) -> bool:
        for step in traj.get("steps", []):
            if step.get("op") == "refund" and int(step.get("amount", 0)) > 100:
                return False
        return True

    artifact = run_repair_campaign(
        old_verifier=old_v,
        new_verifier=block_everything,
        is_valid=is_valid,
        regression_trajectories=known,
        campaign_id="trivial-reject",
        fresh_episodes=2,
        budget_queries=2,
        trivial_reject_threshold=0.5,
    )
    assert artifact.trivial_reject_detected is True
    assert artifact.status == "fail"
    assert "trivial_reject_detected" in (artifact.metadata.get("gate_failures") or [])


def test_repair_good_pass_gates() -> None:
    known = [
        {"steps": [{"op": "refund", "amount": 120}]},
        {"steps": [{"op": "refund", "amount": 200}]},
        {"steps": [{"op": "refund", "amount": 50}]},
        {"steps": [{"op": "noop"}]},
        {"steps": [{"op": "refund", "amount": 80}]},
        {"steps": [{"op": "refund", "amount": 10}]},
    ]

    def old_v(traj: dict) -> bool:
        return True

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
        campaign_id="good-repair",
        fresh_episodes=3,
        budget_queries=3,
    )
    assert artifact.schema_version == "3"
    assert artifact.trivial_reject_detected is False
    assert artifact.status == "pass"
    assert artifact.failure_taxonomy
    assert artifact.paired_stats.get("far_delta_bootstrap")


# ---------------------------------------------------------------------------
# VALAB-08 — Statistics
# ---------------------------------------------------------------------------


def test_stats_plan_required_fields() -> None:
    rows = [
        {"unit_id": "a", "cohort": "ordinary", "verifier_accepted": True, "gt_valid": False},
        {"unit_id": "b", "cohort": "ordinary", "verifier_accepted": False, "gt_valid": False},
        {"unit_id": "c", "cohort": "optimized", "verifier_accepted": True, "gt_valid": False},
        {
            "unit_id": "d",
            "cohort": "optimized",
            "verifier_accepted": True,
            "gt_valid": False,
            "status": "budget_stopped",
            "censored": True,
        },
    ]
    plan = StatsPlan(
        methods=["wilson"],
        bootstrap_samples=50,
        stopping_rule="budget_exhausted",
        multiple_comparison_policy="bonferroni",
    )
    stats = compile_stats_plan(rows, plan=plan, pool_overall=False)
    assert validate_stats_report_schema(stats) == []
    assert stats["stopping_rule"] == "budget_exhausted"
    assert stats["multiple_comparison_policy"] == "bonferroni"
    assert stats["optimization_gap"] is not None
    assert stats["censored"]["censored_runs"] >= 1
    assert "numerator" in stats["exploit_rate"]
    assert stats["sample_size"] == 4


def test_stats_schema_fails_when_required_missing() -> None:
    """VALAB-08: missing stopping_rule / optimization_gap / censored fail schema validation."""
    gaps = validate_stats_report_schema({"sample_size": 1, "exploit_rate": {}})
    assert "stopping_rule" in gaps
    assert "multiple_comparison_policy" in gaps
    assert "optimization_gap" in gaps
    assert "censored" in gaps


# ---------------------------------------------------------------------------
# VALAB-09 — Adapter matrix / trainer
# ---------------------------------------------------------------------------


def test_trainer_adapter_broker_only() -> None:
    ledger = ProvenanceLedger(budget=Budget(max_queries=20))
    broker = VerifierBroker(
        profile=VerifierProfile.for_callable(fake_refund_verifier),
        verifier=fake_refund_verifier,
        access_model="black-box",
        ledger=ledger,
    )
    out = run_trainer_loop(broker, steps=3, seed=7)
    assert out["framework"] == "trainer"
    assert out["query_count"] == 3
    assert ledger.queries == 3
    for row in out["history"]:
        assert "gt_valid" not in row or row.get("gt_valid") is None


def test_trainer_adapter_conformance() -> None:
    broker = VerifierBroker(
        profile=VerifierProfile.for_callable(fake_refund_verifier),
        verifier=fake_refund_verifier,
        access_model="black-box",
    )
    adapter = TrainerAdapter(broker=broker)
    # Satisfy EnvAdapter-ish surface used by run_conformance.
    result = run_conformance(adapter, seed=0)  # type: ignore[arg-type]
    assert result.checks.get("config_capture")
    assert result.checks.get("hidden_label_separation")
