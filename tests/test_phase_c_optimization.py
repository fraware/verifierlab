"""Phase C: persistent attackers, access capabilities, splits, StatsPlan (VAL-R07-R12)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from verifierlab.attacks.registry import create_strategy
from verifierlab.attacks.runtime import (
    PersistentAttacker,
    attacker_store_path,
    is_learning_strategy,
)
from verifierlab.campaigns.engine import _build_work_units, init_workspace, run_campaign
from verifierlab.campaigns.episode import run_episode
from verifierlab.campaigns.splits import assign_split_indices
from verifierlab.campaigns.worker import execute_work_unit
from verifierlab.config.campaign import CampaignSpec, SplitSpec, StatsPlan, load_campaign
from verifierlab.reports.html import build_report
from verifierlab.reports.metrics import compute_metrics
from verifierlab.statistics.plan import compile_stats_plan
from verifierlab.targets.fake import FakeEnvironment, fake_refund_verifier
from verifierlab.verifiers.broker import VerifierBroker
from verifierlab.verifiers.capabilities import AccessDenied, capabilities_for
from verifierlab.verifiers.profile import VerifierProfile

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_persistent_attacker_checkpoints_across_units(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    attacker = PersistentAttacker.open(
        run_dir,
        strategy_name="best_of_n",
        seed=7,
        config={"seed": 7, "n": 3},
    )
    env = FakeEnvironment(max_steps=2)
    profile = VerifierProfile.for_callable(fake_refund_verifier)
    broker = VerifierBroker(
        profile=profile, verifier=fake_refund_verifier, access_model="black-box"
    )
    result1 = run_episode(
        unit_id="u0",
        seed=1,
        max_steps=2,
        env=env,
        strategy=attacker.strategy,
        strategy_config={"seed": 7, "n": 3},
        cohort="optimized",
        access_model="black-box",
        strategy_name="best_of_n",
        commitment_nonce="n0",
        broker=broker,
        learning=True,
    )
    attacker.note_episode()
    cp1 = attacker.checkpoint()
    assert cp1["queries"] >= 3  # candidate-level metering
    assert result1["query_count"] >= 3

    # Second unit restores from disk.
    attacker2 = PersistentAttacker.open(
        run_dir,
        strategy_name="best_of_n",
        seed=7,
        config={"seed": 7, "n": 3},
    )
    prior_queries = int(attacker2.strategy.checkpoint()["queries"])
    assert prior_queries == cp1["queries"]

    env2 = FakeEnvironment(max_steps=2)
    broker2 = VerifierBroker(
        profile=profile, verifier=fake_refund_verifier, access_model="black-box"
    )
    run_episode(
        unit_id="u1",
        seed=2,
        max_steps=2,
        env=env2,
        strategy=attacker2.strategy,
        strategy_config={"seed": 7, "n": 3},
        cohort="optimized",
        access_model="black-box",
        strategy_name="best_of_n",
        commitment_nonce="n1",
        broker=broker2,
        learning=True,
    )
    attacker2.note_episode()
    cp2 = attacker2.checkpoint()
    assert cp2["queries"] > prior_queries
    assert (attacker_store_path(run_dir, "best_of_n", 7) / "state.json").is_file()


def test_bon_candidate_level_query_metering() -> None:
    strategy = create_strategy("best_of_n", {"seed": 1, "n": 5})
    env = FakeEnvironment(max_steps=1)
    profile = VerifierProfile.for_callable(fake_refund_verifier)
    broker = VerifierBroker(profile=profile, verifier=fake_refund_verifier)
    result = run_episode(
        unit_id="bon",
        seed=1,
        max_steps=1,
        env=env,
        strategy=strategy,
        strategy_config={"seed": 1, "n": 5},
        cohort="optimized",
        access_model="black-box",
        strategy_name="best_of_n",
        commitment_nonce="x",
        broker=broker,
    )
    # N candidates + 1 final episode query.
    assert result["query_count"] >= 5
    assert strategy.checkpoint()["queries"] >= 5


def test_beam_candidate_metering() -> None:
    strategy = create_strategy("beam", {"seed": 2, "beam_width": 3})
    env = FakeEnvironment(max_steps=1)
    profile = VerifierProfile.for_callable(fake_refund_verifier)
    broker = VerifierBroker(profile=profile, verifier=fake_refund_verifier)
    result = run_episode(
        unit_id="beam",
        seed=2,
        max_steps=1,
        env=env,
        strategy=strategy,
        strategy_config={"seed": 2, "beam_width": 3},
        cohort="optimized",
        access_model="black-box",
        strategy_name="beam",
        commitment_nonce="y",
        broker=broker,
    )
    assert result["query_count"] >= 3


def test_split_isolation_holdout_not_learning(tmp_path: Path) -> None:
    spec_path = REPO_ROOT / "campaigns" / "fake-smoke.yaml"
    spec, _ = load_campaign(spec_path)
    # Inject holdout split.
    data = spec.model_dump(mode="json")
    data["splits"] = [
        {"name": "train", "fraction": 0.5, "seed": 1},
        {"name": "holdout", "fraction": 0.5},
    ]
    data["attacks"] = [
        {
            "name": "bon",
            "strategy": "best_of_n",
            "cohort": "optimized",
            "units": 4,
            "config": {"n": 2, "seed": 99},
        }
    ]
    spec2 = CampaignSpec.model_validate(data)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    units = _build_work_units(spec2, run_dir=run_dir)
    assert (run_dir / "splits" / "manifest.json").is_file()
    holdout = [u for u in units if u["split"] == "holdout"]
    train = [u for u in units if u.get("learning")]
    assert holdout
    assert train
    for u in holdout:
        assert u["learning"] is False
    # Holdout unit ids are not in the training attacker's write path when learning=False.
    payload = dict(train[0])
    payload["environment_kind"] = "fake"
    r1 = execute_work_unit(payload)
    assert r1.get("attacker_episodes", 0) >= 1
    episodes_after_train = json.loads(
        (Path(train[0]["attacker_dir"]) / "state.json").read_text(encoding="utf-8")
    )["episodes"]
    holdout_payload = dict(holdout[0])
    holdout_payload["environment_kind"] = "fake"
    execute_work_unit(holdout_payload)
    episodes_after_holdout = json.loads(
        (Path(train[0]["attacker_dir"]) / "state.json").read_text(encoding="utf-8")
    )["episodes"]
    assert episodes_after_holdout == episodes_after_train


def test_access_capabilities_black_box_denies_profile_and_source() -> None:
    caps = capabilities_for("black-box")
    profile = VerifierProfile.for_callable(fake_refund_verifier)
    broker = VerifierBroker(
        profile=profile,
        verifier=fake_refund_verifier,
        access_model="black-box",
        capabilities=caps,
    )
    with pytest.raises(AccessDenied):
        broker.profile_mount()
    with pytest.raises(AccessDenied):
        broker.read_source()
    with pytest.raises(AccessDenied):
        caps.require("reason_codes")
    decision = broker.query({"steps": [{"op": "noop"}]})
    assert decision.reason_codes == []
    assert decision.components == {}


def test_access_capabilities_gray_allowlist() -> None:
    caps = capabilities_for("gray-box")
    assert caps.may_read_reason_codes
    assert not caps.may_mount_profile
    assert not caps.may_read_source
    filtered = caps.filter_reason_codes(["amount_limit", "secret_source", "policy"])
    assert "amount_limit" in filtered
    assert "policy" in filtered
    assert "secret_source" not in filtered
    profile = VerifierProfile.for_callable(fake_refund_verifier)
    broker = VerifierBroker(
        profile=profile,
        verifier=fake_refund_verifier,
        access_model="gray-box",
        capabilities=caps,
    )
    with pytest.raises(AccessDenied):
        broker.profile_mount()


def test_access_capabilities_white_box_source() -> None:
    caps = capabilities_for("white-box")
    profile = VerifierProfile.for_callable(fake_refund_verifier)
    broker = VerifierBroker(
        profile=profile,
        verifier=fake_refund_verifier,
        access_model="white-box",
        capabilities=caps,
    )
    mounted = broker.profile_mount()
    assert mounted.name
    src = broker.read_source()
    assert "implementation_digest" in src


def test_stats_plan_cis_no_default_overall_pooling() -> None:
    rows = [
        {
            "cohort": "ordinary",
            "verifier_accepted": True,
            "gt_valid": True,
            "access_model": "black-box",
        },
        {"cohort": "ordinary", "verifier_accepted": False, "gt_valid": False},
        {"cohort": "optimized", "verifier_accepted": True, "gt_valid": False},
        {"cohort": "optimized", "verifier_accepted": True, "gt_valid": False},
    ]
    plan = StatsPlan(methods=["wilson", "exact"], alpha=0.05)
    stats = compile_stats_plan(rows, plan=plan, access_model="black-box", pool_overall=False)
    assert stats["overall"] is None
    assert stats["pool_overall"] is False
    assert "ordinary" in stats["cohorts"]
    assert "far_ci" in stats["cohorts"]["ordinary"]
    assert "wilson" in stats["cohorts"]["ordinary"]["far_ci"]["intervals"]
    assert stats["cohorts"]["ordinary"]["denominators"]["far"] >= 0
    assert stats["optimization_gap"] is not None
    assert stats["optimization_gap"]["gap"] is not None

    # Explicit opt-in still works.
    pooled = compute_metrics(rows, access_model="black-box", pool_overall=True)
    assert pooled.overall.n == 4
    assert pooled.as_dict()["overall"]["fp"] == 2


def test_build_report_includes_stats_plan_cis(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    wu = run_dir / "work_units"
    wu.mkdir(parents=True)
    rows = [
        {
            "unit_id": "u0",
            "cohort": "ordinary",
            "verifier_accepted": True,
            "gt_valid": True,
            "access_model": "black-box",
        },
        {
            "unit_id": "u1",
            "cohort": "optimized",
            "verifier_accepted": True,
            "gt_valid": False,
            "access_model": "black-box",
        },
    ]
    for r in rows:
        (wu / f"{r['unit_id']}.json").write_text(json.dumps(r) + "\n", encoding="utf-8")
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": "r1",
                "run_digest": "abc",
                "metadata": {
                    "access_model": "black-box",
                    "stats_plan": {"methods": ["wilson"], "alpha": 0.05},
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    payload = build_report(run_dir, require_labels_released=False, pool_overall=False)
    assert payload["metrics"]["overall"] is None
    assert "far_ci" in payload["metrics"]["cohorts"]["optimized"]
    html = (run_dir / "report" / "report.html").read_text(encoding="utf-8")
    assert "Cohort pooling disabled" in html or "FAR CI" in html
    assert (run_dir / "report" / "stats.json").is_file()


def test_assign_split_indices_and_learning_flags() -> None:
    names = assign_split_indices(
        6,
        [
            SplitSpec(name="train", fraction=0.5, seed=0),
            SplitSpec(name="holdout", fraction=0.5),
        ],
        seed=0,
    )
    assert len(names) == 6
    assert "holdout" in names
    assert "train" in names


def test_learning_strategy_classification() -> None:
    assert is_learning_strategy("best_of_n")
    assert is_learning_strategy("beam")
    assert is_learning_strategy("evolutionary")
    assert is_learning_strategy("rl_tabular")
    assert not is_learning_strategy("ordinary")
    assert not is_learning_strategy("structured_fuzz")


def test_rl_qtable_persists(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    a = PersistentAttacker.open(run_dir, strategy_name="rl_tabular", seed=3, config={"seed": 3})
    a.strategy.observe(
        {
            "reward": 1.0,
            "verifier_accepted": True,
            "observation": {"step": 1, "balance": 400},
        }
    )
    a.checkpoint()
    b = PersistentAttacker.open(run_dir, strategy_name="rl_tabular", seed=3, config={"seed": 3})
    q = b.strategy.checkpoint()["trainer"]["q"]
    assert q  # non-empty after learn+restore


@pytest.mark.integration
def test_e2e_persistent_attacker_campaign(tmp_path: Path) -> None:
    workspace = init_workspace(tmp_path / ".valab")
    data = {
        "schema_version": "1",
        "name": "phase-c-bon",
        "pinned_versions": {"verifierlab": "0.2.0rc1", "campaign": "phase-c@1"},
        "access_model": "black-box",
        "seed": 5,
        "work_units": 2,
        "budget": {
            "schema_version": "1",
            "max_queries": 200,
            "max_steps": 64,
            "max_wall_time_s": 60,
            "overrun_policy": "stop",
        },
        "environment": {
            "kind": "fake",
            "ref": "verifierlab.targets.fake:FakeEnvironment",
            "config": {"max_steps": 1},
        },
        "verifier": {
            "kind": "python",
            "ref": "verifierlab.targets.fake:fake_refund_verifier",
        },
        "ground_truth": {
            "provider": "planted-oracle",
            "config": {"policy": "amount_gt_100_invalid"},
        },
        "baseline": {"strategy": "ordinary"},
        "attacks": [
            {
                "name": "bon",
                "strategy": "best_of_n",
                "cohort": "optimized",
                "units": 2,
                "config": {"n": 3, "seed": 5},
            }
        ],
        "splits": [
            {"name": "train", "count": 1, "seed": 5},
            {"name": "holdout", "count": 1},
        ],
        "stats_plan": {"methods": ["wilson"], "alpha": 0.05},
        "disclosure_class": "internal",
    }
    camp = tmp_path / "c.yaml"
    import yaml

    camp.write_text(yaml.safe_dump(data), encoding="utf-8")
    result = run_campaign(camp, workspace=workspace, max_workers=1, use_processes=False)
    assert result.manifest.status in {"completed", "completed_with_failures"}
    assert (result.run_dir / "splits" / "manifest.json").is_file()
    assert (result.run_dir / "attackers" / "best_of_n" / "5" / "state.json").is_file()
    assert (result.run_dir / "attackers" / "best_of_n" / "5" / "FROZEN").is_file()
    wu_files = list((result.run_dir / "work_units").glob("*.json"))
    assert len(wu_files) == 2
    queries = [json.loads(p.read_text(encoding="utf-8")).get("query_count", 0) for p in wu_files]
    assert max(queries) >= 3
