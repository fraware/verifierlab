"""WP-09: attack portfolio, identity, transfer corpus, strength boundary."""

from __future__ import annotations

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.attacks import create_strategy, list_strategies
from verifierlab.attacks.exploit_transfer import assert_corpora_disjoint
from verifierlab.attacks.identity import AttackBudgetContract, build_attack_identity
from verifierlab.attacks.model_plugin import (
    DeterministicFixtureAttacker,
    load_model_attacker_plugin,
)
from verifierlab.attacks.portfolio import (
    ACCESS_MODELS_COMPLETE,
    PORTFOLIO_DEPTH_LIMITATIONS,
    build_default_portfolio,
    default_family_guards,
    record_candidate_eval,
)


def test_portfolio_strategies_registered() -> None:
    names = list_strategies()
    for required in (
        "ordinary",
        "random_fuzz",
        "structured_fuzz",
        "coverage_fuzz",
        "evolutionary",
        "best_of_n",
        "beam",
        "rl_tabular",
        "metamorphic_search",
        "exploit_transfer",
    ):
        assert required in names


def test_access_model_completeness_in_portfolio() -> None:
    assert "black-box" in ACCESS_MODELS_COMPLETE
    assert "transfer" in ACCESS_MODELS_COMPLETE
    assert "side-channel" in ACCESS_MODELS_COMPLETE
    assert "score_only" in ACCESS_MODELS_COMPLETE
    portfolio = build_default_portfolio(
        portfolio_id="p1",
        access_models=("black-box", "gray-box", "white-box", "adaptive"),
    )
    assert set(portfolio.access_models) <= set(ACCESS_MODELS_COMPLETE)
    assert len(PORTFOLIO_DEPTH_LIMITATIONS) >= 5
    assert portfolio.qualification_grade is False


def test_held_out_corpus_must_differ_from_discovery() -> None:
    discovery = [{"steps": [{"op": "refund", "amount": 200, "user_id": "eve"}]}]
    held = [{"steps": [{"op": "refund", "amount": 200, "user_id": "eve"}]}]
    with pytest.raises(ValueError, match="disjoint"):
        assert_corpora_disjoint(discovery, held)
    held2 = [{"steps": [{"op": "tamper", "amount": 90, "token": "forged"}]}]
    partition = assert_corpora_disjoint(discovery, held2)
    assert partition.content_digest


def test_exploit_transfer_rejects_overlap_via_config() -> None:
    discovery = [{"steps": [{"op": "refund", "amount": 1}]}]
    with pytest.raises(ValueError, match="disjoint"):
        create_strategy(
            "exploit_transfer",
            {
                "seed": 1,
                "corpus": discovery,
                "discovery_corpus": discovery,
                "corpus_role": "transfer",
            },
        )


def test_strength_calibration_never_supports_unknown_robustness() -> None:
    portfolio = build_default_portfolio(
        portfolio_id="strength",
        include_strength_calibration=True,
        planted_pack_digest=digest_of("planted-pack"),
        calibration_run_digest=digest_of("calib-run"),
    )
    assert portfolio.strength_calibration is not None
    assert portfolio.strength_calibration.supports_unknown_robustness_claim is False
    for identity in portfolio.identities:
        assert identity.supports_unknown_robustness_claim is False


def test_family_guards_cover_vulnerable_and_clean() -> None:
    guards = default_family_guards()
    families = {g.family for g in guards}
    assert "metamorphic_search" in families
    assert "exploit_transfer" in families
    for family in families:
        kinds = {g.kind for g in guards if g.family == family}
        assert kinds == {"vulnerable_fixture", "clean_always_reject"}


def test_attack_identity_and_candidate_meter() -> None:
    identity = build_attack_identity(
        strategy_name="structured_fuzz",
        strategy_version="1",
        source_digest=digest_of("src"),
        configuration={"seed": 3},
        seed=3,
        access_model="black-box",
        budget=AttackBudgetContract(max_queries=10, max_candidate_evals=20),
    )
    meter = record_candidate_eval(identity=identity, candidate_evals=4, verifier_queries=4)
    assert meter.candidate_evals == 4
    with pytest.raises(ValueError, match="exceed"):
        record_candidate_eval(identity=identity, candidate_evals=4, verifier_queries=11)


def test_model_capable_plugin_fixture() -> None:
    attacker = load_model_attacker_plugin("fixture", config={"seed": 2, "max_queries": 5})
    assert isinstance(attacker, DeterministicFixtureAttacker)
    action = attacker.propose(context={"episode": 0})
    assert action["_strategy"] == "model_fixture"
    attacker.observe({"verifier_accepted": False})
    meter = attacker.meter()
    assert meter["queries"] == 1
    assert meter["candidate_evals"] == 1
    identity = attacker.identity()
    assert identity.model_id == "fixture-model"
    assert identity.depth == "model_assisted"
    assert identity.supports_unknown_robustness_claim is False
