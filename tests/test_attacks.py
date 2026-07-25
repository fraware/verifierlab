"""Attack strategy smoke tests."""

from __future__ import annotations

from verifierlab.attacks import create_strategy, list_strategies


def test_strategies_registered() -> None:
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
    ):
        assert required in names


def test_ordinary_and_fuzz_propose() -> None:
    from verifierlab.campaigns.episode import public_attack_feedback

    ordinary = create_strategy("ordinary", {"seed": 1})
    a = ordinary.propose()
    assert a["_cohort"] == "ordinary"
    fuzz = create_strategy("structured_fuzz", {"seed": 2})
    b = fuzz.propose()
    assert b["_cohort"] == "optimized"
    # Strategies must only see public feedback (GT stripped).
    fuzz.observe(
        public_attack_feedback(
            {"verifier_accepted": True, "gt_valid": False, "trajectory": {"steps": [b]}}
        )
    )
    assert "corpus_size" in fuzz.checkpoint()
