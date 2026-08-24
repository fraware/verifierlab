"""Regression tests for optimization-strength-critical beam retention."""

from __future__ import annotations

from verifierlab.attacks.inference import BeamSearch


def _observe(strategy: BeamSearch, *, score: float, candidate: str) -> None:
    strategy._last = {"candidate": candidate}  # regression fixture: action just evaluated
    strategy.observe({"score": score, "verifier_accepted": False, "reward": 0.0})


def test_beam_pruning_retains_top_k_scores() -> None:
    """Pruning must discard the weakest candidate, never the strongest."""
    strategy = BeamSearch()
    strategy.initialize({"seed": 0, "beam_width": 2, "seeds": []})

    _observe(strategy, score=1.0, candidate="low")
    _observe(strategy, score=3.0, candidate="high")
    _observe(strategy, score=2.0, candidate="mid")

    retained = strategy.checkpoint()["beam"]
    retained_scores = sorted(score for score, _counter, _action in retained)
    retained_candidates = {action["candidate"] for _score, _counter, action in retained}

    assert retained_scores == [2.0, 3.0]
    assert retained_candidates == {"mid", "high"}


def test_beam_pruning_with_acceptance_bonus_retains_strongest() -> None:
    strategy = BeamSearch()
    strategy.initialize({"seed": 0, "beam_width": 1, "seeds": []})

    strategy._last = {"candidate": "accepted"}
    strategy.observe({"score": 0.2, "verifier_accepted": True, "reward": 0.0})
    strategy._last = {"candidate": "raw-score-only"}
    strategy.observe({"score": 0.9, "verifier_accepted": False, "reward": 0.0})

    retained = strategy.checkpoint()["beam"]
    assert len(retained) == 1
    assert retained[0][0] == 1.2
    assert retained[0][2]["candidate"] == "accepted"
