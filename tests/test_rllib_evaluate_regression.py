"""Regression tests for frozen RLlib adapter evaluation dispatch."""

from __future__ import annotations

from verifierlab.trainers.rllib_adapter import RLlibPPOAdapter


def test_frozen_evaluate_does_not_recurse_without_sdk() -> None:
    adapter = RLlibPPOAdapter()
    adapter._initialized = True
    adapter._frozen = True

    result = adapter.evaluate({"observation": {"x": 1}})

    assert result == {"action": 0, "mode": "evaluate", "frozen": True}
    assert adapter._frozen is True


def test_frozen_act_dispatches_to_finite_evaluation() -> None:
    adapter = RLlibPPOAdapter()
    adapter._initialized = True
    adapter._frozen = True

    result = adapter.act({"observation": {"x": 1}})

    assert result["mode"] == "evaluate"
    assert result["frozen"] is True
    assert adapter._frozen is True
