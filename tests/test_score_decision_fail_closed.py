"""Regression tests for score-only verifier outputs.

A numeric score is not, by itself, an accept/reject proposition. Different
verifiers use different scales and directions, so acceptance requires an
explicit decision mapping supplied by the verifier integration/profile.
"""

from __future__ import annotations

from verifierlab.api.decision import Decision, DecisionKind


def test_bare_numeric_score_is_indeterminate() -> None:
    decision = Decision.from_raw(0.99)
    assert decision.kind is DecisionKind.SCORE
    assert decision.score == 0.99
    assert decision.accepted is None
    assert decision.status == "indeterminate"


def test_mapping_with_score_only_is_indeterminate() -> None:
    decision = Decision.from_raw({"score": 0.99})
    assert decision.kind is DecisionKind.SCORE
    assert decision.score == 0.99
    assert decision.accepted is None
    assert decision.status == "indeterminate"


def test_legacy_numeric_decision_field_does_not_invent_threshold() -> None:
    decision = Decision.from_raw({"decision": 0.99, "score": 0.99})
    assert decision.kind is DecisionKind.SCORE
    assert decision.accepted is None
    assert decision.status == "indeterminate"


def test_explicit_accepted_field_remains_authoritative() -> None:
    decision = Decision.from_raw({"score": 0.2, "accepted": True})
    assert decision.kind is DecisionKind.ACCEPT
    assert decision.accepted is True
    assert decision.score == 0.2
    assert decision.status == "accept"
