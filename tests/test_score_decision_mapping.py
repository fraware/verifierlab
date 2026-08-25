"""Tests for explicit, content-addressed score-to-decision semantics."""

from __future__ import annotations

from verifierlab.api.decision import DecisionKind
from verifierlab.artifacts.records import AccessModel
from verifierlab.verifiers.broker import VerifierBroker
from verifierlab.verifiers.profile import ScoreDecisionMapping, VerifierProfile


def _profile(*, threshold: float | None) -> VerifierProfile:
    mapping = (
        None if threshold is None else ScoreDecisionMapping(operator="ge", threshold=threshold)
    )
    return VerifierProfile(
        name="score-verifier",
        implementation_digest="sha256:impl",
        config_digest="sha256:config",
        decision_mapping=mapping,
    )


def test_profile_mapping_accepts_and_rejects_score() -> None:
    profile = _profile(threshold=0.7)
    broker = VerifierBroker(
        profile=profile,
        verifier=lambda _trajectory: 0.8,
        access_model=AccessModel.BLACK_BOX.value,
    )
    accepted = broker.query({"steps": []})
    assert accepted.kind is DecisionKind.ACCEPT
    assert accepted.accepted is True

    broker.verifier = lambda _trajectory: 0.6
    rejected = broker.query({"steps": []})
    assert rejected.kind is DecisionKind.REJECT
    assert rejected.accepted is False


def test_unmapped_score_remains_indeterminate() -> None:
    broker = VerifierBroker(
        profile=_profile(threshold=None),
        verifier=lambda _trajectory: 0.99,
        access_model=AccessModel.BLACK_BOX.value,
    )
    decision = broker.query({"steps": []})
    assert decision.kind is DecisionKind.SCORE
    assert decision.accepted is None
    assert decision.status == "indeterminate"


def test_explicit_decision_is_not_overridden_by_score_mapping() -> None:
    broker = VerifierBroker(
        profile=_profile(threshold=0.1),
        verifier=lambda _trajectory: {"status": "reject", "score": 0.99},
        access_model=AccessModel.BLACK_BOX.value,
    )
    decision = broker.query({"steps": []})
    assert decision.kind is DecisionKind.REJECT
    assert decision.accepted is False


def test_mapping_changes_profile_digest() -> None:
    lower = _profile(threshold=0.5)
    higher = _profile(threshold=0.7)
    assert lower.content_digest() != higher.content_digest()


def test_mapping_direction_is_explicit() -> None:
    mapping = ScoreDecisionMapping(operator="le", threshold=0.2, scale="risk")
    assert mapping.accepts(0.1) is True
    assert mapping.accepts(0.3) is False
