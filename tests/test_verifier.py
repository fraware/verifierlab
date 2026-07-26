"""Tests for @verifier decorator and VerifierSpec."""

from __future__ import annotations

from verifierlab.api import DecisionSpace, get_verifier_spec, normalize_decision, verifier
from verifierlab.api.decision import Decision, DecisionKind
from verifierlab.artifacts.canonical import digest_of


@verifier(name="toy", decision_space=DecisionSpace.BINARY, limitations=["toy"])
def toy_verifier(trajectory: dict) -> bool:  # type: ignore[type-arg]
    return bool(trajectory.get("ok", False))


def test_verifier_spec_attached() -> None:
    spec = get_verifier_spec(toy_verifier)
    assert spec.name == "toy"
    assert spec.decision_space == DecisionSpace.BINARY
    assert spec.limitations == ["toy"]
    assert spec.source.module.endswith("test_verifier")
    assert spec.source.qualname == "toy_verifier"
    assert len(spec.callable_digest) == 64
    assert spec.source.source_digest is not None


def test_verifier_callable_still_works() -> None:
    assert toy_verifier({"ok": True}) is True
    assert toy_verifier({"ok": False}) is False


def test_normalize_decision() -> None:
    d = normalize_decision(True)
    assert d.accepted is True
    assert d.status == "accept"
    d2 = normalize_decision({"accepted": False, "reason_codes": ["x"]})
    assert d2.accepted is False
    assert d2.reason_codes == ["x"]
    assert d2.status == "reject"


def test_normalize_decision_reject_string_not_accept() -> None:
    """VAL-R01 / VAL-C03: ``bool(\"reject\")`` must never become acceptance."""
    assert bool("reject") is True  # document the footgun we are closing

    bare = normalize_decision("reject")
    assert bare.kind is DecisionKind.REJECT
    assert bare.accepted is False
    assert bare.status == "reject"

    nested = normalize_decision({"decision": "reject"})
    assert nested.kind is DecisionKind.REJECT
    assert nested.accepted is False
    assert nested.status == "reject"

    false_str = normalize_decision({"decision": "false"})
    assert false_str.accepted is False
    assert false_str.status == "reject"

    # Legacy truthiness path would have accepted these.
    legacy_accept = Decision.from_raw({"decision": "reject"})
    assert legacy_accept.accepted is not True


def test_normalize_decision_unknown_fail_closed() -> None:
    bad = normalize_decision({"decision": "not-a-real-status"})
    assert bad.kind is DecisionKind.ERROR
    assert bad.accepted is None
    assert bad.status == "error"

    weird = normalize_decision(object())
    assert weird.kind is DecisionKind.ERROR
    assert weird.accepted is None


def test_normalize_decision_reject_overrides_conflicting_accepted() -> None:
    d = normalize_decision({"decision": "reject", "accepted": True})
    assert d.accepted is False
    assert d.status == "reject"


def test_normalize_decision_abstain_and_status() -> None:
    d = normalize_decision({"decision": "abstain"})
    assert d.kind is DecisionKind.ABSTAIN
    assert d.accepted is None
    assert d.status == "abstain"

    d2 = normalize_decision({"status": "indeterminate"})
    assert d2.status == "indeterminate"
    assert d2.accepted is None


def test_callable_digest_stable() -> None:
    spec = get_verifier_spec(toy_verifier)
    again = digest_of(
        {
            "module": toy_verifier.__module__,
            "qualname": toy_verifier.__qualname__,
            "source_digest": spec.source.source_digest,
        }
    )
    assert again == spec.callable_digest
