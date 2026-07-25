"""Tests for @verifier decorator and VerifierSpec."""

from __future__ import annotations

from verifierlab.api import DecisionSpace, get_verifier_spec, normalize_decision, verifier
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
    d2 = normalize_decision({"accepted": False, "reason_codes": ["x"]})
    assert d2.accepted is False
    assert d2.reason_codes == ["x"]


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
