import pytest

from verifierlab.campaigns.engine import _single_verifier_profile_digest

A = "a" * 64
B = "b" * 64


def test_profile_binding_accepts_single_digest_across_rows() -> None:
    assert (
        _single_verifier_profile_digest(
            [
                {"verifier_profile_digest": A},
                {"verifier_profile_digest": A, "error": "budget stopped"},
            ]
        )
        == A
    )


def test_profile_binding_allows_unattributable_infrastructure_error() -> None:
    assert (
        _single_verifier_profile_digest(
            [
                {"error": "worker failed before verifier construction"},
                {"verifier_profile_digest": A},
            ]
        )
        == A
    )


def test_profile_binding_rejects_completed_row_without_digest() -> None:
    with pytest.raises(RuntimeError, match="completed work unit missing verifier profile digest"):
        _single_verifier_profile_digest([{"status": "completed"}])


def test_profile_binding_rejects_no_attributable_profile() -> None:
    with pytest.raises(RuntimeError, match="no verifier profile digest"):
        _single_verifier_profile_digest([{"error": "worker failed"}])


def test_profile_binding_rejects_multiple_profiles() -> None:
    with pytest.raises(RuntimeError, match="multiple verifier profile digests"):
        _single_verifier_profile_digest(
            [
                {"verifier_profile_digest": A},
                {"verifier_profile_digest": B},
            ]
        )


def test_profile_binding_rejects_malformed_digest() -> None:
    with pytest.raises(RuntimeError, match="malformed verifier profile digest"):
        _single_verifier_profile_digest([{"verifier_profile_digest": "not-a-digest"}])
