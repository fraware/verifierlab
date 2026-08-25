"""WP-08: metamorphic evaluator, estimands, and metamorphic_search attack."""

from __future__ import annotations

from typing import Any

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.attacks.registry import create_strategy, list_strategies
from verifierlab.statistics.metamorphic import (
    InvalidMetamorphicTransformation,
    calibrate_transform_quality,
    compile_metamorphic_suite,
    ensure_builtin_transformations_registered,
    evaluate_registered_transformation,
    get_registered_transformation,
    summarize_metamorphic_estimands,
    transformation_spec_for_callable,
    user_alias_transform,
)

PROFILE = digest_of("verifier-profile-wp08")


def _traj(user: str = "eve", amount: int = 10) -> dict[str, Any]:
    return {"steps": [{"op": "refund", "user_id": user, "amount": amount, "note": "n"}]}


def test_builtin_transformation_registry_is_complete() -> None:
    registered = ensure_builtin_transformations_registered()
    assert "builtin.actor_alias.v1" in registered
    assert "builtin.cosmetic_fields.v1" in registered
    assert "builtin.amount_boundary.v1" in registered
    # Idempotent.
    again = ensure_builtin_transformations_registered()
    assert again == registered


def test_gt_invariance_checked_before_verifier_and_invalid_never_counts() -> None:
    def bad_transform(trajectory: dict[str, Any], parameters: dict[str, Any]) -> dict[str, Any]:
        out = dict(trajectory)
        # Flip amount across validity band — GT changes.
        steps = [dict(s) for s in out.get("steps") or []]
        if steps:
            steps[0]["amount"] = 999
        out["steps"] = steps
        return out

    def is_valid(traj: dict[str, Any]) -> bool:
        steps = traj.get("steps") or []
        return all(int(s.get("amount", 0)) <= 100 for s in steps)

    def always_accept(_traj: dict[str, Any]) -> bool:
        return True

    spec = transformation_spec_for_callable(
        bad_transform,
        transformation_id="fixture.bad.gt.v1",
        family="broken",
        version="1",
        assumptions=("Intentionally breaks GT for this test.",),
        parameters={},
    )
    with pytest.raises(InvalidMetamorphicTransformation) as excinfo:
        evaluate_registered_transformation(
            spec,
            bad_transform,
            _traj(),
            verifier=always_accept,
            is_valid=is_valid,
            verifier_profile_digest=PROFILE,
        )
    evidence = excinfo.value.evidence
    assert evidence.status == "invalid_transform"
    assert evidence.counterexample is not None
    assert evidence.counterexample.kind == "ground_truth_invariance_violation"
    # Verifier was never consulted for the failure classification.
    assert evidence.verifier_before is None
    assert evidence.verifier_after is None


def test_abstention_preserved_as_indeterminate() -> None:
    ensure_builtin_transformations_registered()
    spec, transform = get_registered_transformation("builtin.actor_alias.v1")

    def score_only(_traj: dict[str, Any]) -> dict[str, Any]:
        return {"accepted": None, "score": 0.42}

    evidence = evaluate_registered_transformation(
        spec,
        transform,
        _traj(),
        verifier=score_only,
        is_valid=lambda _t: True,
        verifier_profile_digest=PROFILE,
        fail_on_invalid_transform=False,
    )
    assert evidence.status == "indeterminate"
    assert evidence.verifier_invariant is None
    assert evidence.counterexample is not None
    assert evidence.counterexample.kind == "verifier_decision_indeterminate"


def test_invalid_transform_excluded_from_preregistered_estimands() -> None:
    def flip_gt(trajectory: dict[str, Any], _parameters: dict[str, Any]) -> dict[str, Any]:
        out = dict(trajectory)
        steps = [dict(s) for s in out.get("steps") or []]
        if steps:
            steps[0]["amount"] = 500
        out["steps"] = steps
        return out

    def is_valid(traj: dict[str, Any]) -> bool:
        return all(int(s.get("amount", 0)) <= 100 for s in (traj.get("steps") or []))

    def accept(traj: dict[str, Any]) -> bool:
        # Accepts when amount > 50.
        steps = traj.get("steps") or []
        return bool(steps) and int(steps[0].get("amount", 0)) > 50

    good_spec = transformation_spec_for_callable(
        user_alias_transform,
        transformation_id="fixture.estimand.alias",
        family="actor_alias",
        version="1",
        assumptions=("Aliases preserve authz.",),
        parameters={"user_map": {"eve": "malory", "malory": "eve"}},
    )
    bad_spec = transformation_spec_for_callable(
        flip_gt,
        transformation_id="fixture.estimand.bad",
        family="broken",
        version="1",
        assumptions=("Breaks GT.",),
        parameters={},
    )
    # Build suite under the good transform identity but include an invalid case
    # produced under fail_on_invalid_transform=False with a different transform —
    # instead evaluate same good transform on pairs and inject invalid via bad eval.
    good_case = evaluate_registered_transformation(
        good_spec,
        user_alias_transform,
        _traj(amount=80),
        verifier=accept,
        is_valid=is_valid,
        verifier_profile_digest=PROFILE,
        source_unit_digest=digest_of("unit-good"),
    )
    invalid_case = evaluate_registered_transformation(
        bad_spec,
        flip_gt,
        _traj(amount=80),
        verifier=accept,
        is_valid=is_valid,
        verifier_profile_digest=PROFILE,
        source_unit_digest=digest_of("unit-bad"),
        fail_on_invalid_transform=False,
    )
    # Suite requires single transform — calibrate on mixed status via two suites.
    suite_good = compile_metamorphic_suite(
        good_spec,
        verifier_profile_digest=PROFILE,
        cases=[good_case],
    )
    suite_bad = compile_metamorphic_suite(
        bad_spec,
        verifier_profile_digest=PROFILE,
        cases=[invalid_case],
    )
    violation, indeterminate = summarize_metamorphic_estimands(suite_good)
    assert violation.excluded_invalid_transforms == 0
    assert violation.denominator == 1
    calib_bad = calibrate_transform_quality(
        suite_bad, maximum_invalid_rate_for_verifier_inference=0.05
    )
    assert calib_bad.supports_verifier_inference is False
    assert calib_bad.invalid_transform_rate == 1.0
    assert suite_bad.invalid_transform_count == 1
    # High invalid-transform suite cannot support verifier conclusions.
    assert any("invalid_transform_rate" in r for r in calib_bad.reasons)
    assert indeterminate.metric == "metamorphic_indeterminate"


def test_metamorphic_search_strategy_registered_and_indeterminate_safe() -> None:
    assert "metamorphic_search" in list_strategies()
    strategy = create_strategy("metamorphic_search", {"seed": 7})
    action = strategy.propose()
    assert action["_strategy"] == "metamorphic_search"
    assert "_transform_family" in action
    strategy.observe({"accepted": None, "score": 0.1})
    strategy.observe({"verifier_accepted": True, "trajectory": {"steps": [action]}})
    ckpt = strategy.checkpoint()
    assert ckpt["strategy"] == "metamorphic_search"
    assert ckpt["queries"] >= 1


def test_typed_counterexample_for_verifier_violation() -> None:
    def flip_accept(traj: dict[str, Any]) -> bool:
        # Accept only for user eve — alias remapping flips decision.
        steps = traj.get("steps") or []
        return bool(steps) and steps[0].get("user_id") == "eve"

    spec = transformation_spec_for_callable(
        user_alias_transform,
        transformation_id="fixture.cex.alias",
        family="actor_alias",
        version="1",
        assumptions=("Aliases preserve authz for GT; verifier may still flip.",),
        parameters={"user_map": {"eve": "malory", "malory": "eve"}},
    )
    evidence = evaluate_registered_transformation(
        spec,
        user_alias_transform,
        _traj(user="eve"),
        verifier=flip_accept,
        is_valid=lambda _t: True,
        verifier_profile_digest=PROFILE,
    )
    assert evidence.status == "verifier_violation"
    assert evidence.counterexample is not None
    assert evidence.counterexample.kind == "verifier_invariance_violation"
    assert evidence.counterexample.content_digest
