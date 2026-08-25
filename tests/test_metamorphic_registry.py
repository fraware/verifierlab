"""Registered metamorphic transformation and evidence tests."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from verifierlab.artifacts.canonical import canonical_dumps, digest_of
from verifierlab.statistics.metamorphic import (
    InvalidMetamorphicTransformation,
    TransformationSpec,
    compile_metamorphic_suite,
    evaluate_registered_transformation,
    get_registered_transformation,
    list_registered_transformations,
    register_transformation,
    transformation_spec_for_callable,
    user_alias_transform,
)

PROFILE = digest_of("verifier-profile")


def _trajectory(user: str = "eve") -> dict[str, Any]:
    return {
        "steps": [
            {
                "op": "refund",
                "user_id": user,
                "amount": 10,
                "note": "fixture",
            }
        ]
    }


def _valid(_trajectory: dict[str, Any]) -> bool:
    return True


def _alias_spec(*, transformation_id: str = "fixture.alias.v1") -> TransformationSpec:
    return transformation_spec_for_callable(
        user_alias_transform,
        transformation_id=transformation_id,
        family="actor_alias",
        version="1",
        assumptions=(
            "Configured actor aliases preserve authorization semantics for this fixture.",
        ),
        parameters={"user_map": {"eve": "malory", "malory": "eve"}},
    )


def test_spec_binds_implementation_parameters_and_assumptions() -> None:
    base = _alias_spec(transformation_id="fixture.binding.base")
    changed_parameters = transformation_spec_for_callable(
        user_alias_transform,
        transformation_id="fixture.binding.base",
        family="actor_alias",
        version="1",
        assumptions=base.assumptions,
        parameters={"user_map": {"eve": "other"}},
    )
    changed_assumptions = transformation_spec_for_callable(
        user_alias_transform,
        transformation_id="fixture.binding.base",
        family="actor_alias",
        version="1",
        assumptions=("A different declared semantic assumption.",),
        parameters={"user_map": {"eve": "malory", "malory": "eve"}},
    )
    assert base.implementation_digest == changed_parameters.implementation_digest
    assert base.content_digest != changed_parameters.content_digest
    assert base.content_digest != changed_assumptions.content_digest
    assert base.parameters_json == canonical_dumps(base.parameters).decode("utf-8")


def test_spec_rejects_noncanonical_parameters_and_empty_assumptions() -> None:
    implementation = _alias_spec(transformation_id="fixture.canonical.source").implementation_digest
    with pytest.raises(ValueError, match="canonical JSON"):
        TransformationSpec(
            transformation_id="fixture.noncanonical",
            family="actor_alias",
            version="1",
            implementation_digest=implementation,
            parameters_json='{ "user_map": {"eve": "malory"} }',
            assumptions=("Preserves fixture semantics.",),
        )
    with pytest.raises(ValueError, match="assumptions"):
        TransformationSpec(
            transformation_id="fixture.empty-assumption",
            family="actor_alias",
            version="1",
            implementation_digest=implementation,
            assumptions=("",),
        )


def test_registry_verifies_implementation_digest_and_rejects_duplicate_id() -> None:
    spec = _alias_spec(transformation_id="fixture.registry.alias")
    register_transformation(spec, user_alias_transform)
    stored_spec, stored_fn = get_registered_transformation("fixture.registry.alias")
    assert stored_spec.content_digest == spec.content_digest
    assert stored_fn is user_alias_transform
    assert list_registered_transformations()["fixture.registry.alias"] == spec.content_digest

    with pytest.raises(ValueError, match="already registered"):
        register_transformation(spec, user_alias_transform)

    tampered = spec.model_copy(
        update={"transformation_id": "fixture.registry.tampered", "implementation_digest": "0" * 64}
    )
    with pytest.raises(ValueError, match="implementation digest mismatch"):
        register_transformation(tampered, user_alias_transform)


def test_consistent_pair_is_content_bound_and_nonqualification() -> None:
    spec = _alias_spec(transformation_id="fixture.consistent")

    def verifier(_value: dict[str, Any]) -> dict[str, bool]:
        return {"accepted": True}

    evidence = evaluate_registered_transformation(
        spec,
        user_alias_transform,
        _trajectory(),
        verifier=verifier,
        is_valid=_valid,
        verifier_profile_digest=PROFILE,
        source_unit_digest=digest_of("unit-consistent"),
    )
    assert evidence.status == "consistent"
    assert evidence.gt_invariant is True
    assert evidence.verifier_invariant is True
    assert evidence.counterexample is None
    assert evidence.original_digest != evidence.transformed_digest
    assert evidence.qualification_grade is False


def test_verifier_invariance_violation_produces_typed_counterexample() -> None:
    spec = _alias_spec(transformation_id="fixture.violation")

    def verifier(value: dict[str, Any]) -> dict[str, bool]:
        return {"accepted": value["steps"][0]["user_id"] == "eve"}

    evidence = evaluate_registered_transformation(
        spec,
        user_alias_transform,
        _trajectory(),
        verifier=verifier,
        is_valid=_valid,
        verifier_profile_digest=PROFILE,
        source_unit_digest=digest_of("unit-violation"),
    )
    assert evidence.status == "verifier_violation"
    assert evidence.gt_invariant is True
    assert evidence.verifier_invariant is False
    assert evidence.counterexample is not None
    assert evidence.counterexample.kind == "verifier_invariance_violation"
    assert evidence.counterexample.transformation_digest == spec.content_digest


def test_score_only_decision_remains_indeterminate() -> None:
    spec = _alias_spec(transformation_id="fixture.indeterminate")

    def verifier(_value: dict[str, Any]) -> float:
        return 0.9

    evidence = evaluate_registered_transformation(
        spec,
        user_alias_transform,
        _trajectory(),
        verifier=verifier,
        is_valid=_valid,
        verifier_profile_digest=PROFILE,
        source_unit_digest=digest_of("unit-indeterminate"),
    )
    assert evidence.status == "indeterminate"
    assert evidence.verifier_before is None
    assert evidence.verifier_after is None
    assert evidence.verifier_invariant is None
    assert evidence.counterexample is not None
    assert evidence.counterexample.kind == "verifier_decision_indeterminate"


def _invalidating_transform(
    trajectory: dict[str, Any],
    _parameters: Mapping[str, Any],
) -> dict[str, Any]:
    out = dict(trajectory)
    out["invalidated_by_transform"] = True
    return out


def test_invalid_transform_fails_closed_before_verifier_is_interpreted() -> None:
    spec = transformation_spec_for_callable(
        _invalidating_transform,
        transformation_id="fixture.invalid-transform",
        family="negative_control",
        version="1",
        assumptions=("This deliberately false invariant is a negative-control fixture.",),
    )
    verifier_calls = 0

    def is_valid(value: dict[str, Any]) -> bool:
        return not bool(value.get("invalidated_by_transform"))

    def verifier(_value: dict[str, Any]) -> dict[str, bool]:
        nonlocal verifier_calls
        verifier_calls += 1
        return {"accepted": True}

    with pytest.raises(InvalidMetamorphicTransformation) as exc_info:
        evaluate_registered_transformation(
            spec,
            _invalidating_transform,
            _trajectory(),
            verifier=verifier,
            is_valid=is_valid,
            verifier_profile_digest=PROFILE,
            source_unit_digest=digest_of("unit-invalid-transform"),
        )
    assert verifier_calls == 0
    evidence = exc_info.value.evidence
    assert evidence.status == "invalid_transform"
    assert evidence.gt_invariant is False
    assert evidence.verifier_before is None
    assert evidence.verifier_after is None
    assert evidence.counterexample is not None
    assert evidence.counterexample.kind == "ground_truth_invariance_violation"


def test_invalid_transform_can_be_preserved_as_nonqualification_evidence() -> None:
    spec = transformation_spec_for_callable(
        _invalidating_transform,
        transformation_id="fixture.invalid-transform-record",
        family="negative_control",
        version="1",
        assumptions=("Negative-control fixture.",),
    )

    def is_valid(value: dict[str, Any]) -> bool:
        return not bool(value.get("invalidated_by_transform"))

    evidence = evaluate_registered_transformation(
        spec,
        _invalidating_transform,
        _trajectory(),
        verifier=lambda _value: {"accepted": True},
        is_valid=is_valid,
        verifier_profile_digest=PROFILE,
        source_unit_digest=digest_of("unit-invalid-record"),
        fail_on_invalid_transform=False,
    )
    assert evidence.status == "invalid_transform"
    assert evidence.qualification_grade is False


def test_evaluator_rejects_callable_not_bound_by_spec() -> None:
    spec = _alias_spec(transformation_id="fixture.callable-mismatch")
    with pytest.raises(ValueError, match="implementation digest mismatch"):
        evaluate_registered_transformation(
            spec,
            _invalidating_transform,
            _trajectory(),
            verifier=lambda _value: {"accepted": True},
            is_valid=_valid,
            verifier_profile_digest=PROFILE,
        )


def test_suite_groups_exact_transform_and_profile_without_inference() -> None:
    spec = _alias_spec(transformation_id="fixture.suite")

    consistent = evaluate_registered_transformation(
        spec,
        user_alias_transform,
        _trajectory(),
        verifier=lambda _value: {"accepted": True},
        is_valid=_valid,
        verifier_profile_digest=PROFILE,
        source_unit_digest=digest_of("suite-a"),
    )
    violation = evaluate_registered_transformation(
        spec,
        user_alias_transform,
        _trajectory(),
        verifier=lambda value: {"accepted": value["steps"][0]["user_id"] == "eve"},
        is_valid=_valid,
        verifier_profile_digest=PROFILE,
        source_unit_digest=digest_of("suite-b"),
    )
    indeterminate = evaluate_registered_transformation(
        spec,
        user_alias_transform,
        _trajectory(),
        verifier=lambda _value: 0.7,
        is_valid=_valid,
        verifier_profile_digest=PROFILE,
        source_unit_digest=digest_of("suite-c"),
    )
    suite = compile_metamorphic_suite(
        spec,
        verifier_profile_digest=PROFILE,
        cases=[violation, indeterminate, consistent],
    )
    assert suite.case_count == 3
    assert suite.consistent_count == 1
    assert suite.verifier_violation_count == 1
    assert suite.indeterminate_count == 1
    assert suite.invalid_transform_count == 0
    assert suite.qualification_grade is False
    assert [case.source_unit_digest for case in suite.cases] == sorted(
        case.source_unit_digest for case in suite.cases
    )

    with pytest.raises(ValueError, match="duplicate source_unit_digest"):
        compile_metamorphic_suite(
            spec,
            verifier_profile_digest=PROFILE,
            cases=[consistent, consistent],
        )
    with pytest.raises(ValueError, match="different verifier profile"):
        compile_metamorphic_suite(
            spec,
            verifier_profile_digest=digest_of("other-profile"),
            cases=[consistent],
        )
