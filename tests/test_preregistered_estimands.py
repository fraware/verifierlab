"""Regression tests for content-bound preregistered estimand compilation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from verifierlab.config.campaign import StatsPlan
from verifierlab.statistics.plan import compile_stats_plan
from verifierlab.statistics.preregistration import AnalysisPreregistration, EstimandSpec


def _rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    ordinary = [False, False, False, True]
    optimized = [True, True, False, False]
    for index, (left, right) in enumerate(zip(ordinary, optimized, strict=True)):
        scenario = f"h-{index}"
        rows.append(
            {
                "scenario_id": scenario,
                "split": "holdout",
                "cohort": "ordinary",
                "gt_valid": False,
                "verifier_accepted": left,
            }
        )
        rows.append(
            {
                "scenario_id": scenario,
                "split": "holdout",
                "cohort": "optimized",
                "gt_valid": False,
                "verifier_accepted": right,
            }
        )
    # Deliberately extreme non-holdout row. A split-bound estimand must ignore it.
    rows.append(
        {
            "scenario_id": "train-0",
            "split": "train",
            "cohort": "optimized",
            "gt_valid": False,
            "verifier_accepted": True,
        }
    )
    return rows


def _registration() -> AnalysisPreregistration:
    return AnalysisPreregistration(
        registration_id="repair-holdout-v1",
        assumptions=("held-out rows are fixed before analysis",),
        estimands=(
            EstimandSpec(
                estimand_id="optimized_far",
                metric="cohort_far",
                cohort="optimized",
                split="holdout",
                role="primary",
                inference="interval",
                interval_method="exact",
                alpha=0.025,
                direction="higher_is_worse",
            ),
            EstimandSpec(
                estimand_id="far_gap",
                metric="optimization_gap",
                contrast=("ordinary", "optimized"),
                split="holdout",
                role="primary",
                inference="interval",
                interval_method="bootstrap",
                alpha=0.025,
                direction="higher_is_worse",
            ),
            EstimandSpec(
                estimand_id="ordinary_far_context",
                metric="cohort_far",
                cohort="ordinary",
                split="holdout",
                role="secondary",
                inference="descriptive",
                direction="higher_is_worse",
            ),
        ),
    )


def _plan(registration: AnalysisPreregistration | None = None) -> StatsPlan:
    return StatsPlan(
        alpha=0.05,
        bootstrap_samples=200,
        bootstrap_seed=19,
        pairing_key="scenario_id",
        multiple_comparison_policy="pre_registered_primary",
        preregistration=registration,
    )


def test_preregistered_primary_requires_explicit_registration() -> None:
    with pytest.raises(ValueError, match="requires an explicit AnalysisPreregistration"):
        compile_stats_plan(_rows(), plan=_plan())


def test_registered_inference_is_the_only_inferential_surface() -> None:
    registration = _registration()
    report = compile_stats_plan(_rows(), plan=_plan(registration))

    assert report["schema_version"] == "4"
    assert report["preregistration_digest"] == registration.content_digest
    assert report["inferential_scope"] == "registered_estimands_only"
    assert report["primary_estimands"] == ["optimized_far", "far_gap"]

    # Compatibility report fields remain descriptive; no unregistered interval leaks out.
    assert report["exploit_rate"]["inferential"] is False
    assert "interval" not in report["exploit_rate"]
    assert report["cohorts"]["optimized"]["far"]["inferential"] is False

    optimized = report["registered_estimands"]["optimized_far"]
    assert optimized["result"]["inferential"] is True
    assert optimized["result"]["interval_method"] == "exact"
    assert optimized["result"]["estimate"] == pytest.approx(0.5)
    assert optimized["population_rows"] == 8

    context = report["registered_estimands"]["ordinary_far_context"]
    assert context["result"]["inferential"] is False
    assert "interval" not in context["result"]


def test_split_binding_excludes_non_holdout_rows() -> None:
    report = compile_stats_plan(_rows(), plan=_plan(_registration()))
    optimized = report["registered_estimands"]["optimized_far"]
    assert optimized["result"]["denominator"] == 4
    assert optimized["result"]["successes"] == 2
    assert optimized["result"]["estimate"] == pytest.approx(0.5)


def test_primary_alpha_allocation_is_applied_and_bounded() -> None:
    registration = _registration()
    report = compile_stats_plan(_rows(), plan=_plan(registration))
    multiplicity = report["multiplicity"]
    assert multiplicity["policy"] == "pre_registered_primary"
    assert multiplicity["allocated_alpha"] == {
        "far_gap": 0.025,
        "optimized_far": 0.025,
    }
    assert multiplicity["allocated_alpha_total"] == pytest.approx(0.05)

    payload = registration.model_dump(mode="json")
    payload["estimands"][0]["alpha"] = 0.04
    payload["estimands"][1]["alpha"] = 0.04
    overallocated = AnalysisPreregistration.model_validate(payload)
    with pytest.raises(ValueError, match="alpha allocation exceeds"):
        compile_stats_plan(_rows(), plan=_plan(overallocated))


def test_secondary_inferential_claims_are_rejected_under_primary_policy() -> None:
    registration = _registration()
    payload = registration.model_dump(mode="json")
    payload["estimands"][2].update(
        {"inference": "interval", "interval_method": "exact", "alpha": 0.01}
    )
    secondary_interval = AnalysisPreregistration.model_validate(payload)
    with pytest.raises(ValueError, match="secondary estimands to be descriptive"):
        compile_stats_plan(_rows(), plan=_plan(secondary_interval))


def test_estimand_semantics_change_registration_digest() -> None:
    registration = _registration()
    payload = registration.model_dump(mode="json")
    payload["estimands"][0]["split"] = "train"
    rebound = AnalysisPreregistration.model_validate(payload)
    assert rebound.content_digest != registration.content_digest


def test_invalid_metric_method_contracts_fail_closed() -> None:
    with pytest.raises(ValidationError, match="requires bootstrap"):
        EstimandSpec(
            estimand_id="gap",
            metric="optimization_gap",
            contrast=("ordinary", "optimized"),
            interval_method="exact",
            alpha=0.05,
        )
    with pytest.raises(ValidationError, match="descriptive estimands cannot"):
        EstimandSpec(
            estimand_id="context",
            metric="exploit_rate",
            role="secondary",
            inference="descriptive",
            interval_method="exact",
            alpha=0.05,
        )


def test_duplicate_estimand_ids_fail_closed() -> None:
    item = EstimandSpec(
        estimand_id="same",
        metric="exploit_rate",
        interval_method="exact",
        alpha=0.025,
    )
    with pytest.raises(ValidationError, match="estimand_id values must be unique"):
        AnalysisPreregistration(
            registration_id="dup",
            assumptions=("fixed family",),
            estimands=(item, item),
        )


def test_sequential_monitoring_remains_unimplemented() -> None:
    plan = _plan(_registration()).model_copy(update={"stopping_rule": "sequential_alpha"})
    with pytest.raises(ValueError, match="no alpha-spending procedure"):
        compile_stats_plan(_rows(), plan=plan)
