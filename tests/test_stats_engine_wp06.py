"""WP-06 statistical engine closure tests."""

from __future__ import annotations

import pytest

from verifierlab.config.preregistration import AnalysisPreregistration, EstimandSpec
from verifierlab.statistics.equivalence import paired_binary_tost
from verifierlab.statistics.multiplicity import bonferroni_alpha, holm_step_down
from verifierlab.statistics.power import PowerPlan, evaluate_power_plan
from verifierlab.statistics.sequential import (
    StoppingPlan,
    alpha_spent_at_look,
    obrien_fleming_spend,
    require_sequential_plan,
)


def test_primary_rejects_trajectory_pseudo_replication() -> None:
    with pytest.raises(ValueError, match="trajectory"):
        EstimandSpec(
            estimand_id="e1",
            metric="attack_success",
            role="primary",
            inference="interval",
            sampling_unit="trajectory",
            interval_method="wilson",
            alpha=0.05,
        )


def test_task_is_default_sampling_unit() -> None:
    spec = EstimandSpec(
        estimand_id="e1",
        metric="far",
        cohort="optimized",
        inference="interval",
        interval_method="wilson",
        alpha=0.05,
    )
    assert spec.sampling_unit == "task"


def test_holm_step_down_orders_and_gates() -> None:
    result = holm_step_down(
        [("a", 0.01), ("b", 0.04), ("c", 0.03)],
        alpha=0.05,
    )
    assert result["policy"] == "holm"
    assert result["family_size"] == 3
    # Smallest p rejects first; later thresholds tighten.
    by_id = {d["estimand_id"]: d for d in result["decisions"]}
    assert by_id["a"]["reject_null"] is True
    assert bonferroni_alpha(0.05, 4) == pytest.approx(0.0125)


def test_sequential_requires_plan() -> None:
    with pytest.raises(ValueError, match="StoppingPlan"):
        require_sequential_plan(None)
    plan = StoppingPlan(looks=(0.5, 1.0), nominal_alpha=0.05)
    spent0 = alpha_spent_at_look(plan, 0)
    spent1 = alpha_spent_at_look(plan, 1)
    assert spent0["cumulative_alpha"] < spent1["cumulative_alpha"]
    assert spent1["cumulative_alpha"] == pytest.approx(0.05)
    assert obrien_fleming_spend(0.05, 1.0) == pytest.approx(0.05)


def test_tost_never_treats_nonrejection_as_equivalence() -> None:
    # Large difference outside margin → not equivalent.
    before = [0, 0, 0, 0, 1, 1, 1, 1]
    after = [1, 1, 1, 1, 1, 1, 1, 1]
    result = paired_binary_tost(before, after, margin=0.05, alpha=0.05)
    assert result["equivalent"] is False
    assert result["status"] == "estimated"
    # Near-zero difference within margin with enough n.
    before2 = [0, 1, 0, 1, 0, 1, 0, 1] * 20
    after2 = list(before2)
    eq = paired_binary_tost(before2, after2, margin=0.1, alpha=0.05)
    assert eq["equivalent"] is True


def test_power_plan_underpowered_is_indeterminate() -> None:
    plan = PowerPlan(
        estimand_id="primary-far",
        p0=0.1,
        p1=0.2,
        alpha=0.05,
        target_power=0.8,
        planned_n_units=500,
    )
    digest = plan.content_digest
    assert len(digest) == 64
    result = evaluate_power_plan(plan, observed_n_units=5)
    assert result["underpowered"] is True
    assert result["status"] == "indeterminate"
    assert result["maturity_blocker"] == "primary_estimand_underpowered"
    assert result["power_plan_digest"] == digest


def test_new_estimand_metrics_validate() -> None:
    specs = [
        EstimandSpec(
            estimand_id="as",
            metric="attack_success",
            inference="interval",
            interval_method="wilson",
            alpha=0.05,
        ),
        EstimandSpec(
            estimand_id="pr",
            metric="paired_repair_delta",
            contrast=("pre", "post"),
            pairing_key="unit_id",
            inference="equivalence",
            alpha=0.05,
            equivalence_margin=0.05,
        ),
        EstimandSpec(
            estimand_id="mv",
            metric="metamorphic_violation",
            role="descriptive",
            inference="descriptive",
        ),
        EstimandSpec(
            estimand_id="ps",
            metric="planted_sensitivity",
            inference="interval",
            interval_method="exact",
            alpha=0.05,
        ),
    ]
    reg = AnalysisPreregistration(
        registration_id="wp06",
        estimands=tuple(specs),
        assumptions=("task-cluster sampling",),
    )
    assert reg.content_digest
    assert reg.default_sampling_unit == "task"
