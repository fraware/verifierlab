"""Golden tests for StatsPlan controls that must be executable, not decorative."""

from __future__ import annotations

import pytest

from verifierlab.config.campaign import StatsPlan
from verifierlab.statistics.plan import _effective_alpha, _paired_far_gap


def test_bonferroni_changes_effective_alpha() -> None:
    plan = StatsPlan(alpha=0.05, multiple_comparison_policy="bonferroni")
    effective, record = _effective_alpha(plan, family_size=5)
    assert effective == pytest.approx(0.01)
    assert record == {
        "policy": "bonferroni",
        "family_size": 5,
        "nominal_alpha": 0.05,
        "effective_alpha": pytest.approx(0.01),
        "applied": True,
    }


def test_sequential_alpha_without_stopping_plan_is_rejected() -> None:
    plan = StatsPlan(stopping_rule="sequential_alpha")
    with pytest.raises(ValueError, match="no preregistered StoppingPlan"):
        _effective_alpha(plan, family_size=1)


def test_sequential_alpha_with_lan_demets_plan_spends_alpha() -> None:
    from verifierlab.statistics.sequential import StoppingPlan

    plan = StatsPlan(
        stopping_rule="sequential_alpha",
        stopping_plan=StoppingPlan(looks=(0.5, 1.0), nominal_alpha=0.05),
    )
    effective, record = _effective_alpha(plan, family_size=1, look_index=0)
    assert record["policy"] == "sequential_alpha"
    assert record["applied"] is True
    assert 0.0 < effective <= 0.05
    final_eff, final_rec = _effective_alpha(plan, family_size=1, look_index=1)
    assert final_rec["sequential"]["information_fraction"] == 1.0
    assert final_eff >= effective


def test_pre_registered_primary_is_rejected_until_family_compiler_exists() -> None:
    plan = StatsPlan(multiple_comparison_policy="pre_registered_primary")
    with pytest.raises(ValueError, match="no explicit estimand-family compiler"):
        _effective_alpha(plan, family_size=1)


def test_bootstrap_seed_and_pairing_are_declared_fields() -> None:
    plan = StatsPlan(bootstrap_seed=73, pairing_key="scenario_id")
    payload = plan.model_dump(mode="json")
    assert payload["bootstrap_seed"] == 73
    assert payload["pairing_key"] == "scenario_id"


def test_paired_gap_uses_declared_key_not_row_order() -> None:
    rows = [
        {"scenario_id": "b", "cohort": "optimized", "gt_valid": False, "verifier_accepted": True},
        {"scenario_id": "a", "cohort": "ordinary", "gt_valid": False, "verifier_accepted": False},
        {"scenario_id": "b", "cohort": "ordinary", "gt_valid": False, "verifier_accepted": True},
        {"scenario_id": "a", "cohort": "optimized", "gt_valid": False, "verifier_accepted": True},
    ]
    result = _paired_far_gap(
        rows,
        pairing_key="scenario_id",
        ordinary="ordinary",
        optimized="optimized",
        samples=50,
        alpha=0.05,
        seed=11,
    )
    # a: 1-0 = +1; b: 1-1 = 0 -> mean +0.5
    assert result["n_pairs"] == 2
    assert result["gap"] == pytest.approx(0.5)
    assert result["bootstrap_seed"] == 11


def test_declared_pairing_without_complete_pairs_is_indeterminate() -> None:
    result = _paired_far_gap(
        [{"scenario_id": "a", "cohort": "ordinary", "gt_valid": False, "verifier_accepted": False}],
        pairing_key="scenario_id",
        ordinary="ordinary",
        optimized="optimized",
        samples=50,
        alpha=0.05,
        seed=11,
    )
    assert result["status"] == "indeterminate"
    assert result["gap"] is None
