"""Statistics package."""

from __future__ import annotations

from verifierlab.statistics.intervals import (
    Interval,
    cluster_bootstrap,
    exact_clopper_pearson,
    kaplan_meier_survival,
    paired_bootstrap,
    power_binomial,
    robustness_curve,
    sample_size_for_power,
    time_to_exploit,
    wilson_interval,
)
from verifierlab.statistics.metamorphic import (
    assert_gt_invariance,
    isomorphic_remap,
    verifier_invariance_report,
)
from verifierlab.statistics.plan import (
    compile_stats_plan,
    enrich_cohort_stats,
    optimization_gap,
    validate_stats_report_schema,
)

__all__ = [
    "Interval",
    "assert_gt_invariance",
    "cluster_bootstrap",
    "compile_stats_plan",
    "enrich_cohort_stats",
    "exact_clopper_pearson",
    "isomorphic_remap",
    "kaplan_meier_survival",
    "optimization_gap",
    "paired_bootstrap",
    "power_binomial",
    "robustness_curve",
    "sample_size_for_power",
    "time_to_exploit",
    "validate_stats_report_schema",
    "verifier_invariance_report",
    "wilson_interval",
]
