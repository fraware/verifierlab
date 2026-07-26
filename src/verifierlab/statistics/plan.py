"""StatsPlan compiler: CI-backed per-cohort estimands (VAL-R12 / VAL-C14 / VALAB-08)."""

from __future__ import annotations

from typing import Any

from verifierlab.config.campaign import StatsPlan
from verifierlab.reports.metrics import CohortMetrics, MetricsReport, compute_metrics_iter
from verifierlab.statistics.intervals import (
    Interval,
    exact_clopper_pearson,
    kaplan_meier_survival,
    time_to_exploit,
    wilson_interval,
)

_REQUIRED_REPORT_FIELDS = frozenset(
    {
        "stopping_rule",
        "multiple_comparison_policy",
        "optimization_gap",
        "censored",
        "sample_size",
        "exploit_rate",
    }
)


def _interval_for(
    successes: int,
    n: int,
    *,
    method: str,
    alpha: float,
) -> Interval:
    if method == "exact":
        return exact_clopper_pearson(successes, n, alpha=alpha)
    # Default / wilson
    return wilson_interval(successes, n, alpha=alpha)


def _rate_ci(
    successes: int,
    denom: int,
    *,
    methods: list[str],
    alpha: float,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "estimate": (successes / denom) if denom else None,
        "successes": successes,
        "numerator": successes,
        "n": denom,
        "denominator": denom,
        "intervals": {},
    }
    if denom <= 0:
        return out
    for method in methods:
        key = method if method in {"wilson", "exact"} else "wilson"
        out["intervals"][key] = _interval_for(successes, denom, method=key, alpha=alpha).as_dict()
    return out


def enrich_cohort_stats(
    cm: CohortMetrics,
    *,
    plan: StatsPlan,
) -> dict[str, Any]:
    """Attach CIs, denominators, and missingness to a cohort metrics dict."""
    methods = list(plan.methods) or ["wilson"]
    alpha = float(plan.alpha)
    far_denom = cm.fp + cm.tn
    frr_denom = cm.fn + cm.tp
    body = cm.as_dict()
    body["denominators"] = {
        "far": far_denom,
        "frr": frr_denom,
        "decided": cm.n - cm.missing - cm.failed,
        "n": cm.n,
    }
    body["sample_size"] = cm.n
    body["far_ci"] = _rate_ci(cm.fp, far_denom, methods=methods, alpha=alpha)
    body["frr_ci"] = _rate_ci(cm.fn, frr_denom, methods=methods, alpha=alpha)
    # Exploit rate among decided invalids (FAR numerator/denominator framing).
    body["exploit_rate"] = _rate_ci(cm.fp, far_denom, methods=methods, alpha=alpha)
    body["missingness_detail"] = {
        "missing": cm.missing,
        "failed": cm.failed,
        "abstentions": cm.abstentions,
        "missingness": cm.missingness,
        "abstention_rate": cm.abstention_rate,
    }
    body["stopping_rule"] = plan.stopping_rule
    body["multiple_comparison_policy"] = plan.multiple_comparison_policy
    return body


def optimization_gap(
    cohorts: dict[str, CohortMetrics],
    *,
    plan: StatsPlan,
    ordinary: str = "ordinary",
    optimized: str = "optimized",
) -> dict[str, Any] | None:
    """FAR(optimized) - FAR(ordinary) with optional bootstrap CI on the gap.

    When either cohort is absent, returns ``None``. Bootstrap resamples
    Bernoulli FAR indicators independently per cohort (unpaired) using
    ``plan.bootstrap_samples``.
    """
    if ordinary not in cohorts or optimized not in cohorts:
        return None
    o = cohorts[ordinary]
    z = cohorts[optimized]
    far_o = o.far
    far_z = z.far
    if far_o is None or far_z is None:
        return {
            "ordinary_far": far_o,
            "optimized_far": far_z,
            "gap": None,
            "note": "insufficient denominators for FAR gap",
        }
    gap = far_z - far_o
    result: dict[str, Any] = {
        "ordinary_far": far_o,
        "optimized_far": far_z,
        "gap": gap,
        "ordinary_n": o.fp + o.tn,
        "optimized_n": z.fp + z.tn,
    }
    methods = list(plan.methods) or ["wilson"]
    result["ordinary_far_ci"] = _rate_ci(o.fp, o.fp + o.tn, methods=methods, alpha=plan.alpha)
    result["optimized_far_ci"] = _rate_ci(z.fp, z.fp + z.tn, methods=methods, alpha=plan.alpha)
    result["multiplicity_policy"] = plan.multiple_comparison_policy
    n_boot = int(plan.bootstrap_samples)
    if n_boot > 0 and (o.fp + o.tn) > 0 and (z.fp + z.tn) > 0:
        result["gap_ci"] = _far_gap_bootstrap(
            fp_o=o.fp,
            n_o=o.fp + o.tn,
            fp_z=z.fp,
            n_z=z.fp + z.tn,
            samples=n_boot,
            alpha=float(plan.alpha),
            seed=0,
        ).as_dict()
    else:
        result["gap_ci"] = None
    return result


def _far_gap_bootstrap(
    *,
    fp_o: int,
    n_o: int,
    fp_z: int,
    n_z: int,
    samples: int,
    alpha: float,
    seed: int,
) -> Interval:
    """Unpaired bootstrap CI for FAR_z - FAR_o from contingency margins."""
    import random

    rng = random.Random(seed)
    ind_o = [1] * fp_o + [0] * (n_o - fp_o)
    ind_z = [1] * fp_z + [0] * (n_z - fp_z)
    boots: list[float] = []
    for _ in range(samples):
        so = [ind_o[rng.randrange(n_o)] for _ in range(n_o)]
        sz = [ind_z[rng.randrange(n_z)] for _ in range(n_z)]
        boots.append(sum(sz) / n_z - sum(so) / n_o)
    boots.sort()
    est = (fp_z / n_z) - (fp_o / n_o)
    lo = boots[int(alpha / 2 * (samples - 1))]
    hi = boots[int((1 - alpha / 2) * (samples - 1))]
    return Interval(est, lo, hi, "unpaired_bootstrap_far_gap", min(n_o, n_z))


def _censored_summary(results: Any) -> dict[str, Any]:
    """Aggregate failed / censored run counts and optional Kaplan-Meier."""
    rows = list(results) if not isinstance(results, list) else results
    failed = 0
    censored = 0
    times: list[float] = []
    events: list[bool] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "")
        if status in {"failed", "error"} or row.get("failed"):
            failed += 1
        if status in {"budget_stopped", "censored", "cancelled"} or row.get("censored"):
            censored += 1
        # Optional time-to-exploit fields when present.
        if "time_to_exploit" in row or "queries_to_exploit" in row:
            t = float(row.get("time_to_exploit") or row.get("queries_to_exploit") or 0.0)
            exploited = bool(row.get("exploited") or row.get("is_exploit"))
            times.append(t)
            events.append(exploited)
    summary: dict[str, Any] = {
        "failed_runs": failed,
        "censored_runs": censored,
        "n_rows": len(rows),
    }
    if times:
        tte = time_to_exploit(times, exploited=events)
        summary["time_to_exploit"] = tte
        summary["kaplan_meier"] = kaplan_meier_survival(times, exploited=events)
    return summary


def validate_stats_report_schema(payload: dict[str, Any]) -> list[str]:
    """Return missing required VALAB-08 fields (empty = valid)."""
    missing = [f for f in sorted(_REQUIRED_REPORT_FIELDS) if f not in payload]
    return missing


def compile_stats_plan(
    results: Any,
    *,
    plan: StatsPlan | None = None,
    access_model: str = "black-box",
    pool_overall: bool = False,
) -> dict[str, Any]:
    """Drive analysis from a declared :class:`StatsPlan`.

    Primary estimands: per-cohort FAR/FRR (+ CIs) and optimization gap.
    Overall cohort pooling is **disabled by default** (VAL-C14).
    VALAB-08 always includes stopping_rule, multiple_comparison_policy,
    censored/failed counts, and ordinary-versus-optimized gap.
    """
    plan = plan or StatsPlan()
    metrics: MetricsReport = compute_metrics_iter(
        results,
        access_model=access_model,
        pool_overall=pool_overall,
    )
    cohort_stats = {
        name: enrich_cohort_stats(cm, plan=plan) for name, cm in sorted(metrics.cohorts.items())
    }
    total_n = sum(cm.n for cm in metrics.cohorts.values())
    total_fp = sum(cm.fp for cm in metrics.cohorts.values())
    total_far_denom = sum(cm.fp + cm.tn for cm in metrics.cohorts.values())
    gap = optimization_gap(metrics.cohorts, plan=plan)
    # Require optimization_gap key even when cohorts are absent.
    if gap is None:
        gap = {
            "ordinary_far": None,
            "optimized_far": None,
            "gap": None,
            "note": "ordinary/optimized cohorts not both present",
        }
    censored = _censored_summary(results)
    payload: dict[str, Any] = {
        "schema_version": "2",
        "access_model": access_model,
        "stats_plan": plan.model_dump(mode="json"),
        "pool_overall": pool_overall,
        "cohorts": cohort_stats,
        "optimization_gap": gap,
        "stopping_rule": plan.stopping_rule,
        "multiple_comparison_policy": plan.multiple_comparison_policy,
        "sample_size": total_n,
        "exploit_rate": _rate_ci(
            total_fp,
            total_far_denom,
            methods=list(plan.methods) or ["wilson"],
            alpha=float(plan.alpha),
        ),
        "censored": censored,
        "primary_estimands": [
            "per_cohort_far",
            "per_cohort_frr",
            "optimization_gap",
            "exploit_rate",
        ],
    }
    if pool_overall:
        payload["overall"] = enrich_cohort_stats(metrics.overall, plan=plan)
    else:
        payload["overall"] = None
        payload["overall_note"] = (
            "overall cohort pooling disabled by default; set pool_overall=True to enable"
        )
    gaps = validate_stats_report_schema(payload)
    if gaps:
        raise ValueError(f"stats report missing required fields: {gaps}")
    return payload


__all__ = [
    "compile_stats_plan",
    "enrich_cohort_stats",
    "optimization_gap",
    "validate_stats_report_schema",
]
