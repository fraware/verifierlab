"""StatsPlan compiler: executable CI-backed estimands (VAL-R12 / VALAB-08)."""

from __future__ import annotations

from typing import Any

from verifierlab.config.campaign import StatsPlan
from verifierlab.reports.metrics import CohortMetrics, MetricsReport, compute_metrics_iter
from verifierlab.statistics.intervals import (
    Interval,
    exact_clopper_pearson,
    kaplan_meier_survival,
    paired_bootstrap,
    time_to_exploit,
    wilson_interval,
)

_REQUIRED_REPORT_FIELDS = frozenset(
    {
        "stopping_rule",
        "multiple_comparison_policy",
        "multiplicity",
        "optimization_gap",
        "censored",
        "sample_size",
        "exploit_rate",
    }
)


def _interval_for(successes: int, n: int, *, method: str, alpha: float) -> Interval:
    if method == "exact":
        return exact_clopper_pearson(successes, n, alpha=alpha)
    if method == "wilson":
        return wilson_interval(successes, n, alpha=alpha)
    raise ValueError(f"unsupported interval method: {method!r}")


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
        "alpha": alpha,
        "intervals": {},
    }
    if denom <= 0:
        return out
    for method in methods:
        out["intervals"][method] = _interval_for(
            successes,
            denom,
            method=method,
            alpha=alpha,
        ).as_dict()
    return out


def enrich_cohort_stats(
    cm: CohortMetrics,
    *,
    plan: StatsPlan,
    analysis_alpha: float | None = None,
) -> dict[str, Any]:
    """Attach CIs, denominators, missingness and applied alpha to a cohort."""
    methods = list(plan.methods) or ["wilson"]
    alpha = float(plan.alpha if analysis_alpha is None else analysis_alpha)
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
    body["analysis_alpha"] = alpha
    return body


def _paired_far_gap(
    rows: list[Any],
    *,
    pairing_key: str,
    ordinary: str,
    optimized: str,
    samples: int,
    alpha: float,
    seed: int,
) -> dict[str, Any]:
    """Paired FAR gap from explicitly paired invalid units.

    Pairing is never inferred from row order. Both members must expose the
    declared pairing key and be ground-truth invalid for FAR to be defined.
    """
    pairs: dict[str, dict[str, dict[str, Any]]] = {}
    for row in rows:
        if not isinstance(row, dict) or pairing_key not in row:
            continue
        cohort = str(row.get("cohort") or "")
        if cohort not in {ordinary, optimized}:
            continue
        key = str(row[pairing_key])
        pairs.setdefault(key, {})[cohort] = row

    ordinary_values: list[float] = []
    optimized_values: list[float] = []
    for pair in pairs.values():
        o = pair.get(ordinary)
        z = pair.get(optimized)
        if o is None or z is None:
            continue
        if o.get("gt_valid") is not False or z.get("gt_valid") is not False:
            continue
        ordinary_values.append(1.0 if o.get("verifier_accepted") is True else 0.0)
        optimized_values.append(1.0 if z.get("verifier_accepted") is True else 0.0)

    if not ordinary_values:
        return {
            "method": "paired_bootstrap_far_gap",
            "pairing_key": pairing_key,
            "n_pairs": 0,
            "gap": None,
            "gap_ci": None,
            "status": "indeterminate",
            "note": "no complete invalid ordinary/optimized pairs for declared pairing_key",
        }

    gap = sum(z - o for z, o in zip(optimized_values, ordinary_values, strict=True)) / len(
        ordinary_values
    )
    interval = None
    if samples > 0:
        interval = paired_bootstrap(
            optimized_values,
            ordinary_values,
            samples=samples,
            alpha=alpha,
            seed=seed,
        ).as_dict()
    return {
        "method": "paired_bootstrap_far_gap",
        "pairing_key": pairing_key,
        "n_pairs": len(ordinary_values),
        "gap": gap,
        "gap_ci": interval,
        "status": "estimated",
        "bootstrap_seed": seed,
        "alpha": alpha,
    }


def optimization_gap(
    cohorts: dict[str, CohortMetrics],
    *,
    plan: StatsPlan,
    rows: list[Any] | None = None,
    analysis_alpha: float | None = None,
    ordinary: str = "ordinary",
    optimized: str = "optimized",
) -> dict[str, Any] | None:
    """FAR(optimized) - FAR(ordinary), paired when explicitly declared."""
    if ordinary not in cohorts or optimized not in cohorts:
        return None
    o = cohorts[ordinary]
    z = cohorts[optimized]
    far_o = o.far
    far_z = z.far
    alpha = float(plan.alpha if analysis_alpha is None else analysis_alpha)
    if far_o is None or far_z is None:
        return {
            "ordinary_far": far_o,
            "optimized_far": far_z,
            "gap": None,
            "note": "insufficient denominators for FAR gap",
            "alpha": alpha,
        }

    if plan.pairing_key is not None:
        paired = _paired_far_gap(
            rows or [],
            pairing_key=plan.pairing_key,
            ordinary=ordinary,
            optimized=optimized,
            samples=int(plan.bootstrap_samples),
            alpha=alpha,
            seed=int(plan.bootstrap_seed),
        )
        paired.update(
            {
                "ordinary_far": far_o,
                "optimized_far": far_z,
                "ordinary_n": o.fp + o.tn,
                "optimized_n": z.fp + z.tn,
                "multiplicity_policy": plan.multiple_comparison_policy,
            }
        )
        return paired

    gap = far_z - far_o
    result: dict[str, Any] = {
        "ordinary_far": far_o,
        "optimized_far": far_z,
        "gap": gap,
        "ordinary_n": o.fp + o.tn,
        "optimized_n": z.fp + z.tn,
        "method": "unpaired_bootstrap_far_gap",
        "pairing_key": None,
        "alpha": alpha,
        "multiplicity_policy": plan.multiple_comparison_policy,
    }
    n_boot = int(plan.bootstrap_samples)
    if n_boot > 0 and (o.fp + o.tn) > 0 and (z.fp + z.tn) > 0:
        result["gap_ci"] = _far_gap_bootstrap(
            fp_o=o.fp,
            n_o=o.fp + o.tn,
            fp_z=z.fp,
            n_z=z.fp + z.tn,
            samples=n_boot,
            alpha=alpha,
            seed=int(plan.bootstrap_seed),
        ).as_dict()
        result["bootstrap_seed"] = int(plan.bootstrap_seed)
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


def _censored_summary(rows: list[Any]) -> dict[str, Any]:
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
        summary["time_to_exploit"] = time_to_exploit(times, exploited=events)
        summary["kaplan_meier"] = kaplan_meier_survival(times, exploited=events)
    return summary


def validate_stats_report_schema(payload: dict[str, Any]) -> list[str]:
    return [f for f in sorted(_REQUIRED_REPORT_FIELDS) if f not in payload]


def _family_size(cohorts: dict[str, CohortMetrics], *, gap_available: bool) -> int:
    # FAR + FRR for each reported cohort, global exploit rate, and one gap.
    return max(1, 2 * len(cohorts) + 1 + int(gap_available))


def _effective_alpha(
    plan: StatsPlan,
    *,
    family_size: int,
    look_index: int | None = None,
) -> tuple[float, dict[str, Any]]:
    if plan.stopping_rule == "sequential_alpha":
        from verifierlab.statistics.sequential import alpha_spent_at_look, require_sequential_plan

        stopping = plan.stopping_plan
        if stopping is None and plan.preregistration is not None:
            stopping = plan.preregistration.stopping_plan
        stopping = require_sequential_plan(stopping)
        idx = 0 if look_index is None else look_index
        spent = alpha_spent_at_look(stopping, idx)
        effective = float(spent["incremental_alpha"])
        return effective, {
            "policy": "sequential_alpha",
            "family_size": family_size,
            "nominal_alpha": float(plan.alpha),
            "effective_alpha": effective,
            "applied": True,
            "sequential": spent,
        }
    if plan.multiple_comparison_policy == "pre_registered_primary":
        raise ValueError(
            "pre_registered_primary is declared but no explicit estimand-family compiler is "
            "implemented; refusing to advertise an unapplied multiplicity policy"
        )
    if plan.multiple_comparison_policy == "bonferroni":
        effective = float(plan.alpha) / family_size
        return effective, {
            "policy": "bonferroni",
            "family_size": family_size,
            "nominal_alpha": float(plan.alpha),
            "effective_alpha": effective,
            "applied": True,
        }
    if plan.multiple_comparison_policy == "holm":
        # Holm adjusts per-test thresholds from raw p-values at decision time;
        # intervals use nominal alpha here and holm decisions are attached separately.
        return float(plan.alpha), {
            "policy": "holm",
            "family_size": family_size,
            "nominal_alpha": float(plan.alpha),
            "effective_alpha": float(plan.alpha),
            "applied": True,
            "note": "holm thresholds applied to p-values via holm_step_down",
        }
    return float(plan.alpha), {
        "policy": "none",
        "family_size": family_size,
        "nominal_alpha": float(plan.alpha),
        "effective_alpha": float(plan.alpha),
        "applied": False,
    }


def compile_stats_plan(
    results: Any,
    *,
    plan: StatsPlan | None = None,
    access_model: str = "black-box",
    pool_overall: bool = False,
) -> dict[str, Any]:
    """Drive analysis from an executable declared :class:`StatsPlan`.

    Unsupported sequential/multiplicity declarations fail closed. Bonferroni
    adjusts every inferential interval emitted by this compiler. A pairing key,
    when declared, is used explicitly for the optimization-gap bootstrap and
    never replaced by row-order pairing.
    """
    plan = plan or StatsPlan()
    if plan.multiple_comparison_policy == "pre_registered_primary":
        from verifierlab.statistics.preregistered import compile_preregistered_stats_plan

        return compile_preregistered_stats_plan(
            results,
            plan=plan,
            access_model=access_model,
            pool_overall=pool_overall,
        )
    rows = results if isinstance(results, list) else list(results)
    metrics: MetricsReport = compute_metrics_iter(
        rows,
        access_model=access_model,
        pool_overall=pool_overall,
    )
    gap_available = "ordinary" in metrics.cohorts and "optimized" in metrics.cohorts
    family_size = _family_size(metrics.cohorts, gap_available=gap_available)
    analysis_alpha, multiplicity = _effective_alpha(plan, family_size=family_size)

    cohort_stats = {
        name: enrich_cohort_stats(cm, plan=plan, analysis_alpha=analysis_alpha)
        for name, cm in sorted(metrics.cohorts.items())
    }
    total_n = sum(cm.n for cm in metrics.cohorts.values())
    total_fp = sum(cm.fp for cm in metrics.cohorts.values())
    total_far_denom = sum(cm.fp + cm.tn for cm in metrics.cohorts.values())
    gap = optimization_gap(
        metrics.cohorts,
        plan=plan,
        rows=rows,
        analysis_alpha=analysis_alpha,
    )
    if gap is None:
        gap = {
            "ordinary_far": None,
            "optimized_far": None,
            "gap": None,
            "note": "ordinary/optimized cohorts not both present",
        }
    censored = _censored_summary(rows)
    payload: dict[str, Any] = {
        "schema_version": "3",
        "access_model": access_model,
        "stats_plan": plan.model_dump(mode="json"),
        "pool_overall": pool_overall,
        "cohorts": cohort_stats,
        "optimization_gap": gap,
        "stopping_rule": plan.stopping_rule,
        "multiple_comparison_policy": plan.multiple_comparison_policy,
        "multiplicity": multiplicity,
        "sample_size": total_n,
        "exploit_rate": _rate_ci(
            total_fp,
            total_far_denom,
            methods=list(plan.methods) or ["wilson"],
            alpha=analysis_alpha,
        ),
        "censored": censored,
        "primary_estimands": [
            "per_cohort_far",
            "per_cohort_frr",
            "optimization_gap",
            "exploit_rate",
        ],
        "bootstrap_seed": int(plan.bootstrap_seed),
        "pairing_key": plan.pairing_key,
    }
    if pool_overall:
        payload["overall"] = enrich_cohort_stats(
            metrics.overall,
            plan=plan,
            analysis_alpha=analysis_alpha,
        )
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
