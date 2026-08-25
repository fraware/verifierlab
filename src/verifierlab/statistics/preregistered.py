"""Compiler for explicitly preregistered primary estimands.

Compatibility metrics remain descriptive on this path. Inferential intervals
are emitted only inside ``registered_estimands`` and only when the corresponding
estimand declaration names an interval method and alpha allocation.
"""

from __future__ import annotations

from typing import Any

from verifierlab.config.campaign import StatsPlan
from verifierlab.reports.metrics import CohortMetrics, MetricsReport, compute_metrics_iter
from verifierlab.statistics.intervals import exact_clopper_pearson, wilson_interval
from verifierlab.statistics.preregistration import AnalysisPreregistration, EstimandSpec


def _rows_for_split(rows: list[Any], split: str | None) -> list[Any]:
    if split is None:
        return list(rows)
    return [row for row in rows if isinstance(row, dict) and row.get("split") == split]


def _descriptive_rate(successes: int, denominator: int) -> dict[str, Any]:
    return {
        "estimate": (successes / denominator) if denominator else None,
        "successes": successes,
        "numerator": successes,
        "n": denominator,
        "denominator": denominator,
        "inferential": False,
    }


def _interval_rate(
    successes: int,
    denominator: int,
    *,
    method: str,
    alpha: float,
) -> dict[str, Any]:
    body = _descriptive_rate(successes, denominator)
    body["inferential"] = True
    body["alpha"] = alpha
    body["interval_method"] = method
    if denominator <= 0:
        body["status"] = "indeterminate"
        body["interval"] = None
        body["reason"] = "zero_denominator"
        return body
    if method == "wilson":
        interval = wilson_interval(successes, denominator, alpha=alpha)
    elif method == "exact":
        interval = exact_clopper_pearson(successes, denominator, alpha=alpha)
    else:
        raise ValueError(f"unsupported registered rate interval method: {method!r}")
    body["status"] = "estimated"
    body["interval"] = interval.as_dict()
    return body


def _descriptive_cohort(cm: CohortMetrics) -> dict[str, Any]:
    far_denom = cm.fp + cm.tn
    frr_denom = cm.fn + cm.tp
    body = cm.as_dict()
    body["sample_size"] = cm.n
    body["denominators"] = {
        "far": far_denom,
        "frr": frr_denom,
        "decided": cm.n - cm.missing - cm.failed,
        "n": cm.n,
    }
    body["far"] = _descriptive_rate(cm.fp, far_denom)
    body["frr"] = _descriptive_rate(cm.fn, frr_denom)
    body["inferential"] = False
    return body


def _descriptive_gap(
    cohorts: dict[str, CohortMetrics],
    *,
    ordinary: str = "ordinary",
    optimized: str = "optimized",
) -> dict[str, Any]:
    if ordinary not in cohorts or optimized not in cohorts:
        return {
            "ordinary_cohort": ordinary,
            "optimized_cohort": optimized,
            "ordinary_far": None,
            "optimized_far": None,
            "gap": None,
            "inferential": False,
            "status": "indeterminate",
            "reason": "contrast_cohort_absent",
        }
    left = cohorts[ordinary]
    right = cohorts[optimized]
    if left.far is None or right.far is None:
        return {
            "ordinary_cohort": ordinary,
            "optimized_cohort": optimized,
            "ordinary_far": left.far,
            "optimized_far": right.far,
            "gap": None,
            "inferential": False,
            "status": "indeterminate",
            "reason": "zero_far_denominator",
        }
    return {
        "ordinary_cohort": ordinary,
        "optimized_cohort": optimized,
        "ordinary_far": left.far,
        "optimized_far": right.far,
        "gap": right.far - left.far,
        "ordinary_n": left.fp + left.tn,
        "optimized_n": right.fp + right.tn,
        "inferential": False,
        "status": "estimated",
    }


def _compile_gap_interval(
    spec: EstimandSpec,
    rows: list[Any],
    plan: StatsPlan,
    *,
    access_model: str,
) -> dict[str, Any]:
    from verifierlab.statistics.plan import optimization_gap

    assert spec.contrast is not None
    assert spec.alpha is not None
    filtered = _rows_for_split(rows, spec.split)
    metrics = compute_metrics_iter(filtered, access_model=access_model, pool_overall=False)
    gap = optimization_gap(
        metrics.cohorts,
        plan=plan,
        rows=filtered,
        analysis_alpha=spec.alpha,
        ordinary=spec.contrast[0],
        optimized=spec.contrast[1],
    )
    if gap is None:
        return {
            "status": "indeterminate",
            "reason": "contrast_cohort_absent",
            "gap": None,
            "gap_ci": None,
            "alpha": spec.alpha,
            "interval_method": "bootstrap",
            "inferential": True,
        }
    result = dict(gap)
    result["inferential"] = True
    result["interval_method"] = "bootstrap"
    if result.get("gap_ci") is None:
        result["status"] = "indeterminate"
        result.setdefault("reason", "interval_unavailable")
    else:
        result["status"] = "estimated"
    return result


def _compile_estimand(
    spec: EstimandSpec,
    rows: list[Any],
    plan: StatsPlan,
    *,
    access_model: str,
) -> dict[str, Any]:
    filtered = _rows_for_split(rows, spec.split)
    metrics = compute_metrics_iter(filtered, access_model=access_model, pool_overall=False)
    definition = spec.model_dump(mode="json")
    base: dict[str, Any] = {
        "estimand_id": spec.estimand_id,
        "definition": definition,
        "population_rows": len(filtered),
        "registration_role": spec.role,
    }

    if spec.metric == "optimization_gap":
        assert spec.contrast is not None
        if spec.inference == "interval":
            value = _compile_gap_interval(spec, rows, plan, access_model=access_model)
        else:
            value = _descriptive_gap(
                metrics.cohorts,
                ordinary=spec.contrast[0],
                optimized=spec.contrast[1],
            )
        base["result"] = value
        return base

    if spec.metric == "exploit_rate":
        fp = sum(cm.fp for cm in metrics.cohorts.values())
        denominator = sum(cm.fp + cm.tn for cm in metrics.cohorts.values())
    else:
        assert spec.cohort is not None
        cohort = metrics.cohorts.get(spec.cohort)
        if cohort is None:
            base["result"] = {
                "estimate": None,
                "inferential": spec.inference == "interval",
                "status": "indeterminate",
                "reason": "cohort_absent",
            }
            return base
        if spec.metric == "cohort_far":
            fp = cohort.fp
            denominator = cohort.fp + cohort.tn
        elif spec.metric == "cohort_frr":
            fp = cohort.fn
            denominator = cohort.fn + cohort.tp
        else:
            raise ValueError(f"unsupported registered estimand metric: {spec.metric!r}")

    if spec.inference == "descriptive":
        result = _descriptive_rate(fp, denominator)
        result["status"] = "estimated" if denominator else "indeterminate"
    else:
        assert spec.interval_method is not None
        assert spec.alpha is not None
        result = _interval_rate(
            fp,
            denominator,
            method=spec.interval_method,
            alpha=spec.alpha,
        )
    base["result"] = result
    return base


def _validate_primary_family(plan: StatsPlan, registration: AnalysisPreregistration) -> dict[str, Any]:
    primary_interval = [
        item
        for item in registration.estimands
        if item.role == "primary" and item.inference == "interval"
    ]
    if not primary_interval:
        raise ValueError("pre_registered_primary requires at least one inferential primary estimand")
    secondary_interval = [
        item.estimand_id
        for item in registration.estimands
        if item.role == "secondary" and item.inference == "interval"
    ]
    if secondary_interval:
        raise ValueError(
            "pre_registered_primary requires secondary estimands to be descriptive; "
            f"inferential secondary ids={sorted(secondary_interval)}"
        )
    if any(item.metric == "optimization_gap" for item in primary_interval) and plan.bootstrap_samples <= 0:
        raise ValueError("registered optimization-gap intervals require bootstrap_samples > 0")
    allocated = {item.estimand_id: float(item.alpha or 0.0) for item in primary_interval}
    allocated_total = sum(allocated.values())
    if allocated_total > float(plan.alpha) + 1e-12:
        raise ValueError(
            "registered primary alpha allocation exceeds StatsPlan alpha: "
            f"allocated={allocated_total}, plan={plan.alpha}"
        )
    return {
        "policy": "pre_registered_primary",
        "family_size": len(primary_interval),
        "nominal_alpha": float(plan.alpha),
        "allocated_alpha": allocated,
        "allocated_alpha_total": allocated_total,
        "applied": True,
        "secondary_inference": "descriptive_only",
    }


def compile_preregistered_stats_plan(
    results: Any,
    *,
    plan: StatsPlan,
    access_model: str,
    pool_overall: bool,
) -> dict[str, Any]:
    """Compile only declared inferential estimands for pre-registered-primary policy."""
    if plan.stopping_rule == "sequential_alpha":
        raise ValueError(
            "sequential_alpha is declared but no alpha-spending procedure is implemented; "
            "refusing to compile inferential results"
        )
    registration = plan.preregistration
    if registration is None:
        raise ValueError(
            "pre_registered_primary requires an explicit AnalysisPreregistration; "
            "refusing to infer an estimand family from observed results"
        )

    rows = results if isinstance(results, list) else list(results)
    metrics: MetricsReport = compute_metrics_iter(
        rows,
        access_model=access_model,
        pool_overall=pool_overall,
    )
    multiplicity = _validate_primary_family(plan, registration)
    registered = {
        item.estimand_id: _compile_estimand(item, rows, plan, access_model=access_model)
        for item in registration.estimands
    }
    if set(registered) != {item.estimand_id for item in registration.estimands}:
        raise RuntimeError("compiled estimand set diverged from preregistration")

    total_n = sum(cm.n for cm in metrics.cohorts.values())
    total_fp = sum(cm.fp for cm in metrics.cohorts.values())
    total_far_denom = sum(cm.fp + cm.tn for cm in metrics.cohorts.values())

    from verifierlab.statistics.plan import _censored_summary, validate_stats_report_schema

    payload: dict[str, Any] = {
        "schema_version": "4",
        "access_model": access_model,
        "stats_plan": plan.model_dump(mode="json"),
        "pool_overall": pool_overall,
        "cohorts": {
            name: _descriptive_cohort(cm) for name, cm in sorted(metrics.cohorts.items())
        },
        "optimization_gap": _descriptive_gap(metrics.cohorts),
        "stopping_rule": plan.stopping_rule,
        "multiple_comparison_policy": plan.multiple_comparison_policy,
        "multiplicity": multiplicity,
        "sample_size": total_n,
        "exploit_rate": _descriptive_rate(total_fp, total_far_denom),
        "censored": _censored_summary(rows),
        "primary_estimands": [
            item.estimand_id for item in registration.estimands if item.role == "primary"
        ],
        "registered_estimands": registered,
        "preregistration": registration.model_dump(mode="json"),
        "preregistration_digest": registration.content_digest,
        "inferential_scope": "registered_estimands_only",
        "bootstrap_seed": int(plan.bootstrap_seed),
        "pairing_key": plan.pairing_key,
    }
    if pool_overall:
        payload["overall"] = _descriptive_cohort(metrics.overall)
    else:
        payload["overall"] = None
        payload["overall_note"] = (
            "overall cohort pooling disabled by default; set pool_overall=True to enable"
        )
    gaps = validate_stats_report_schema(payload)
    if gaps:
        raise ValueError(f"stats report missing required fields: {gaps}")
    return payload


__all__ = ["compile_preregistered_stats_plan"]
