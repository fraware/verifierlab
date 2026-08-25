"""Compiler for explicitly preregistered estimands.

Compatibility summaries remain descriptive. Inferential results are emitted
only for declared estimands and unsupported/missing data paths return typed
``indeterminate`` results rather than silently substituting another metric.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from verifierlab.config.campaign import StatsPlan
from verifierlab.config.preregistration import AnalysisPreregistration, EstimandSpec
from verifierlab.reports.metrics import CohortMetrics, MetricsReport, compute_metrics_iter
from verifierlab.statistics.intervals import (
    cluster_bootstrap,
    exact_clopper_pearson,
    kaplan_meier_survival,
    paired_bootstrap,
    time_to_exploit,
    wilson_interval,
)


def _rows_for_split(rows: list[Any], split: str | None) -> list[dict[str, Any]]:
    typed = [row for row in rows if isinstance(row, dict)]
    if split is None:
        return typed
    return [row for row in typed if row.get("split") == split]


def _rows_for_cohort(rows: list[dict[str, Any]], cohort: str | None) -> list[dict[str, Any]]:
    if cohort is None:
        return rows
    return [row for row in rows if str(row.get("cohort") or "") == cohort]


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


def _descriptive_cohort(metrics: CohortMetrics) -> dict[str, Any]:
    far_denom = metrics.fp + metrics.tn
    frr_denom = metrics.fn + metrics.tp
    body = metrics.as_dict()
    body["sample_size"] = metrics.n
    body["denominators"] = {
        "far": far_denom,
        "frr": frr_denom,
        "decided": metrics.n - metrics.missing - metrics.failed,
        "n": metrics.n,
    }
    body["far"] = _descriptive_rate(metrics.fp, far_denom)
    body["frr"] = _descriptive_rate(metrics.fn, frr_denom)
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


def _binary_value(metric: str, row: dict[str, Any]) -> int | None:
    """Resolve one metric's explicitly named binary observation from a result row."""
    if metric == "attack_success":
        for key in ("attack_success", "exploit", "is_exploit", "exploited"):
            if isinstance(row.get(key), bool):
                return int(bool(row[key]))
        if row.get("gt_valid") is False and isinstance(row.get("verifier_accepted"), bool):
            return int(bool(row["verifier_accepted"]))
        return None
    if metric == "clean_success":
        if isinstance(row.get("clean_success"), bool):
            return int(bool(row["clean_success"]))
        if row.get("gt_valid") is True and isinstance(row.get("verifier_accepted"), bool):
            return int(bool(row["verifier_accepted"]))
        return None
    if metric == "metamorphic_violation":
        value = row.get("metamorphic_violation")
        return int(value) if isinstance(value, bool) else None
    if metric == "planted_sensitivity":
        if row.get("planted_present") is False or row.get("planted_positive") is False:
            return None
        for key in ("planted_detected", "detected_planted_exploit", "calibration_detected"):
            if isinstance(row.get(key), bool):
                return int(bool(row[key]))
        return None
    if metric == "planted_fpr":
        if row.get("planted_present") is True or row.get("planted_positive") is True:
            return None
        for key in ("planted_detected", "false_positive", "calibration_detected"):
            if isinstance(row.get(key), bool):
                return int(bool(row[key]))
        return None
    if metric == "deployment_outcome":
        value = row.get("deployment_outcome")
        return int(value) if isinstance(value, bool) else None
    raise ValueError(f"metric has no binary row contract: {metric!r}")


def _sampling_key(spec: EstimandSpec) -> str:
    return {
        "task": "task_id",
        "environment": "environment_id",
        "episode": "episode_id",
        "trajectory": "trajectory_id",
    }[spec.sampling_unit]


def _compile_binary_rate(
    spec: EstimandSpec,
    rows: list[dict[str, Any]],
    plan: StatsPlan,
) -> dict[str, Any]:
    values: list[tuple[dict[str, Any], int]] = []
    missing = 0
    for row in _rows_for_cohort(rows, spec.cohort):
        value = _binary_value(spec.metric, row)
        if value is None:
            missing += 1
            continue
        values.append((row, value))

    if missing and spec.missingness in {"fail_closed", "infra_as_indeterminate"}:
        return {
            "status": "indeterminate",
            "reason": "required_binary_observation_missing",
            "missing_rows": missing,
            "n": len(values),
            "inferential": spec.inference != "descriptive",
        }
    if not values:
        return {
            "status": "indeterminate",
            "reason": "zero_denominator",
            "missing_rows": missing,
            "n": 0,
            "inferential": spec.inference != "descriptive",
        }

    successes = sum(value for _, value in values)
    if spec.inference == "descriptive":
        result = _descriptive_rate(successes, len(values))
        result.update({"status": "estimated", "missing_rows": missing})
        return result

    assert spec.interval_method is not None
    assert spec.alpha is not None
    if spec.interval_method in {"wilson", "exact"}:
        result = _interval_rate(
            successes,
            len(values),
            method=spec.interval_method,
            alpha=spec.alpha,
        )
        result["missing_rows"] = missing
        return result

    if spec.interval_method == "cluster_bootstrap":
        key = _sampling_key(spec)
        clusters: dict[str, list[int]] = defaultdict(list)
        missing_key = 0
        for row, value in values:
            unit = row.get(key)
            if unit is None:
                missing_key += 1
                continue
            clusters[str(unit)].append(value)
        if missing_key or not clusters:
            return {
                "status": "indeterminate",
                "reason": "sampling_unit_key_missing",
                "sampling_unit_key": key,
                "missing_sampling_keys": missing_key,
                "n": len(values),
                "inferential": True,
            }
        interval = cluster_bootstrap(
            list(clusters.values()),
            alpha=spec.alpha,
            samples=int(plan.bootstrap_samples),
            seed=int(plan.bootstrap_seed),
        )
        return {
            "status": "estimated",
            "estimate": interval.estimate,
            "interval": interval.as_dict(),
            "interval_method": "cluster_bootstrap",
            "alpha": spec.alpha,
            "n": len(values),
            "n_clusters": interval.n,
            "sampling_unit_key": key,
            "missing_rows": missing,
            "inferential": True,
        }

    raise ValueError(f"unsupported rate interval method: {spec.interval_method!r}")


def _compile_paired_repair_delta(
    spec: EstimandSpec,
    rows: list[dict[str, Any]],
    plan: StatsPlan,
) -> dict[str, Any]:
    assert spec.contrast is not None
    assert spec.pairing_key is not None
    assert spec.alpha is not None
    before_name, after_name = spec.contrast
    pairs: dict[str, dict[str, int]] = defaultdict(dict)
    for row in rows:
        cohort = str(row.get("cohort") or "")
        if cohort not in {before_name, after_name}:
            continue
        pair_value = row.get(spec.pairing_key)
        if pair_value is None:
            continue
        attack_value = _binary_value("attack_success", row)
        if attack_value is not None:
            pairs[str(pair_value)][cohort] = attack_value

    before: list[float] = []
    after: list[float] = []
    for pair in pairs.values():
        if before_name in pair and after_name in pair:
            before.append(float(pair[before_name]))
            after.append(float(pair[after_name]))
    if not before:
        return {
            "status": "indeterminate",
            "reason": "no_complete_attack_success_pairs",
            "pairing_key": spec.pairing_key,
            "n_pairs": 0,
            "inferential": True,
        }
    interval = paired_bootstrap(
        after,
        before,
        samples=int(plan.bootstrap_samples),
        alpha=spec.alpha,
        seed=int(plan.bootstrap_seed),
    )
    if interval.n <= 0:
        return {
            "status": "indeterminate",
            "reason": "paired_bootstrap_unavailable",
            "pairing_key": spec.pairing_key,
            "n_pairs": 0,
            "inferential": True,
        }
    return {
        "status": "estimated",
        "estimate": interval.estimate,
        "interval": interval.as_dict(),
        "interval_method": "paired_bootstrap",
        "contrast": [before_name, after_name],
        "contrast_definition": "after_attack_success_minus_before_attack_success",
        "pairing_key": spec.pairing_key,
        "n_pairs": interval.n,
        "alpha": spec.alpha,
        "inferential": True,
    }


def _compile_time_to_exploit(spec: EstimandSpec, rows: list[dict[str, Any]]) -> dict[str, Any]:
    times: list[float] = []
    events: list[bool] = []
    missing = 0
    for row in _rows_for_cohort(rows, spec.cohort):
        raw_time = row.get("time_to_exploit")
        if raw_time is None:
            raw_time = row.get("queries_to_exploit")
        if raw_time is None:
            raw_time = row.get("queries_used")
        event = row.get("exploited")
        if not isinstance(event, bool):
            event = row.get("exploit") if isinstance(row.get("exploit"), bool) else None
        if raw_time is None or event is None:
            missing += 1
            continue
        try:
            times.append(float(raw_time))
        except (TypeError, ValueError):
            missing += 1
            continue
        events.append(bool(event))

    if missing and spec.missingness in {"fail_closed", "infra_as_indeterminate"}:
        return {
            "status": "indeterminate",
            "reason": "time_or_censoring_indicator_missing",
            "missing_rows": missing,
            "n": len(times),
            "inferential": True,
        }
    if not times:
        return {
            "status": "indeterminate",
            "reason": "no_time_to_exploit_observations",
            "n": 0,
            "inferential": True,
        }
    summary = time_to_exploit(times, exploited=events)
    survival = kaplan_meier_survival(times, exploited=events)
    return {
        "status": "estimated",
        "method": "kaplan_meier",
        "summary": summary,
        "survival": survival,
        "n": len(times),
        "n_events": sum(events),
        "n_censored": len(events) - sum(events),
        "missing_rows": missing,
        "inferential": True,
        "claim_boundary": (
            "censoring-aware Kaplan-Meier curve and median when identifiable; "
            "no unregistered hazard-model extrapolation"
        ),
    }


def _compile_estimand(
    spec: EstimandSpec,
    rows: list[Any],
    plan: StatsPlan,
    *,
    access_model: str,
) -> dict[str, Any]:
    filtered = _rows_for_split(rows, spec.split)
    metrics = compute_metrics_iter(filtered, access_model=access_model, pool_overall=False)
    base: dict[str, Any] = {
        "estimand_id": spec.estimand_id,
        "definition": spec.model_dump(mode="json"),
        "population_rows": len(filtered),
        "registration_role": spec.role,
    }

    if spec.metric == "optimization_gap":
        assert spec.contrast is not None
        if spec.inference == "interval":
            result = _compile_gap_interval(spec, rows, plan, access_model=access_model)
        else:
            result = _descriptive_gap(
                metrics.cohorts,
                ordinary=spec.contrast[0],
                optimized=spec.contrast[1],
            )
        base["result"] = result
        return base

    if spec.metric == "paired_repair_delta":
        base["result"] = _compile_paired_repair_delta(spec, filtered, plan)
        return base

    if spec.metric == "time_to_exploit":
        base["result"] = _compile_time_to_exploit(spec, filtered)
        return base

    if spec.metric in {
        "attack_success",
        "clean_success",
        "metamorphic_violation",
        "planted_sensitivity",
        "planted_fpr",
        "deployment_outcome",
    }:
        base["result"] = _compile_binary_rate(spec, filtered, plan)
        return base

    if spec.metric == "exploit_rate":
        numerator = sum(cohort.fp for cohort in metrics.cohorts.values())
        denominator = sum(cohort.fp + cohort.tn for cohort in metrics.cohorts.values())
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
        if spec.metric in {"cohort_far", "far"}:
            numerator = cohort.fp
            denominator = cohort.fp + cohort.tn
        elif spec.metric in {"cohort_frr", "frr"}:
            numerator = cohort.fn
            denominator = cohort.fn + cohort.tp
        else:
            raise ValueError(f"unsupported registered estimand metric: {spec.metric!r}")

    if spec.inference == "descriptive":
        result = _descriptive_rate(numerator, denominator)
        result["status"] = "estimated" if denominator else "indeterminate"
    else:
        assert spec.interval_method is not None
        assert spec.alpha is not None
        if spec.interval_method == "cluster_bootstrap":
            # FAR/FRR are already aggregated by CohortMetrics and cannot recover
            # task clusters from margins. Refuse to invent cluster structure.
            result = {
                "status": "indeterminate",
                "reason": "cluster_structure_not_recoverable_from_cohort_margins",
                "inferential": True,
                "interval_method": "cluster_bootstrap",
            }
        else:
            result = _interval_rate(
                numerator,
                denominator,
                method=spec.interval_method,
                alpha=spec.alpha,
            )
    base["result"] = result
    return base


def _validate_primary_family(
    plan: StatsPlan,
    registration: AnalysisPreregistration,
) -> dict[str, Any]:
    primary_interval = [
        item
        for item in registration.estimands
        if item.role == "primary" and item.inference in {"interval", "test", "equivalence"}
    ]
    if not primary_interval:
        raise ValueError(
            "pre_registered_primary requires at least one inferential primary estimand"
        )
    secondary_interval = [
        item.estimand_id
        for item in registration.estimands
        if item.role == "secondary" and item.inference != "descriptive"
    ]
    if secondary_interval:
        raise ValueError(
            "pre_registered_primary requires secondary estimands to be descriptive; "
            f"inferential secondary ids={sorted(secondary_interval)}"
        )
    if (
        any(
            item.interval_method in {"bootstrap", "cluster_bootstrap"}
            for item in primary_interval
        )
        and plan.bootstrap_samples <= 0
    ):
        raise ValueError("registered bootstrap intervals require bootstrap_samples > 0")

    allocated = {item.estimand_id: float(item.alpha or 0.0) for item in primary_interval}
    allocated_total = sum(allocated.values())
    if allocated_total > float(plan.alpha) + 1e-12:
        raise ValueError(
            "registered primary alpha allocation exceeds StatsPlan alpha: "
            f"allocated={allocated_total}, plan={plan.alpha}"
        )

    registration_multiplicity = registration.multiplicity
    if registration_multiplicity is not None and registration_multiplicity.policy == "bonferroni":
        expected = float(plan.alpha) / len(primary_interval)
        wrong = {
            estimand_id: alpha
            for estimand_id, alpha in allocated.items()
            if abs(alpha - expected) > 1e-12
        }
        if wrong:
            raise ValueError(
                "bonferroni preregistration requires equal primary alpha allocation: "
                f"expected={expected}, observed={wrong}"
            )

    return {
        "policy": "pre_registered_primary",
        "registration_multiplicity": (
            registration_multiplicity.model_dump(mode="json")
            if registration_multiplicity is not None
            else None
        ),
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
    """Compile the exact preregistered estimand family from result rows."""
    registration = plan.preregistration
    if plan.stopping_rule == "sequential_alpha":
        from verifierlab.statistics.sequential import require_sequential_plan

        stopping = plan.stopping_plan
        if stopping is None and registration is not None:
            stopping = registration.stopping_plan
        require_sequential_plan(stopping)
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

    total_n = sum(cohort.n for cohort in metrics.cohorts.values())
    total_fp = sum(cohort.fp for cohort in metrics.cohorts.values())
    total_far_denom = sum(cohort.fp + cohort.tn for cohort in metrics.cohorts.values())

    from verifierlab.statistics.plan import _censored_summary, validate_stats_report_schema

    payload: dict[str, Any] = {
        "schema_version": "5",
        "access_model": access_model,
        "stats_plan": plan.model_dump(mode="json"),
        "pool_overall": pool_overall,
        "cohorts": {
            name: _descriptive_cohort(cohort) for name, cohort in sorted(metrics.cohorts.items())
        },
        "optimization_gap": _descriptive_gap(metrics.cohorts),
        "stopping_rule": plan.stopping_rule,
        "multiple_comparison_policy": plan.multiple_comparison_policy,
        "multiplicity": multiplicity,
        "sample_size": total_n,
        "exploit_rate": _descriptive_rate(total_fp, total_far_denom),
        "censored": _censored_summary(rows),
        "negative_results_preserved": True,
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
