"""M1 metrics and report tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from verifierlab.config.campaign import StatsPlan
from verifierlab.reports import MetricsIngestError, build_report, compute_metrics


def test_compute_metrics_stratified() -> None:
    rows = [
        {"cohort": "ordinary", "verifier_accepted": True, "gt_valid": True},
        {"cohort": "ordinary", "verifier_accepted": False, "gt_valid": False},
        {"cohort": "optimized", "verifier_accepted": True, "gt_valid": False},
        {"cohort": "optimized", "verifier_accepted": True, "gt_valid": False},
    ]
    report = compute_metrics(rows, access_model="black-box")
    assert report.cohorts["optimized"].fp == 2
    assert report.cohorts["optimized"].far == 1.0
    assert report.overall.n == 0  # no default overall pooling
    assert report.as_dict()["overall"] is None

    pooled = compute_metrics(rows, access_model="black-box", pool_overall=True)
    assert pooled.overall.fp == 2


def test_compute_metrics_reject_string_not_accept() -> None:
    """VAL-C13: string labels must not be truthiness-coerced into accepts."""
    assert bool("reject") is True
    assert bool("false") is True

    rows = [
        {"cohort": "ordinary", "verifier_accepted": "reject", "gt_valid": False},
        {"cohort": "ordinary", "verifier_accepted": "false", "gt_valid": False},
    ]
    report = compute_metrics(rows, access_model="black-box", pool_overall=True)
    assert report.cohorts["ordinary"].tn == 2
    assert report.cohorts["ordinary"].fp == 0
    assert report.overall.fp == 0


def test_compute_metrics_invalid_label_fail_closed() -> None:
    with pytest.raises(MetricsIngestError, match="truthiness"):
        compute_metrics(
            [{"cohort": "ordinary", "verifier_accepted": "not-a-label", "gt_valid": True}],
            access_model="black-box",
        )
    with pytest.raises(MetricsIngestError, match="truthiness"):
        compute_metrics(
            [{"cohort": "ordinary", "verifier_accepted": True, "gt_valid": 1}],
            access_model="black-box",
        )


def test_build_report(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    wu = run_dir / "work_units"
    wu.mkdir(parents=True)
    (wu / "u0.json").write_text(
        '{"unit_id":"u0","cohort":"optimized","verifier_accepted":true,"gt_valid":false}\n',
        encoding="utf-8",
    )
    (run_dir / "manifest.json").write_text(
        '{"run_id":"r1","run_digest":"abc","metadata":{"access_model":"black-box"}}\n',
        encoding="utf-8",
    )
    payload = build_report(run_dir, require_labels_released=False)
    assert payload["exploit_count"] == 1
    assert (run_dir / "report" / "report.html").is_file()
    assert (run_dir / "report" / "report.json").is_file()
    assert (run_dir / "report" / "metrics.csv").is_file()


def test_build_report_preregistered_rate_shape(tmp_path: Path) -> None:
    run_dir = tmp_path / "registered"
    rows = [
        {
            "unit_id": "u0",
            "cohort": "optimized",
            "access_model": "black-box",
            "verifier_accepted": True,
            "gt_valid": False,
        },
        {
            "unit_id": "u1",
            "cohort": "optimized",
            "access_model": "black-box",
            "verifier_accepted": False,
            "gt_valid": False,
        },
    ]
    plan = StatsPlan.model_validate(
        {
            "methods": ["wilson"],
            "alpha": 0.05,
            "stopping_rule": "fixed_n",
            "multiple_comparison_policy": "pre_registered_primary",
            "preregistration": {
                "schema_version": "1",
                "registration_id": "report-rate-shape",
                "estimands": [
                    {
                        "estimand_id": "far_optimized",
                        "metric": "cohort_far",
                        "role": "primary",
                        "inference": "interval",
                        "cohort": "optimized",
                        "interval_method": "wilson",
                        "alpha": 0.05,
                        "direction": "higher_is_worse",
                    }
                ],
                "assumptions": ["test fixture only"],
            },
        }
    )
    payload = build_report(
        run_dir,
        results=rows,
        access_model="black-box",
        require_labels_released=False,
        stats_plan=plan,
    )
    registered = payload["metrics"]["registered_estimands"]["far_optimized"]["result"]
    assert registered["estimate"] == 0.5
    assert registered["interval"]["method"] == "wilson"
    html = (run_dir / "report" / "report.html").read_text(encoding="utf-8")
    assert "0.5000" in html
    assert "(wilson)" in html
    csv_text = (run_dir / "report" / "metrics.csv").read_text(encoding="utf-8")
    assert "optimized,2,0.5" in csv_text
    assert "{'estimate'" not in csv_text
