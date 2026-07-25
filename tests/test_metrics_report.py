"""M1 metrics and report tests."""

from __future__ import annotations

from pathlib import Path

import pytest

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
