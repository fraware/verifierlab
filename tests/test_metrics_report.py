"""M1 metrics and report tests."""

from __future__ import annotations

from pathlib import Path

from verifierlab.reports import build_report, compute_metrics


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
    assert report.overall.fp == 2


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
    payload = build_report(run_dir)
    assert payload["exploit_count"] == 1
    assert (run_dir / "report" / "report.html").is_file()
    assert (run_dir / "report" / "report.json").is_file()
    assert (run_dir / "report" / "metrics.csv").is_file()
