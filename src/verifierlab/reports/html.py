"""Static HTML assurance reports from immutable run artifacts."""

from __future__ import annotations

import csv
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from jinja2 import Template

from verifierlab.artifacts.records import AssuranceReport
from verifierlab.reports.metrics import MetricsReport, compute_metrics_iter
from verifierlab.security.secrets import assert_no_secrets, scan_for_secrets

REPORT_TEMPLATE = Template(
    """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>VerifierLab Assurance Report — {{ run_id }}</title>
  <style>
    :root { --ink:#1a1a1a; --muted:#555; --line:#ddd; --bg:#fafafa; --accent:#0b5; }
    body { font-family: "IBM Plex Sans", "Segoe UI", sans-serif; color:var(--ink);
           background:linear-gradient(180deg,#f3f6f4 0%,#fafafa 40%); margin:0; padding:2rem; }
    main { max-width:960px; margin:0 auto; }
    h1 { font-size:1.6rem; letter-spacing:-0.02em; margin-bottom:0.25rem; }
    .meta { color:var(--muted); margin-bottom:1.5rem; }
    table { border-collapse:collapse; width:100%; background:#fff; }
    th, td { border:1px solid var(--line); padding:0.5rem 0.75rem; text-align:left; }
    th { background:#f0f3f1; }
    .fp { color:#a30; font-weight:600; }
    code { font-family:"IBM Plex Mono", Consolas, monospace; font-size:0.9em; }
  </style>
</head>
<body>
<main>
  <h1>Assurance Report</h1>
  <p class="meta">Run <code>{{ run_id }}</code> · digest <code>{{ run_digest }}</code>
     · access <code>{{ access_model }}</code></p>
  <h2>Overall</h2>
  <table>
    <tr><th>n</th><th>FAR</th><th>FRR</th><th>FP</th><th>FN</th><th>Abstention</th></tr>
    <tr>
      <td>{{ overall.n }}</td>
      <td class="fp">{{ fmt(overall.far) }}</td>
      <td>{{ fmt(overall.frr) }}</td>
      <td class="fp">{{ overall.fp }}</td>
      <td>{{ overall.fn }}</td>
      <td>{{ fmt(overall.abstention_rate) }}</td>
    </tr>
  </table>
  <h2>By cohort</h2>
  <table>
    <tr><th>Cohort</th><th>n</th><th>FAR</th><th>FRR</th><th>FP</th><th>FN</th></tr>
    {% for c in cohorts %}
    <tr>
      <td>{{ c.cohort }}</td>
      <td>{{ c.n }}</td>
      <td class="fp">{{ fmt(c.far) }}</td>
      <td>{{ fmt(c.frr) }}</td>
      <td class="fp">{{ c.fp }}</td>
      <td>{{ c.fn }}</td>
    </tr>
    {% endfor %}
  </table>
  <h2>Exploits</h2>
  <p>{{ exploit_count }} exploit case(s) recorded (accept ∧ invalid).</p>
  <p class="meta">Rebuilt offline from immutable artifacts. Report format v{{ report_version }}.</p>
</main>
</body>
</html>
"""
)


def _fmt(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{value:.4f}"


def build_report(
    run_dir: Path,
    *,
    results: list[dict[str, Any]] | None = None,
    access_model: str | None = None,
    run_id: str | None = None,
    run_digest: str | None = None,
) -> dict[str, Any]:
    """Write HTML + JSON + CSV sidecars under ``run_dir/report/``."""
    run_dir = Path(run_dir)
    manifest = {}
    manifest_path = run_dir / "manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    run_id = run_id or str(manifest.get("run_id") or run_dir.name)
    run_digest = run_digest or str(manifest.get("run_digest") or "")
    meta = manifest.get("metadata") or {}
    # Prefer explicit arg, then manifest metadata, then first work-unit row.
    resolved_access = access_model or meta.get("access_model")
    if not resolved_access and results:
        resolved_access = results[0].get("access_model")
    if not resolved_access:
        # Peek one work unit without loading the full campaign into memory.
        for row in iter_work_unit_rows(run_dir):
            resolved_access = row.get("access_model")
            break
    access_model = str(resolved_access or "black-box")

    source: Iterator[dict[str, Any]] = (
        iter(results) if results is not None else iter_work_unit_rows(run_dir)
    )

    # Stream metrics; collect only exploit unit ids (not full trajectories).
    exploit_unit_ids: list[str] = []

    def _rows() -> Iterator[dict[str, Any]]:
        for row in source:
            hits = scan_for_secrets(row)
            if hits:
                raise ValueError(
                    f"secret patterns detected in work-unit {row.get('unit_id')}: {hits}"
                )
            if row.get("verifier_accepted") is True and row.get("gt_valid") is False:
                exploit_unit_ids.append(str(row.get("unit_id") or ""))
            yield row

    metrics: MetricsReport = compute_metrics_iter(_rows(), access_model=access_model)
    out_dir = run_dir / "report"
    out_dir.mkdir(parents=True, exist_ok=True)

    report = AssuranceReport(
        run_id=run_id,
        run_digest=run_digest,
        access_model=access_model,
        metrics=metrics.as_dict(),
        exploit_count=len(exploit_unit_ids),
        exploit_unit_ids=exploit_unit_ids,
    )
    payload = report.model_dump(mode="json")
    assert_no_secrets(payload)
    (out_dir / "report.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    html = REPORT_TEMPLATE.render(
        run_id=run_id,
        run_digest=run_digest,
        access_model=access_model,
        overall=metrics.overall,
        cohorts=list(metrics.cohorts.values()),
        exploit_count=len(exploit_unit_ids),
        report_version=report.report_version,
        fmt=_fmt,
    )
    (out_dir / "report.html").write_text(html, encoding="utf-8")

    with (out_dir / "metrics.csv").open("w", encoding="utf-8", newline="") as fh:
        fieldnames = [
            "cohort",
            "n",
            "far",
            "frr",
            "fp",
            "fn",
            "tp",
            "tn",
            "abstentions",
            "abstention_rate",
            "missing",
            "missingness",
            "failed",
        ]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(metrics.overall.as_dict())
        for c in metrics.cohorts.values():
            writer.writerow(c.as_dict())

    return payload


def iter_work_unit_rows(run_dir: Path) -> Iterator[dict[str, Any]]:
    """Yield work-unit JSON rows without materializing the full list."""
    wu_dir = Path(run_dir) / "work_units"
    if not wu_dir.is_dir():
        return
    for path in sorted(wu_dir.glob("*.json")):
        yield json.loads(path.read_text(encoding="utf-8"))


def _load_results(run_dir: Path) -> list[dict[str, Any]]:
    return list(iter_work_unit_rows(run_dir))
