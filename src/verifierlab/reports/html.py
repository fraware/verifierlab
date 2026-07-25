"""Static HTML assurance reports from immutable run artifacts."""

from __future__ import annotations

import csv
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from jinja2 import Template

from verifierlab.artifacts.records import AssuranceReport
from verifierlab.config.campaign import StatsPlan
from verifierlab.security.secrets import assert_no_secrets, scan_for_secrets
from verifierlab.statistics.plan import compile_stats_plan

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
     · access <code>{{ access_model }}</code>
     · StatsPlan <code>{{ stats_methods }}</code> alpha={{ alpha }}</p>
  {% if overall %}
  <h2>Overall <span class="meta">(explicitly pooled)</span></h2>
  <table>
    <tr><th>n</th><th>FAR</th><th>FAR CI</th><th>FRR</th><th>FRR CI</th><th>Missing</th></tr>
    <tr>
      <td>{{ overall.n }}</td>
      <td class="fp">{{ fmt(overall.far) }}</td>
      <td>{{ fmt_ci(overall.far_ci) }}</td>
      <td>{{ fmt(overall.frr) }}</td>
      <td>{{ fmt_ci(overall.frr_ci) }}</td>
      <td>{{ overall.missing }} ({{ fmt(overall.missingness) }})</td>
    </tr>
  </table>
  {% else %}
  <h2>Overall</h2>
  <p class="meta">Cohort pooling disabled by default (VAL-C14). Primary estimands are per-cohort.</p>
  {% endif %}
  <h2>By cohort</h2>
  <table>
    <tr><th>Cohort</th><th>n</th><th>FAR</th><th>FAR CI</th><th>FAR denom</th>
        <th>FRR</th><th>FRR CI</th><th>Missing</th></tr>
    {% for c in cohorts %}
    <tr>
      <td>{{ c.cohort }}</td>
      <td>{{ c.n }}</td>
      <td class="fp">{{ fmt(c.far) }}</td>
      <td>{{ fmt_ci(c.far_ci) }}</td>
      <td>{{ c.denominators.far }}</td>
      <td>{{ fmt(c.frr) }}</td>
      <td>{{ fmt_ci(c.frr_ci) }}</td>
      <td>{{ c.missing }} ({{ fmt(c.missingness) }})</td>
    </tr>
    {% endfor %}
  </table>
  {% if gap %}
  <h2>Optimization gap</h2>
  <p>FAR(optimized) - FAR(ordinary) = <code>{{ fmt(gap.gap) }}</code>
     · policy: {{ gap.multiplicity_policy }}</p>
  {% endif %}
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


def _fmt_ci(ci: dict[str, Any] | None) -> str:
    if not ci:
        return "—"
    intervals = ci.get("intervals") or {}
    for method in ("wilson", "exact"):
        iv = intervals.get(method)
        if iv:
            return f"[{iv['low']:.4f}, {iv['high']:.4f}] ({method})"
    if intervals:
        iv = next(iter(intervals.values()))
        return f"[{iv['low']:.4f}, {iv['high']:.4f}]"
    return "—"


def _load_stats_plan(run_dir: Path, manifest: dict[str, Any]) -> StatsPlan:
    """Resolve StatsPlan from campaign CAS tip or defaults."""
    meta = manifest.get("metadata") or {}
    if isinstance(meta.get("stats_plan"), dict):
        return StatsPlan.model_validate(meta["stats_plan"])
    # Try campaign digest in store.
    dig = manifest.get("campaign_digest")
    if dig:
        try:
            from verifierlab.artifacts.cas import ContentAddressedStore

            ws = run_dir.parent.parent
            store = ContentAddressedStore(ws / "store")
            raw = store.get_json(str(dig))
            if isinstance(raw.get("stats_plan"), dict):
                return StatsPlan.model_validate(raw["stats_plan"])
        except Exception:
            pass
    return StatsPlan()


def build_report(
    run_dir: Path,
    *,
    results: list[dict[str, Any]] | None = None,
    access_model: str | None = None,
    run_id: str | None = None,
    run_digest: str | None = None,
    require_labels_released: bool = True,
    stats_plan: StatsPlan | None = None,
    pool_overall: bool = False,
) -> dict[str, Any]:
    """Write HTML + JSON + CSV sidecars under ``run_dir/report/``.

    Driven by declared :class:`StatsPlan` (VAL-R12). Overall pooling is off
    by default (VAL-C14).
    """
    run_dir = Path(run_dir)
    manifest = {}
    manifest_path = run_dir / "manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    run_id = run_id or str(manifest.get("run_id") or run_dir.name)
    run_digest = run_digest or str(manifest.get("tip_digest") or manifest.get("run_digest") or "")
    meta = manifest.get("metadata") or {}

    if require_labels_released and results is None:
        from verifierlab.campaigns.lifecycle import labels_released

        if not labels_released(run_dir):
            raise PermissionError(
                "report blocked until labels are released "
                "(valab campaign freeze → adjudicate → release-labels)"
            )

    resolved_access = access_model or meta.get("access_model")
    if not resolved_access and results:
        resolved_access = results[0].get("access_model")
    if not resolved_access:
        for row in iter_work_unit_rows(run_dir):
            resolved_access = row.get("access_model")
            break
    access_model = str(resolved_access or "black-box")
    plan = stats_plan or _load_stats_plan(run_dir, manifest)

    rows_list = list(results) if results is not None else list(iter_work_unit_rows(run_dir))
    exploit_unit_ids: list[str] = []
    cleaned: list[dict[str, Any]] = []
    for row in rows_list:
        hits = scan_for_secrets(row)
        if hits:
            raise ValueError(f"secret patterns detected in work-unit {row.get('unit_id')}: {hits}")
        if row.get("verifier_accepted") is True and row.get("gt_valid") is False:
            exploit_unit_ids.append(str(row.get("unit_id") or ""))
        cleaned.append(row)

    stats = compile_stats_plan(
        cleaned,
        plan=plan,
        access_model=access_model,
        pool_overall=pool_overall,
    )
    out_dir = run_dir / "report"
    out_dir.mkdir(parents=True, exist_ok=True)

    report = AssuranceReport(
        run_id=run_id,
        run_digest=run_digest,
        access_model=access_model,
        metrics=stats,
        exploit_count=len(exploit_unit_ids),
        exploit_unit_ids=exploit_unit_ids,
        metadata={
            "stats_plan": plan.model_dump(mode="json"),
            "pool_overall": pool_overall,
            "primary_estimands": stats.get("primary_estimands"),
            "assurance_grade": (
                "research_ungated" if not require_labels_released else "post_release"
            ),
            "labels_release_required": require_labels_released,
        },
    )
    payload = report.model_dump(mode="json")
    if not require_labels_released:
        payload["assurance_disclaimer"] = (
            "NON-ASSURANCE: report built with require_labels_released=False; "
            "not a scientific release artifact."
        )
    assert_no_secrets(payload)
    (out_dir / "report.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "stats.json").write_text(
        json.dumps(stats, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    cohorts = list((stats.get("cohorts") or {}).values())
    html = REPORT_TEMPLATE.render(
        run_id=run_id,
        run_digest=run_digest,
        access_model=access_model,
        overall=stats.get("overall"),
        cohorts=cohorts,
        gap=stats.get("optimization_gap"),
        exploit_count=len(exploit_unit_ids),
        report_version=report.report_version,
        stats_methods=",".join(plan.methods),
        alpha=plan.alpha,
        fmt=_fmt,
        fmt_ci=_fmt_ci,
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
            "far_denom",
            "frr_denom",
            "far_ci_low",
            "far_ci_high",
            "frr_ci_low",
            "frr_ci_high",
            "abstentions",
            "abstention_rate",
            "missing",
            "missingness",
            "failed",
        ]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()

        def _row(c: dict[str, Any]) -> dict[str, Any]:
            far_iv = ((c.get("far_ci") or {}).get("intervals") or {}).get("wilson") or {}
            frr_iv = ((c.get("frr_ci") or {}).get("intervals") or {}).get("wilson") or {}
            den = c.get("denominators") or {}
            return {
                "cohort": c.get("cohort"),
                "n": c.get("n"),
                "far": c.get("far"),
                "frr": c.get("frr"),
                "fp": c.get("fp"),
                "fn": c.get("fn"),
                "tp": c.get("tp"),
                "tn": c.get("tn"),
                "far_denom": den.get("far"),
                "frr_denom": den.get("frr"),
                "far_ci_low": far_iv.get("low"),
                "far_ci_high": far_iv.get("high"),
                "frr_ci_low": frr_iv.get("low"),
                "frr_ci_high": frr_iv.get("high"),
                "abstentions": c.get("abstentions"),
                "abstention_rate": c.get("abstention_rate"),
                "missing": c.get("missing"),
                "missingness": c.get("missingness"),
                "failed": c.get("failed"),
            }

        if stats.get("overall"):
            writer.writerow(_row(stats["overall"]))
        for c in cohorts:
            writer.writerow(_row(c))

    return payload


def iter_work_unit_rows(run_dir: Path) -> Iterator[dict[str, Any]]:
    """Yield work-unit JSON rows without materializing the full list.

    Prefers post-release analysis copies (with ``gt_valid``) when present;
    otherwise streams attack-plane work units.
    """
    run_dir = Path(run_dir)
    analysis = run_dir / "analysis" / "work_units"
    wu_dir = (
        analysis if analysis.is_dir() and any(analysis.glob("*.json")) else run_dir / "work_units"
    )
    if not wu_dir.is_dir():
        return
    for path in sorted(wu_dir.glob("*.json")):
        yield json.loads(path.read_text(encoding="utf-8"))


def _load_results(run_dir: Path) -> list[dict[str, Any]]:
    return list(iter_work_unit_rows(run_dir))
