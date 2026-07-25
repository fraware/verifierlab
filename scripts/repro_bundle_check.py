#!/usr/bin/env python3
"""Reproducible campaign bundle check for science-facing parity.

Raw ``run_digest`` / work-unit digests intentionally include per-run commitment
nonces, so this script compares **campaign digest + post-release science
artifacts** (status, exploit taxonomies, stratified metrics) across two clean
workspaces.

Usage:
  uv run python scripts/repro_bundle_check.py campaigns/fake-smoke.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from verifierlab.campaigns.engine import (
    adjudicate_campaign,
    freeze_run,
    init_workspace,
    release_labels,
    run_campaign,
)
from verifierlab.reports import build_report


def _taxonomies(run_dir: Path) -> list[str]:
    found: set[str] = set()
    adj = run_dir / "adjudications"
    if not adj.is_dir():
        return []
    for path in adj.glob("*.json"):
        row = json.loads(path.read_text(encoding="utf-8"))
        exploit = row.get("exploit")
        if isinstance(exploit, dict) and exploit.get("taxonomy"):
            found.add(str(exploit["taxonomy"]))
    return sorted(found)


def _metrics_fingerprint(report: dict[str, Any]) -> dict[str, Any]:
    metrics = report.get("metrics") or {}
    # Keep only stable stratified fields (drop sample noise / timestamps).
    out: dict[str, Any] = {}
    for key, value in sorted(metrics.items()):
        if not isinstance(value, dict):
            continue
        out[key] = {
            k: value.get(k)
            for k in ("far", "frr", "n", "fp", "fn", "tp", "tn", "abstentions", "missing")
            if k in value
        }
    return out


def _run_once(campaign: Path, root: Path) -> dict[str, Any]:
    workspace = init_workspace(root / ".valab")
    result = run_campaign(
        campaign,
        workspace=workspace,
        max_workers=2,
        use_processes=False,
    )
    freeze_run(result.run_dir)
    adjudicate_campaign(result.run_dir, campaign_path=campaign)
    release_labels(result.run_dir)
    report = build_report(result.run_dir)
    return {
        "campaign_digest": result.manifest.campaign_digest,
        "status": result.manifest.status,
        "exploit_count": report.get("exploit_count"),
        "taxonomies": _taxonomies(result.run_dir),
        "metrics": _metrics_fingerprint(report),
        # Informative only — may differ across runs due to commitment nonces.
        "run_digest": result.run_digest,
        "work_unit_digest_count": len(result.manifest.work_unit_digests or []),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path, help="Campaign YAML path")
    args = parser.parse_args(argv)
    campaign = args.campaign.resolve()
    if not campaign.is_file():
        print(f"campaign not found: {campaign}", file=sys.stderr)
        return 2

    with (
        tempfile.TemporaryDirectory(prefix="valab-repro-a-") as a,
        tempfile.TemporaryDirectory(prefix="valab-repro-b-") as b,
    ):
        first = _run_once(campaign, Path(a))
        second = _run_once(campaign, Path(b))

    keys = ("campaign_digest", "status", "exploit_count", "taxonomies", "metrics")
    mismatch = {k: (first.get(k), second.get(k)) for k in keys if first.get(k) != second.get(k)}
    payload = {
        "first": first,
        "second": second,
        "mismatch": mismatch,
        "note": "run_digest may differ (commitment nonces); science keys must match",
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    if mismatch:
        print("FAIL: reproducible science artifacts diverged", file=sys.stderr)
        return 1
    if first.get("work_unit_digest_count") != second.get("work_unit_digest_count"):
        print("FAIL: work unit counts diverged", file=sys.stderr)
        return 1
    print("OK: reproducible campaign science artifacts match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
