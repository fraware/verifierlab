#!/usr/bin/env python3
"""Build a standardized reproducibility bundle from a sealed campaign run.

Usage:
  python scripts/build_repro_bundle.py --run-dir .valab/runs/<run-id> --out dist/repro-bundle
  python scripts/build_repro_bundle.py --run-dir ... --archive dist/repro-bundle.tgz

Excludes vault keys, unreleased labels, decrypt material, and confidential
trajectories that contain ground-truth fields.
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
from repro_bundle_layout import REQUIRED_FILES, validate_bundle_tree  # noqa: E402


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _safe_copy_text(src: Path | None, dest: Path, fallback: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if src is not None and src.is_file():
        dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    else:
        dest.write_text(fallback, encoding="utf-8")


def _public_adjudication_release(run_dir: Path) -> dict[str, Any]:
    """Public release record only — no label payloads."""
    tip = _read_json(run_dir / "tip_index.json") or {}
    sealed = _read_json(run_dir / "sealed_run.json") or {}
    release_marker = None
    for cand in (
        run_dir / "label_release.json",
        run_dir / "release.json",
        run_dir / "adjudication" / "release.json",
    ):
        payload = _read_json(cand)
        if payload:
            release_marker = {
                "path": cand.name,
                "keys": sorted(k for k in payload if k not in {"labels", "gt_valid", "vault"}),
                "content_digest": payload.get("content_digest"),
                "status": payload.get("status") or payload.get("kind"),
            }
            break
    return {
        "schema_version": "1",
        "kind": "adjudication_release_public",
        "run_id": tip.get("run_id") or sealed.get("run_id"),
        "campaign_digest": sealed.get("campaign_digest") or tip.get("campaign_digest"),
        "lifecycle": tip.get("lifecycle") or sealed.get("lifecycle"),
        "release_marker": release_marker,
        "note": "Hidden labels and vault material are excluded from this bundle.",
    }


def _query_ledger(run_dir: Path) -> dict[str, Any]:
    for cand in (
        run_dir / "ledger.json",
        run_dir / "spend.json",
        run_dir / "query_ledger.json",
        run_dir / "budget_ledger.json",
    ):
        payload = _read_json(cand)
        if payload:
            # Strip any accidental secrets.
            cleaned = {
                k: v
                for k, v in payload.items()
                if k not in {"vault_key", "decrypt_key", "private_key"}
            }
            return cleaned
    tip = _read_json(run_dir / "tip_index.json") or {}
    meta = tip.get("metadata") or {}
    return {
        "schema_version": "1",
        "kind": "query_ledger_summary",
        "ledger_digest": tip.get("ledger_digest") or meta.get("ledger_digest"),
        "note": "Full spend events unavailable; digest summary only.",
    }


def _stats_and_tables(run_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    report = _read_json(run_dir / "report.json") or {}
    tip = _read_json(run_dir / "tip_index.json") or {}
    meta = tip.get("metadata") or {}
    stats_plan = meta.get("stats_plan") or report.get("stats_plan") or {
        "methods": ["wilson"],
        "alpha": 0.05,
    }
    tables = {
        "schema_version": "1",
        "metrics": report.get("metrics"),
        "exploit_count": report.get("exploit_count"),
        "cohorts": (report.get("metrics") or {}).get("cohorts")
        if isinstance(report.get("metrics"), dict)
        else report.get("metrics"),
    }
    return stats_plan if isinstance(stats_plan, dict) else {"raw": stats_plan}, tables


def build_bundle(
    *,
    run_dir: Path,
    out_dir: Path,
    campaign_path: Path | None = None,
    package_version: str = "0.2.0rc2",
) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    out_dir = out_dir.resolve()
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    sealed = _read_json(run_dir / "sealed_run.json") or {}
    freeze = _read_json(run_dir / "freeze.json") or {}
    tip = _read_json(run_dir / "tip_index.json") or {}

    # Campaign plan (public YAML only).
    camp_src = campaign_path
    if camp_src is None:
        for cand in (run_dir / "campaign.yaml", run_dir / "campaign.yml"):
            if cand.is_file():
                camp_src = cand
                break
    camp_text = (
        camp_src.read_text(encoding="utf-8")
        if camp_src is not None and camp_src.is_file()
        else "# campaign plan unavailable in run dir\nname: unknown\n"
    )
    (out_dir / "campaign").mkdir(parents=True, exist_ok=True)
    (out_dir / "campaign" / "campaign_plan.yaml").write_text(camp_text, encoding="utf-8")

    # Profiles — prefer pack sidecars / sealed metadata; else synthesize.
    verifier_profile = {
        "schema_version": "1",
        "kind": "verifier_profile",
        "campaign_digest": sealed.get("campaign_digest"),
        "may_read_hidden_labels": False,
    }
    env_profile = {
        "schema_version": "1",
        "kind": "environment_profile",
        "campaign_digest": sealed.get("campaign_digest"),
    }
    _write_json(out_dir / "profiles" / "verifier.json", verifier_profile)
    _write_json(out_dir / "profiles" / "environment.json", env_profile)

    # Attack checkpoints (public state only).
    ckpt_dir = out_dir / "attacks" / "checkpoints"
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    (ckpt_dir / ".gitkeep").write_text("", encoding="utf-8")
    attackers = run_dir / "attackers"
    if attackers.is_dir():
        for path in attackers.rglob("checkpoint.json"):
            payload = _read_json(path)
            if not payload:
                continue
            # Drop any GT-ish keys.
            clean = {
                k: v
                for k, v in payload.items()
                if k not in {"gt_valid", "hidden_label", "ground_truth_label"}
            }
            rel = path.relative_to(attackers).as_posix().replace("/", "__")
            _write_json(ckpt_dir / rel, clean)

    _write_json(out_dir / "ledger" / "query_ledger.json", _query_ledger(run_dir))
    _write_json(
        out_dir / "freeze" / "freeze_record.json",
        freeze
        or {
            "schema_version": "1",
            "kind": "freeze",
            "note": "freeze.json missing from run dir",
            "sealed_present": bool(sealed),
        },
    )
    _write_json(
        out_dir / "adjudication" / "release_public.json",
        _public_adjudication_release(run_dir),
    )

    stats_plan, tables = _stats_and_tables(run_dir)
    analysis_manifest = {
        "schema_version": "1",
        "kind": "analysis_manifest",
        "run_id": tip.get("run_id") or sealed.get("run_id"),
        "campaign_digest": sealed.get("campaign_digest"),
        "report_present": (run_dir / "report.json").is_file(),
        "built_at": datetime.now(UTC).isoformat(),
    }
    _write_json(out_dir / "analysis" / "analysis_manifest.json", analysis_manifest)
    _write_json(out_dir / "analysis" / "stats_plan.json", stats_plan)
    _write_json(out_dir / "analysis" / "result_tables.json", tables)

    # Digests / locks / seeds / hardware.
    release_manifest = _read_json(REPO / "dist" / "release-manifest.json") or {
        "schema_version": "1",
        "project": "verifierlab",
        "version": package_version,
        "note": "release-manifest.json not present locally",
    }
    source_manifest = {
        "schema_version": "1",
        "kind": "source_manifest",
        "run_dir_name": run_dir.name,
        "sealed_run_digest": sealed.get("content_digest"),
        "freeze_digest": freeze.get("content_digest") if freeze else None,
        "package_version": package_version,
    }
    _write_json(out_dir / "digests" / "source_manifest.json", source_manifest)
    _write_json(out_dir / "digests" / "release_manifest.json", release_manifest)
    images = (release_manifest.get("images") or {}).get("images") or release_manifest.get(
        "images"
    )
    _write_json(
        out_dir / "digests" / "container_digests.json",
        {
            "schema_version": "1",
            "images": images or {},
            "note": "Digests filled after GHCR publish; null digests are not claims.",
        },
    )
    _write_json(
        out_dir / "locks" / "dependencies.lock.json",
        {
            "schema_version": "1",
            "python": platform.python_version(),
            "package": {"verifierlab": package_version},
            "pinned_hint": "Install the wheel/sdist matching digests/release_manifest.json",
        },
    )
    _write_json(
        out_dir / "seeds" / "seeds.json",
        {
            "schema_version": "1",
            "seed": (tip.get("metadata") or {}).get("seed"),
            "campaign_seed_note": "Use campaign_plan.yaml seed when present",
        },
    )
    _write_json(
        out_dir / "hardware" / "hardware.json",
        {
            "schema_version": "1",
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python": platform.python_version(),
            "system": platform.system(),
        },
    )

    citation = REPO / "CITATION.cff"
    citation_text = (
        citation.read_text(encoding="utf-8")
        if citation.is_file()
        else (
            "cff-version: 1.2.0\n"
            "title: VerifierLab\n"
            "message: If you use this software, please cite it.\n"
            f"version: {package_version}\n"
        )
    )
    (out_dir / "CITATION.cff").write_text(citation_text, encoding="utf-8")

    readme = (
        "# VerifierLab reproducibility bundle\n\n"
        "This archive contains **public** artifacts for independent verification.\n\n"
        "## Verify\n\n"
        "```bash\n./verify.sh\n```\n\n"
        "## Reproduce (offline)\n\n"
        "```bash\n./reproduce.sh\n```\n\n"
        "## Exclusions\n\n"
        "- Vault keys and decrypt material\n"
        "- Unreleased / private labels\n"
        "- Confidential trajectories containing ground truth\n"
        "- Secrets and private keys\n"
    )
    (out_dir / "README.md").write_text(readme, encoding="utf-8")

    verify_sh = """#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
test -f MANIFEST.json
test -f CITATION.cff
test -f campaign/campaign_plan.yaml
test -f freeze/freeze_record.json
test -f adjudication/release_public.json
python - <<'PY'
import json
from pathlib import Path
manifest = json.loads(Path("MANIFEST.json").read_text(encoding="utf-8"))
missing = [m for m in manifest.get("members", []) if not Path(m).exists()]
# .gitkeep optional if checkpoints dir has other files
missing = [m for m in missing if not (m.endswith(".gitkeep") and Path(m).parent.is_dir())]
if missing:
    raise SystemExit(f"missing members: {missing}")
print("verify ok")
PY
"""
    reproduce_sh = """#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
echo "Reproduce using pinned verifierlab from digests/release_manifest.json"
echo "1. Create a clean venv and install the matching wheel"
echo "2. valab campaign validate campaign/campaign_plan.yaml"
echo "3. Re-run with seeds/seeds.json and compare analysis/result_tables.json"
./verify.sh
"""
    (out_dir / "verify.sh").write_text(verify_sh, encoding="utf-8")
    (out_dir / "reproduce.sh").write_text(reproduce_sh, encoding="utf-8")

    members = sorted(
        p.relative_to(out_dir).as_posix() for p in out_dir.rglob("*") if p.is_file()
    )
    if "MANIFEST.json" not in members:
        members = sorted([*members, "MANIFEST.json"])
    manifest = {
        "schema_version": "1",
        "kind": "repro_bundle_manifest",
        "created_at": datetime.now(UTC).isoformat(),
        "package_version": package_version,
        "run_id": tip.get("run_id") or sealed.get("run_id"),
        "campaign_digest": sealed.get("campaign_digest"),
        "members": members,
        "required_layout": list(REQUIRED_FILES),
        "exclusions": [
            "vault keys",
            "unreleased labels",
            "confidential trajectories with gt_valid",
            "secrets",
        ],
    }
    _write_json(out_dir / "MANIFEST.json", manifest)

    validation = validate_bundle_tree(out_dir)
    return {"out_dir": str(out_dir), "validation": validation, "manifest": manifest}


def _archive_tgz(src: Path, archive: Path) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(src, arcname=src.name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=REPO / "dist" / "repro-bundle")
    parser.add_argument("--archive", type=Path, default=None, help="Optional .tgz path")
    parser.add_argument("--campaign", type=Path, default=None)
    parser.add_argument("--package-version", default="0.2.0rc2")
    args = parser.parse_args(argv)

    if not args.run_dir.is_dir():
        print(f"run dir not found: {args.run_dir}", file=sys.stderr)
        return 2

    result = build_bundle(
        run_dir=args.run_dir,
        out_dir=args.out,
        campaign_path=args.campaign,
        package_version=args.package_version,
    )
    validation = result["validation"]
    print(json.dumps({"out_dir": result["out_dir"], "ok": validation["ok"]}, indent=2))
    if not validation["ok"]:
        print(json.dumps(validation, indent=2, sort_keys=True), file=sys.stderr)
        print("FAIL: bundle layout validation", file=sys.stderr)
        return 1

    if args.archive is not None:
        _archive_tgz(Path(result["out_dir"]), args.archive.resolve())
        print(f"wrote archive {args.archive}")
    print("OK: reproducibility bundle built", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
