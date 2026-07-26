#!/usr/bin/env python3
"""Generate ``release-manifest.json`` for a VerifierLab release.

Fields (Milestone A2):
  project, version, tag, commit; wheel/sdist digests; campaign / verifier-profile /
  decision / plugin schemas; Python versions; adapter matrix versions; image digests;
  pack IDs; repro bundle pointer; isolation mode; known limitations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_commit(explicit: str | None) -> str:
    if explicit:
        return explicit
    env = os.environ.get("GITHUB_SHA") or os.environ.get("GIT_COMMIT")
    if env:
        return env
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO,
            text=True,
            stderr=subprocess.DEVNULL,
        )
        return out.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _read_version() -> str:
    data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def _artifact_digests(dist_dir: Path) -> dict[str, Any]:
    wheels = sorted(dist_dir.glob("verifierlab-*.whl"))
    sdists = sorted(dist_dir.glob("verifierlab-*.tar.gz"))
    out: dict[str, Any] = {"wheel": None, "sdist": None}
    if wheels:
        wheel = wheels[0]
        out["wheel"] = {
            "path": wheel.name,
            "sha256": _sha256(wheel),
            "size": wheel.stat().st_size,
        }
    if sdists:
        sdist = sdists[0]
        out["sdist"] = {
            "path": sdist.name,
            "sha256": _sha256(sdist),
            "size": sdist.stat().st_size,
        }
    return out


def _pack_ids() -> list[str]:
    packs = REPO / "campaigns" / "packs"
    if not packs.is_dir():
        return []
    ids: list[str] = []
    for path in sorted(packs.glob("pack-*.yaml")):
        ids.append(path.stem)
    return ids


def _schema_inventory() -> dict[str, Any]:
    """Document schema versions used by public contracts (no separate schema/ tree yet)."""
    return {
        "campaign": {"schema_version": "1", "loader": "verifierlab.config.campaign"},
        "verifier_profile": {
            "schema_version": "1",
            "model": "verifierlab.verifiers.profile.VerifierProfile",
        },
        "decision": {
            "schema_version": "1",
            "model": "verifierlab.api.decision.Decision",
            "status_set": ["accept", "reject", "abstain", "indeterminate", "error"],
        },
        "plugin": {
            "entry_points": [
                "verifierlab.plugins",
                "verifierlab.transcript_auditors",
            ],
            "note": "Plugin registry JSON arrives in Milestone E; entry points are the current contract.",
        },
    }


def _adapter_matrix() -> list[dict[str, Any]]:
    """Honest live-vs-fixture matrix from registry (Milestone D4)."""
    path = REPO / "registry" / "adapter-matrix-v1.json"
    if path.is_file():
        raw = json.loads(path.read_text(encoding="utf-8"))
        rows = raw.get("adapters") or []
        if isinstance(rows, list) and rows:
            return rows
    # Fallback if registry is missing (should not happen in-tree).
    return [
        {
            "adapter": "native",
            "extra": None,
            "status": "live",
            "versions": {"python": ">=3.11,<3.14"},
            "ci": "required",
        },
        {
            "adapter": "envassure",
            "extra": "envassure",
            "status": "not-live",
            "versions": {"envassure": ">=0.2.0b1,<0.3"},
            "ci": "hard-fail-when-installable",
            "note": "Never claim live from fixtures.",
        },
        {
            "adapter": "rllib",
            "extra": "rllib",
            "status": "partial",
            "versions": {"ray[rllib]": "==2.48.0"},
            "ci": "skip-if-missing",
            "note": "Integration conformance only.",
        },
    ]


def _image_digests() -> dict[str, Any]:
    """Placeholder image coordinates; digests filled after GHCR publish."""
    version = _read_version()
    return {
        "registry": "ghcr.io/fraware",
        "images": {
            "cli": {
                "ref": f"ghcr.io/fraware/verifierlab-cli:{version}",
                "digest": None,
                "status": "dockerfile-ready",
            },
            "worker": {
                "ref": f"ghcr.io/fraware/verifierlab-worker:{version}",
                "digest": None,
                "status": "dockerfile-ready",
            },
            "adjudicator": {
                "ref": f"ghcr.io/fraware/verifierlab-adjudicator:{version}",
                "digest": None,
                "status": "dockerfile-ready",
            },
            "rllib": {
                "ref": f"ghcr.io/fraware/verifierlab-rllib:{version}",
                "digest": None,
                "status": "partial-qualification",
                "claim": "integration_conformance",
            },
        },
    }


def _limitations_excerpt() -> list[str]:
    path = REPO / "docs" / "limitations.md"
    if not path.is_file():
        return ["See docs/limitations.md"]
    text = path.read_text(encoding="utf-8")
    bullets: list[str] = []
    for line in text.splitlines():
        if line.startswith("| ") and "Reality today" not in line and "----" not in line:
            # Grab thin/non-claim rows from tables when present.
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) >= 2 and cells[0] and cells[1]:
                bullets.append(f"{cells[0]}: {cells[1]}")
        if len(bullets) >= 12:
            break
    if not bullets:
        bullets.append("See docs/limitations.md for honest non-claims.")
    return bullets


def build_manifest(
    *,
    dist_dir: Path,
    tag: str | None,
    commit: str | None,
) -> dict[str, Any]:
    version = _read_version()
    resolved_tag = tag or os.environ.get("RELEASE_TAG") or f"v{version}"
    requires = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    python_requires = str(requires["project"].get("requires-python", ">=3.11"))
    return {
        "schema_version": "1",
        "generated_at": datetime.now(UTC).isoformat(),
        "project": "verifierlab",
        "version": version,
        "tag": resolved_tag,
        "commit": _git_commit(commit),
        "artifacts": _artifact_digests(dist_dir),
        "schemas": _schema_inventory(),
        "python": {
            "requires": python_requires,
            "tested": ["3.11", "3.12", "3.13"],
        },
        "adapter_matrix": _adapter_matrix(),
        "images": _image_digests(),
        "packs": {"ids": _pack_ids()},
        "repro_bundle": {
            "pointer": None,
            "layout": "scripts/repro_bundle_layout.py",
            "build": "scripts/build_repro_bundle.py --run-dir <sealed-run> --out dist/repro-bundle",
            "local_verify": "scripts/repro_bundle_check.py campaigns/fake-smoke.yaml",
            "published_verify": "scripts/verify_repro_bundle.py <bundle.tgz>",
            "download_verify": "scripts/verify_repro_bundle.py --download-url <url> --allow-missing-download --local-campaign campaigns/fake-smoke.yaml",
            "status": "layout-standardized",
            "adapter_matrix_asset": "dist/adapter-matrix.json",
        },
        "isolation_mode": {
            "default": "process-local",
            "optional": ["sandbox-docker"],
            "worker_adjudicator_separation": "lifecycle + import bans in trust-boundary images",
        },
        "known_limitations": _limitations_excerpt(),
        "limitations_doc": "docs/limitations.md",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dist-dir",
        type=Path,
        default=REPO / "dist",
        help="Directory containing wheel/sdist artifacts",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output path (default: <dist-dir>/release-manifest.json)",
    )
    parser.add_argument("--tag", default=None, help="Release tag (e.g. v0.2.0rc2)")
    parser.add_argument("--commit", default=None, help="Git commit SHA")
    args = parser.parse_args(argv)

    dist_dir = args.dist_dir
    if not dist_dir.is_dir():
        dist_dir.mkdir(parents=True, exist_ok=True)

    manifest = build_manifest(dist_dir=dist_dir, tag=args.tag, commit=args.commit)
    output = args.output or (dist_dir / "release-manifest.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
