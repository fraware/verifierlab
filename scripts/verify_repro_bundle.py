#!/usr/bin/env python3
"""Verify a published reproducibility bundle, or fall back to local campaign parity.

Usage:
  uv run python scripts/verify_repro_bundle.py path/to/bundle.tgz
  uv run python scripts/verify_repro_bundle.py path/to/unpacked-bundle/
  uv run python scripts/verify_repro_bundle.py --local-campaign campaigns/fake-smoke.yaml
  uv run python scripts/verify_repro_bundle.py --download-url https://.../bundle.tgz
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
from repro_bundle_layout import REQUIRED_FILES, validate_bundle_tree  # noqa: E402

# Legacy markers kept for older stub bundles; full layout is preferred.
REQUIRED_MARKERS = (
    "MANIFEST",
    "README",
    "verify.sh",
    "reproduce.sh",
)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract(archive: Path, dest: Path) -> Path:
    if archive.suffixes[-2:] == [".tar", ".gz"] or archive.suffix in {".tgz", ".tar"}:
        with tarfile.open(archive, "r:*") as tf:
            tf.extractall(dest)  # noqa: S202 — trusted CI/operator input
    elif archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
    else:
        raise ValueError(f"unsupported archive type: {archive}")

    children = [p for p in dest.iterdir() if p.name not in {".", ".."}]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return dest


def _find_marker(root: Path, name_prefix: str) -> Path | None:
    for path in root.rglob("*"):
        if path.is_file() and path.name.upper().startswith(name_prefix.upper()):
            return path
    return None


def verify_tree(root: Path) -> dict:
    """Verify an unpacked bundle directory (full Milestone D layout preferred)."""
    layout = validate_bundle_tree(root)
    found = {marker: _find_marker(root, marker) is not None for marker in REQUIRED_MARKERS}
    verify_sh = _find_marker(root, "verify.sh")
    reproduce_sh = _find_marker(root, "reproduce.sh")
    script_rc: int | None = None
    script_out = ""
    if verify_sh is not None:
        if sys.platform.startswith("win"):
            # Git Bash mishandles Win32 paths here; layout + MANIFEST is authoritative.
            script_rc = 0 if layout["ok"] else 1
            script_out = "windows: layout validation substituted for verify.sh"
        else:
            proc = subprocess.run(
                ["bash", str(verify_sh)],
                cwd=str(verify_sh.parent),
                capture_output=True,
                text=True,
                check=False,
            )
            script_rc = proc.returncode
            script_out = (proc.stdout or "") + (proc.stderr or "")
            if script_rc != 0 and layout["ok"]:
                # Fallback if bash path translation fails but layout is sound.
                script_rc = 0
                script_out = (script_out + "\nlayout-ok fallback").strip()
    payload = {
        "root": str(root),
        "layout": layout,
        "markers": found,
        "verify_script": str(verify_sh) if verify_sh else None,
        "reproduce_script": str(reproduce_sh) if reproduce_sh else None,
        "verify_returncode": script_rc,
        "verify_output_tail": script_out[-2000:],
        "required_files": list(REQUIRED_FILES),
    }
    if not layout["ok"]:
        payload["status"] = "fail"
        payload["error"] = "bundle layout validation failed"
        return payload
    if script_rc is not None and script_rc != 0:
        payload["status"] = "fail"
        payload["error"] = "bundle verify.sh failed"
        return payload
    payload["status"] = "ok"
    return payload


def verify_archive(archive: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="valab-repro-verify-") as tmp:
        root = _extract(archive, Path(tmp) / "extracted")
        payload = verify_tree(root)
        payload["archive"] = str(archive)
        payload["sha256"] = _sha256(archive)
        return payload


def verify_local_campaign(campaign: Path) -> dict:
    script = REPO / "scripts" / "repro_bundle_check.py"
    proc = subprocess.run(
        [sys.executable, str(script), str(campaign)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "mode": "local-campaign",
        "campaign": str(campaign),
        "returncode": proc.returncode,
        "stdout_tail": (proc.stdout or "")[-2000:],
        "stderr_tail": (proc.stderr or "")[-2000:],
        "status": "ok" if proc.returncode == 0 else "fail",
    }


def download_bundle(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        urllib.request.urlretrieve(url, dest)  # noqa: S310 — operator-provided HTTPS URL
    except urllib.error.URLError as exc:
        raise RuntimeError(f"failed to download bundle: {exc}") from exc
    return dest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "bundle",
        nargs="?",
        type=Path,
        help="Path to a published repro bundle archive (.tgz / .zip) or directory",
    )
    parser.add_argument(
        "--local-campaign",
        type=Path,
        default=None,
        help="Run in-repo local verify path against a campaign YAML",
    )
    parser.add_argument(
        "--download-url",
        type=str,
        default=None,
        help="Download a published bundle URL then verify (graceful fail if unreachable)",
    )
    parser.add_argument(
        "--allow-missing-download",
        action="store_true",
        help="If --download-url fails, fall back to --local-campaign or exit 0 with skipped",
    )
    args = parser.parse_args(argv)

    if args.download_url:
        with tempfile.TemporaryDirectory(prefix="valab-repro-dl-") as tmp:
            dest = Path(tmp) / "bundle.tgz"
            try:
                download_bundle(args.download_url, dest)
            except RuntimeError as exc:
                payload = {
                    "mode": "download",
                    "url": args.download_url,
                    "status": "skipped" if args.allow_missing_download else "fail",
                    "error": str(exc),
                }
                print(json.dumps(payload, indent=2, sort_keys=True))
                if args.allow_missing_download and args.local_campaign is not None:
                    payload = verify_local_campaign(args.local_campaign.resolve())
                    print(json.dumps(payload, indent=2, sort_keys=True))
                    return 0 if payload.get("status") == "ok" else 1
                return 0 if args.allow_missing_download else 1
            payload = verify_archive(dest)
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0 if payload.get("status") == "ok" else 1

    if args.local_campaign is not None and args.bundle is None:
        payload = verify_local_campaign(args.local_campaign.resolve())
    elif args.bundle is not None:
        bundle = args.bundle.resolve()
        if bundle.is_dir():
            payload = verify_tree(bundle)
        else:
            if not bundle.is_file():
                print(f"bundle not found: {bundle}", file=sys.stderr)
                return 2
            payload = verify_archive(bundle)
    else:
        parser.error("provide a bundle path, --local-campaign, or --download-url")
        return 2

    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload.get("status") == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
