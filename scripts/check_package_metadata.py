#!/usr/bin/env python3
"""Assert package metadata exposes docs / changelog / source URLs.

Source of truth is ``pyproject.toml``. Installed distribution metadata is
checked when present; stale editable installs warn instead of hard-failing so
local worktrees remain usable before ``uv sync`` / rebuild.
"""

from __future__ import annotations

import importlib.metadata
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
REQUIRED_URL_KEYS = ("Homepage", "Repository", "Issues", "Documentation", "Changelog")


def _installed_has_url(meta: importlib.metadata.PackageMetadata, label: str) -> bool:
    for raw in meta.get_all("Project-URL") or []:
        if raw.lower().startswith(label.lower() + ","):
            return True
    if label == "Homepage" and meta.get("Home-page"):
        return True
    return False


def main() -> int:
    pyproject = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    urls = pyproject.get("project", {}).get("urls", {})
    missing = [k for k in REQUIRED_URL_KEYS if k not in urls]
    if missing:
        print("ERROR: pyproject.toml [project.urls] missing:", ", ".join(missing))
        return 1
    for key in REQUIRED_URL_KEYS:
        if not str(urls[key]).startswith("https://"):
            print(f"ERROR: project.urls.{key} must be an https URL")
            return 1

    try:
        meta = importlib.metadata.metadata("verifierlab")
    except importlib.metadata.PackageNotFoundError:
        print("OK: project.urls present in pyproject.toml (package not installed)")
        return 0

    missing_installed = [k for k in REQUIRED_URL_KEYS if not _installed_has_url(meta, k)]
    if missing_installed:
        print(
            "WARN: installed metadata missing Project-URL:",
            ", ".join(missing_installed),
            "(pyproject.toml is complete; reinstall/sync to refresh dist-info)",
        )
        print("OK: project.urls present in pyproject.toml")
        return 0

    print("OK: package metadata URLs present (pyproject + installed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
