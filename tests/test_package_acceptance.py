"""Package acceptance checks for Milestone A5 (metadata + release assets)."""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_project_urls_include_docs_and_changelog() -> None:
    data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    urls = data["project"]["urls"]
    for key in ("Homepage", "Repository", "Issues", "Documentation", "Changelog"):
        assert key in urls, f"missing project.urls.{key}"
        assert urls[key].startswith("https://"), f"{key} must be https URL"


def test_check_package_metadata_script() -> None:
    script = REPO / "scripts" / "check_package_metadata.py"
    proc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_release_manifest_script_runs() -> None:
    script = REPO / "scripts" / "build_release_manifest.py"
    out = REPO / "dist" / "release-manifest-test.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [sys.executable, str(script), "--dist-dir", str(out.parent), "--output", str(out)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    text = out.read_text(encoding="utf-8")
    assert '"project": "verifierlab"' in text
    assert "adapter_matrix" in text
    assert "known_limitations" in text
    out.unlink(missing_ok=True)


def test_docs_extra_lists_mkdocs() -> None:
    data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    docs = data["project"]["optional-dependencies"]["docs"]
    joined = " ".join(docs)
    assert "mkdocs" in joined
    assert "mkdocs-material" in joined
