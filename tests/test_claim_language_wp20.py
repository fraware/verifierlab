"""Claim-language lint tests (WP-20)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_claim_language_script_clean() -> None:
    proc = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "check_claim_language.py")],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_claim_language_doc_exists() -> None:
    text = (REPO / "docs" / "claim-language.md").read_text(encoding="utf-8")
    assert "internally_verified" in text
    assert "scientifically_qualified" in text
    assert "Banned overclaims" in text


def test_readme_does_not_claim_scientific_qualification() -> None:
    text = (REPO / "README.md").read_text(encoding="utf-8")
    assert "internally_verified" in text
    compact = " ".join(text.split())
    assert "does **not** claim `scientifically_qualified`" in compact
