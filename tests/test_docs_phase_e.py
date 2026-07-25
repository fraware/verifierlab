"""Docs / community templates for Phase E (VAL-R19)."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOCS = REPO / "docs"


def test_ten_minute_path_documents_full_lifecycle() -> None:
    text = (DOCS / "getting-started.md").read_text(encoding="utf-8")
    for needle in (
        "campaign freeze",
        "campaign adjudicate",
        "campaign release-labels",
        "report builds",
    ):
        assert needle in text, f"missing lifecycle step: {needle}"


def test_cli_documents_adjudicate() -> None:
    text = (DOCS / "cli.md").read_text(encoding="utf-8")
    assert "campaign adjudicate" in text
    assert "freeze → adjudicate → release-labels" in text or "freeze -> adjudicate" in text


def test_disclosure_and_incident_templates_exist() -> None:
    disclosure = DOCS / "templates" / "disclosure.md"
    incident = DOCS / "templates" / "incident.md"
    assert disclosure.is_file()
    assert incident.is_file()
    assert "Embargo" in disclosure.read_text(encoding="utf-8")
    assert "gt_valid" in incident.read_text(encoding="utf-8")


def test_beta_acceptance_documents_rc_version() -> None:
    text = (DOCS / "beta-acceptance.md").read_text(encoding="utf-8")
    assert "0.2.0rc1" in text
    assert "SOTA" in text
    assert "Packs A-F" in text or "Packs A\u2013F" in text
