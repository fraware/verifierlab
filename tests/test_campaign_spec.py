"""CampaignSpec load and validation diagnostics."""

from __future__ import annotations

from pathlib import Path

import pytest

from verifierlab.artifacts.records import AccessModel, DisclosureClass
from verifierlab.config.campaign import CampaignSpecError, load_campaign, load_campaign_dict

REPO_ROOT = Path(__file__).resolve().parents[1]
FAKE_SMOKE = REPO_ROOT / "campaigns" / "fake-smoke.yaml"


def test_load_fake_smoke_campaign() -> None:
    spec, diags = load_campaign(FAKE_SMOKE)
    assert spec.name == "fake-smoke"
    assert spec.access_model == AccessModel.BLACK_BOX
    assert spec.disclosure_class == DisclosureClass.INTERNAL
    assert spec.budget.max_queries == 32
    assert "verifierlab" in spec.pinned_versions
    assert not any(d.severity.value == "error" for d in diags)


def test_missing_pinned_versions_errors() -> None:
    data = {
        "name": "bad",
        "access_model": "black-box",
        "budget": {"max_queries": 1},
        "environment": {"kind": "fake", "ref": "x"},
        "verifier": {"kind": "python", "ref": "y"},
        "ground_truth": {"provider": "planted-oracle"},
        "pinned_versions": {},
    }
    spec, diags = load_campaign_dict(data)
    assert spec is not None
    errors = [d for d in diags if d.severity.value == "error"]
    assert any(d.code == "VALAB.CAMPAIGN.PINNED_VERSION" for d in errors)


def test_invalid_budget_raises() -> None:
    data = {
        "name": "bad-budget",
        "access_model": "black-box",
        "budget": {},
        "environment": {"kind": "fake", "ref": "x"},
        "verifier": {"kind": "python", "ref": "y"},
        "ground_truth": {"provider": "planted-oracle"},
        "pinned_versions": {"verifierlab": "0.2.0rc1", "campaign": "x"},
    }
    spec, diags = load_campaign_dict(data)
    assert spec is None
    assert diags


def test_load_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_campaign(tmp_path / "missing.yaml")


def test_campaign_spec_error_from_file(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("name: only\n", encoding="utf-8")
    with pytest.raises(CampaignSpecError) as excinfo:
        load_campaign(path)
    assert excinfo.value.diagnostics
