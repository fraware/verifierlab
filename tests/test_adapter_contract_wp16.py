"""WP-16 adapter contract + matrix honesty tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from verifierlab.targets.conformance import check_decision_normalization, run_conformance
from verifierlab.targets.contract import (
    ADAPTER_CONTRACT_V1,
    ALLOWED_MATRIX_STATUSES,
    AdapterMatrixHonestyError,
    assert_matrix_row_honesty,
    validate_matrix_document,
)
from verifierlab.targets.harbor_adapter import HarborAdapter

REPO = Path(__file__).resolve().parents[1]
MATRIX = REPO / "registry" / "adapter-matrix-v1.json"
FIXTURES = Path(__file__).parent / "fixtures"


def test_adapter_contract_version_surfaces() -> None:
    report = ADAPTER_CONTRACT_V1.as_report()
    assert report["version"] == "1.0"
    assert report["contract_id"] == "verifierlab.adapter.contract"
    for surface in (
        "decision_normalization",
        "timeout_error_taxonomy",
        "hidden_label_isolation",
        "version_reporting",
    ):
        assert surface in report["surfaces"]
    assert len(report["digest"]) == 64
    assert ADAPTER_CONTRACT_V1.content_digest() == report["digest"]


def test_conformance_embeds_contract() -> None:
    adapter = HarborAdapter(atif_path=FIXTURES / "harbor_atif_trajectory.json")
    result = run_conformance(adapter, seed=0)
    assert result.ok, result.as_dict()
    assert result.contract["version"] == "1.0"
    assert result.checks["contract_version_reported"] is True
    assert all(check_decision_normalization().values())


def test_matrix_document_honesty() -> None:
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    errors = validate_matrix_document(matrix)
    assert errors == [], errors
    statuses = {row["status"] for row in matrix["adapters"]}
    assert statuses <= ALLOWED_MATRIX_STATUSES
    assert "live-tested" in statuses
    assert "fixture-only" in statuses
    env = next(r for r in matrix["adapters"] if r["adapter"] == "envassure")
    assert env["status"] == "fixture-only"
    assert env.get("installable") is not True


def test_fixture_cannot_be_labeled_live() -> None:
    with pytest.raises(AdapterMatrixHonestyError):
        assert_matrix_row_honesty(
            {
                "adapter": "bogus",
                "status": "fixture-only",
                "live_vs_fixture": "live-tested",
            }
        )
    with pytest.raises(AdapterMatrixHonestyError):
        assert_matrix_row_honesty(
            {
                "adapter": "envassure",
                "status": "live-tested",
                "live_vs_fixture": "live-tested",
                "installable": False,
            }
        )


def test_illegal_status_rejected() -> None:
    with pytest.raises(AdapterMatrixHonestyError):
        assert_matrix_row_honesty({"adapter": "x", "status": "live", "live_vs_fixture": "live"})
