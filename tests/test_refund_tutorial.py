"""Refund tutorial campaign integration."""

from __future__ import annotations

from pathlib import Path

import pytest

from verifierlab.campaigns.engine import (
    adjudicate_campaign,
    freeze_run,
    init_workspace,
    release_labels,
    run_campaign,
)
from verifierlab.labels.vault import LabelVault
from verifierlab.plugins.loader import load_object
from verifierlab.reports import build_report

REPO = Path(__file__).resolve().parents[1]
REFUND_CI = REPO / "campaigns" / "refund-ci-smoke.yaml"


def _lifecycle_complete(run_dir: Path, campaign: Path) -> None:
    freeze_run(run_dir)
    adjudicate_campaign(run_dir, campaign_path=campaign)
    release_labels(run_dir)


@pytest.mark.integration
def test_refund_ci_smoke(tmp_path: Path) -> None:
    workspace = init_workspace(tmp_path / ".valab")
    result = run_campaign(
        REFUND_CI,
        workspace=workspace,
        max_workers=2,
        use_processes=False,
    )
    assert result.manifest.status == "completed"
    # Attack plane: no exploits until adjudication.
    assert (result.manifest.metadata or {}).get("exploit_count", 0) == 0
    for path in (result.run_dir / "work_units").glob("*.json"):
        import json

        row = json.loads(path.read_text(encoding="utf-8"))
        assert row.get("gt_valid") is None

    _lifecycle_complete(result.run_dir, REFUND_CI)
    report = build_report(result.run_dir)
    assert report["exploit_count"] >= 1
    # Recover planted classes via taxonomy on adjudication records.
    classes = set()
    for path in (result.run_dir / "adjudications").glob("*.json"):
        import json

        row = json.loads(path.read_text(encoding="utf-8"))
        if row.get("exploit"):
            classes.add(row["exploit"]["taxonomy"])
    assert len(classes) >= 3, f"expected ≥3 planted exploit classes, got {sorted(classes)}"
    index = __import__("json").loads((result.run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert (index.get("metadata") or {}).get("gt_evaluated_on") == "adjudicator"


def test_inspect_refund_verifier() -> None:
    fn = load_object("examples.refunds.verifier:grade")
    from verifierlab.api.verifier import get_verifier_spec

    spec = get_verifier_spec(fn)
    assert spec.name == "refund_grade"


@pytest.mark.integration
def test_freeze_and_label_release(tmp_path: Path) -> None:
    workspace = init_workspace(tmp_path / ".valab")
    result = run_campaign(REFUND_CI, workspace=workspace, max_workers=1, use_processes=False)
    freeze = freeze_run(result.run_dir)
    assert freeze.run_id == result.run_id
    adjudicate_campaign(result.run_dir, campaign_path=REFUND_CI)
    vault = LabelVault.open(result.run_dir / "vault", workspace=workspace)
    with pytest.raises(RuntimeError):
        vault.commit({"steps": []}, {"valid": True}, role="coordinator")
    commitments = list((result.run_dir / "vault" / "commitments").glob("*.json"))
    assert commitments
    with pytest.raises(PermissionError):
        vault.get_label(commitments[0].stem)
    release_labels(result.run_dir)
    label = vault.get_label(commitments[0].stem)
    assert "valid" in label
