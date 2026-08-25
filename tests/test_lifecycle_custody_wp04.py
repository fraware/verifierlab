"""WP-04 freeze → adjudicate → release lifecycle and hidden-holdout custody."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from verifierlab.campaigns.custody import (
    assert_no_holdout_side_channels,
    assert_split_rebind_rejected,
    build_custody_map,
    opaque_unit_token,
    public_split_view,
    scan_attack_plane_for_holdout_leakage,
)
from verifierlab.campaigns.engine import (
    adjudicate_campaign,
    freeze_run,
    init_workspace,
    release_labels,
    run_campaign,
)
from verifierlab.campaigns.registrations import (
    ResearchRegistrationKind,
    assert_attack_plane_immutable,
    assert_label_inject_before_release_rejected,
    register_research_instrument,
)
from verifierlab.config.campaign import CampaignSpec, load_campaign
from verifierlab.labels.release import LabelReleaseReceipt, assert_receipt_binds_seal
from verifierlab.labels.vault import LabelVault
from verifierlab.reports.html import build_report

REPO_ROOT = Path(__file__).resolve().parents[1]
FAKE_SMOKE = REPO_ROOT / "campaigns" / "fake-smoke.yaml"


def _campaign_with_private(tmp_path: Path) -> tuple[Path, CampaignSpec]:
    raw = yaml.safe_load(FAKE_SMOKE.read_text(encoding="utf-8"))
    raw["name"] = "wp04-private"
    raw["work_units"] = 3
    raw["attacks"] = [
        {"name": "ordinary", "strategy": "ordinary", "cohort": "ordinary", "units": 3, "config": {}}
    ]
    raw["splits"] = [
        {"name": "train", "count": 2, "label_tier": "development"},
        {"name": "private_holdout", "count": 1, "label_tier": "private_holdout"},
    ]
    path = tmp_path / "campaign.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    spec, _ = load_campaign(path)
    return path, spec


def test_opaque_ids_hide_private_holdout_membership() -> None:
    units = [
        {
            "unit_id": "logical-train-0",
            "split": "train",
            "learning": True,
            "label_tier": "development",
            "attack_visible": True,
        },
        {
            "unit_id": "logical-hold-1",
            "split": "private_holdout",
            "learning": False,
            "label_tier": "private_holdout",
            "attack_visible": False,
        },
    ]
    custody = build_custody_map(units, run_salt="salt")
    pub = public_split_view(custody)
    hold = next(u for u in pub["units"] if u["label_tier"] == "sealed")
    assert hold["split"] == "sealed"
    assert "private" not in hold["unit_id"]
    assert hold["unit_id"].startswith("u-")
    assert (
        opaque_unit_token(run_salt="salt", logical_unit_id="logical-hold-1", index=1)
        == hold["unit_id"]
    )


def test_freeze_seals_split_custody_and_bundle(tmp_path: Path) -> None:
    ws = init_workspace(tmp_path / "ws")
    result = run_campaign(FAKE_SMOKE, workspace=ws, use_processes=False)
    freeze_run(result.run_dir)
    sealed = json.loads((result.run_dir / "sealed_run.json").read_text(encoding="utf-8"))
    assert sealed["schema_version"] == "2"
    assert sealed.get("split_manifest_digest")
    assert sealed.get("freeze_seal_bundle_digest")
    assert (result.run_dir / "freeze_seal_bundle.json").is_file()
    assert (result.run_dir / "attack_plane_lock.json").is_file()
    assert (result.run_dir / "chronology.json").is_file()


def test_post_freeze_attack_mutation_rejected(tmp_path: Path) -> None:
    ws = init_workspace(tmp_path / "ws")
    result = run_campaign(FAKE_SMOKE, workspace=ws, use_processes=False)
    freeze_run(result.run_dir)
    lock = json.loads((result.run_dir / "attack_plane_lock.json").read_text(encoding="utf-8"))
    wu = next((result.run_dir / "work_units").glob("*.json"))
    row = json.loads(wu.read_text(encoding="utf-8"))
    row["tampered"] = True
    wu.write_text(json.dumps(row), encoding="utf-8")
    with pytest.raises(ValueError, match="post-freeze attack evidence mutation"):
        assert_attack_plane_immutable(
            result.run_dir, expected_work_unit_digest=str(lock["work_unit_cas_digest"])
        )


def test_split_rebind_rejected() -> None:
    with pytest.raises(ValueError, match="split rebind"):
        assert_split_rebind_rejected(
            sealed_split_digest="a" * 64,
            candidate_split_digest="b" * 64,
        )


def test_label_inject_before_freeze_rejected() -> None:
    with pytest.raises(RuntimeError, match="before freeze"):
        assert_label_inject_before_release_rejected(
            frozen=False, released=False, role="coordinator"
        )


def test_label_release_receipt_binds_seal(tmp_path: Path) -> None:
    ws = init_workspace(tmp_path / "ws")
    result = run_campaign(FAKE_SMOKE, workspace=ws, use_processes=False)
    freeze_run(result.run_dir)
    adjudicate_campaign(result.run_dir, campaign_path=FAKE_SMOKE)
    release_labels(result.run_dir)
    receipt_path = result.run_dir / "label_release_receipt.json"
    assert receipt_path.is_file()
    body = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt = LabelReleaseReceipt.model_validate(
        {k: v for k, v in body.items() if k != "content_digest"}
    )
    sealed = json.loads((result.run_dir / "sealed_run.json").read_text(encoding="utf-8"))
    assert_receipt_binds_seal(
        receipt,
        sealed_run_digest=str(sealed["content_digest"]),
        freeze_digest=str(sealed["freeze_digest"]),
    )
    with pytest.raises(ValueError, match="sealed_run_digest"):
        assert_receipt_binds_seal(
            receipt,
            sealed_run_digest="0" * 64,
            freeze_digest=str(sealed["freeze_digest"]),
        )


def test_report_requires_release_receipt(tmp_path: Path) -> None:
    ws = init_workspace(tmp_path / "ws")
    result = run_campaign(FAKE_SMOKE, workspace=ws, use_processes=False)
    freeze_run(result.run_dir)
    adjudicate_campaign(result.run_dir, campaign_path=FAKE_SMOKE)
    with pytest.raises(PermissionError, match="labels are released"):
        build_report(result.run_dir, require_labels_released=True)
    release_labels(result.run_dir)
    report = build_report(result.run_dir, require_labels_released=True)
    assert report["metadata"]["assurance_grade"] == "post_release"
    ungated = build_report(result.run_dir, require_labels_released=False)
    assert "NON-ASSURANCE" in ungated["assurance_disclaimer"]


def test_research_registration_before_outcomes(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    rec = register_research_instrument(
        run_dir,
        run_id="run-1",
        registration_kind=ResearchRegistrationKind.DEPLOYMENT_PREDICTION,
        payload={"prediction": "far<=0.1", "horizon": "30d"},
    )
    assert rec.before_outcomes is True
    (run_dir / "analysis" / "work_units").mkdir(parents=True)
    (run_dir / "analysis" / "work_units" / "u.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="registered_before_outcomes"):
        register_research_instrument(
            run_dir,
            run_id="run-1",
            registration_kind=ResearchRegistrationKind.RESPONSE_SURFACE,
            payload={"grid": []},
        )


def test_private_holdout_side_channel_scan(tmp_path: Path) -> None:
    ws = init_workspace(tmp_path / "ws")
    camp_path, _ = _campaign_with_private(tmp_path)
    result = run_campaign(camp_path, workspace=ws, use_processes=False)
    assert (result.run_dir / "custody" / "hidden_split.json").is_file()
    assert (result.run_dir / "splits" / "public_view.json").is_file()
    # Attack-plane units must use opaque IDs.
    wu_ids = [p.stem for p in (result.run_dir / "work_units").glob("*.json")]
    assert all(uid.startswith("u-") for uid in wu_ids)
    assert_no_holdout_side_channels(result.run_dir)
    wu = next((result.run_dir / "work_units").glob("*.json"))
    row = json.loads(wu.read_text(encoding="utf-8"))
    row["note"] = "private_holdout membership"
    wu.write_text(json.dumps(row), encoding="utf-8")
    hits = scan_attack_plane_for_holdout_leakage(result.run_dir)
    assert hits
    with pytest.raises(ValueError, match="side-channel"):
        assert_no_holdout_side_channels(result.run_dir)


def test_vault_post_freeze_non_adjudicator_inject_rejected(tmp_path: Path) -> None:
    ws = init_workspace(tmp_path / "ws")
    vault = LabelVault.open(tmp_path / "vault", workspace=ws)
    vault.freeze(role="coordinator")
    with pytest.raises(RuntimeError, match="post-freeze"):
        vault.commit({"t": 1}, {"gt_valid": True}, role="coordinator")
