"""Adversarial tests for canonical fresh-reattack evidence derivation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.cas import ContentAddressedStore
from verifierlab.campaigns.splits import materialize_split_manifest
from verifierlab.config.campaign import CampaignSpec
from verifierlab.repairs.canonical_evidence import load_canonical_fresh_run

_CANDIDATE_DIGEST = "1" * 64
_VERIFIER_DIGEST = "2" * 64


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _campaign(*, max_queries: int = 8) -> CampaignSpec:
    return CampaignSpec.model_validate(
        {
            "schema_version": "1",
            "name": "repair-fresh-qualification",
            "pinned_versions": {
                "verifierlab": "0.2.0rc2",
                "campaign": "repair-fresh-qualification@1",
            },
            "access_model": "black-box",
            "budget": {
                "schema_version": "2",
                "max_queries": max_queries,
                "overrun_policy": "stop",
            },
            "environment": {
                "kind": "fake",
                "ref": "verifierlab.targets.fake:FakeEnvironment",
                "version": "1",
                "config": {"max_steps": 1},
            },
            "verifier": {
                "kind": "python",
                "ref": "verifierlab.targets.fake:fake_refund_verifier",
                "version": "1",
                "config": {},
            },
            "ground_truth": {"provider": "planted-oracle", "version": "1", "config": {}},
            "baseline": {"strategy": "ordinary", "config": {}},
            "attacks": [
                {
                    "name": "fresh",
                    "strategy": "ordinary",
                    "cohort": "optimized",
                    "units": 2,
                    "config": {"actions": [{"op": "noop"}]},
                }
            ],
            "splits": [
                {"name": "train", "count": 1, "seed": 17, "label_tier": "development"},
                {"name": "holdout", "count": 1, "seed": 17, "label_tier": "release"},
            ],
            "stats_plan": {"methods": ["wilson"], "alpha": 0.05},
            "seed": 17,
            "work_units": 2,
            "metadata": {"repair_candidate_digest": _CANDIDATE_DIGEST},
        }
    )


def _security_boundary() -> dict[str, Any]:
    return {
        "schema_version": "1",
        "mode": "container_isolated",
        "security_grade": True,
        "no_host_mounts": True,
        "network_none": True,
        "read_only_root": True,
    }


def _build_bundle(
    tmp_path: Path,
    *,
    boundary: dict[str, Any] | None = None,
    persistent: bool = False,
    ledger_queries: int = 3,
    max_queries: int = 8,
) -> tuple[Path, dict[str, Any]]:
    workspace = tmp_path / ".valab"
    run_dir = workspace / "runs" / "run-fresh"
    store = ContentAddressedStore(workspace / "store")
    spec = _campaign(max_queries=max_queries)
    campaign_digest = store.put_json(spec.model_dump(mode="json"))

    unit_ids = ["unit-train", "unit-holdout"]
    split = materialize_split_manifest(spec, unit_ids=unit_ids, run_dir=None)
    _write_json(run_dir / "splits" / "manifest.json", split)
    holdout = next(row for row in split["units"] if row["learning"] is False)
    holdout_id = str(holdout["unit_id"])

    effective_boundary = _security_boundary() if boundary is None else boundary
    attack_row: dict[str, Any] = {
        "schema_version": "2",
        "unit_id": holdout_id,
        "seed": 18,
        "cohort": "optimized",
        "strategy": "ordinary",
        "access_model": "black-box",
        "split": "holdout",
        "learning": False,
        "trajectory": {"schema_version": "1", "steps": [{"op": "noop"}]},
        "verifier_accepted": True,
        "verifier_profile_digest": _VERIFIER_DIGEST,
        "gt_valid": None,
        "exploit": None,
    }
    if effective_boundary:
        attack_row["execution_boundary"] = effective_boundary
        attack_row["execution_boundary_digest"] = digest_of(effective_boundary)
    if persistent:
        attack_row["attacker_checkpoint"] = "/state/attacker"
    work_digest = store.put_json(attack_row)
    attack_file = {**attack_row, "cas_digest": work_digest}
    _write_json(run_dir / "work_units" / f"{holdout_id}.json", attack_file)

    analysis = {
        **attack_file,
        "gt_valid": True,
        "exploit": None,
        "vault_commitment": "3" * 64,
        "labels_released": True,
    }
    _write_json(run_dir / "analysis" / "work_units" / f"{holdout_id}.json", analysis)

    sealed = {
        "schema_version": "1",
        "kind": "sealed_run",
        "seal_id": "seal-run-fresh",
        "run_id": "run-fresh",
        "freeze_digest": "4" * 64,
        "campaign_digest": campaign_digest,
        "verifier_digest": _VERIFIER_DIGEST,
        "attack_digests": [work_digest],
        "sealed_at": 1.0,
    }
    sealed_digest = store.put_json(sealed)
    _write_json(run_dir / "sealed_run.json", {**sealed, "content_digest": sealed_digest})

    ledger = {"schema_version": "2", "queries": ledger_queries, "steps": 1, "events": []}
    ledger_digest = store.put_json(ledger)
    release = {
        "schema_version": "1",
        "kind": "adjudication_release",
        "release_id": "release-run-fresh",
        "run_id": "run-fresh",
        "prev_digest": "5" * 64,
        "released_at": 2.0,
        "commitment_digests": ["3" * 64],
        "metadata": {},
    }
    release_digest = store.put_json(release)
    manifest = {
        "schema_version": "1",
        "run_id": "run-fresh",
        "tip_digest": release_digest,
        "run_digest": release_digest,
        "tip_kind": "adjudication_release",
        "lifecycle": "label_release",
        "campaign_digest": campaign_digest,
        "ledger_digest": ledger_digest,
        "chain": ["5" * 64, release_digest],
        "status": "completed",
        "work_unit_digests": [work_digest],
        "metadata": {"lifecycle": "label_release", "labels_released": True},
    }
    _write_json(run_dir / "manifest.json", manifest)
    return run_dir, {"holdout_id": holdout_id, "work_digest": work_digest}


def test_derives_qualification_evidence_only_from_consistent_artifacts(tmp_path: Path) -> None:
    run_dir, refs = _build_bundle(tmp_path)

    rows, evidence = load_canonical_fresh_run(
        run_dir,
        expected_repair_candidate_digest=_CANDIDATE_DIGEST,
    )

    assert [row["unit_id"] for row in rows] == [refs["holdout_id"]]
    assert evidence.fresh_attacker_established is True
    assert evidence.execution_security_grade is True
    assert evidence.holdout_isolated is True
    assert evidence.repair_candidate_digest == _CANDIDATE_DIGEST
    assert evidence.sealed_holdout_work_digests == (refs["work_digest"],)
    assert evidence.qualification_blockers == ()


def test_process_local_or_missing_boundary_cannot_establish_freshness(tmp_path: Path) -> None:
    run_dir, _ = _build_bundle(tmp_path, boundary={})

    _, evidence = load_canonical_fresh_run(
        run_dir,
        expected_repair_candidate_digest=_CANDIDATE_DIGEST,
    )

    assert evidence.fresh_attacker_established is False
    assert evidence.execution_security_grade is False
    assert any(item.startswith("execution_boundary_missing:") for item in evidence.qualification_blockers)


def test_tampered_split_manifest_is_rejected_even_with_new_self_digest(tmp_path: Path) -> None:
    run_dir, _ = _build_bundle(tmp_path)
    path = run_dir / "splits" / "manifest.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    body = {k: v for k, v in payload.items() if k != "content_digest"}
    body["seed"] = 999
    body["content_digest"] = digest_of(body)
    _write_json(path, body)

    with pytest.raises(RuntimeError, match="does not reconstruct"):
        load_canonical_fresh_run(run_dir, expected_repair_candidate_digest=_CANDIDATE_DIGEST)


def test_sealed_run_file_must_match_cas(tmp_path: Path) -> None:
    run_dir, _ = _build_bundle(tmp_path)
    path = run_dir / "sealed_run.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    body = {k: v for k, v in payload.items() if k != "content_digest"}
    body["sealed_at"] = 9.0
    body["content_digest"] = digest_of(body)
    _write_json(path, body)

    with pytest.raises((KeyError, RuntimeError)):
        load_canonical_fresh_run(run_dir, expected_repair_candidate_digest=_CANDIDATE_DIGEST)


def test_released_analysis_row_cannot_mutate_attack_evidence(tmp_path: Path) -> None:
    run_dir, refs = _build_bundle(tmp_path)
    path = run_dir / "analysis" / "work_units" / f"{refs['holdout_id']}.json"
    row = json.loads(path.read_text(encoding="utf-8"))
    row["verifier_accepted"] = False
    _write_json(path, row)

    with pytest.raises(RuntimeError, match="diverges from sealed attack artifact"):
        load_canonical_fresh_run(run_dir, expected_repair_candidate_digest=_CANDIDATE_DIGEST)


def test_wrong_repair_candidate_binding_is_rejected(tmp_path: Path) -> None:
    run_dir, _ = _build_bundle(tmp_path)

    with pytest.raises(RuntimeError, match="pre-bound"):
        load_canonical_fresh_run(run_dir, expected_repair_candidate_digest="9" * 64)


def test_ledger_spend_above_campaign_budget_is_rejected(tmp_path: Path) -> None:
    run_dir, _ = _build_bundle(tmp_path, ledger_queries=9, max_queries=8)

    with pytest.raises(RuntimeError, match="inconsistent with campaign budget"):
        load_canonical_fresh_run(run_dir, expected_repair_candidate_digest=_CANDIDATE_DIGEST)


def test_persistent_attacker_state_blocks_freshness(tmp_path: Path) -> None:
    run_dir, _ = _build_bundle(tmp_path, persistent=True)

    _, evidence = load_canonical_fresh_run(
        run_dir,
        expected_repair_candidate_digest=_CANDIDATE_DIGEST,
    )

    assert evidence.fresh_attacker_established is False
    assert any(
        item.startswith("persistent_attacker_state_present:")
        for item in evidence.qualification_blockers
    )
