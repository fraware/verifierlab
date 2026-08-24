"""Evidence derivation for qualification-grade fresh reattack runs.

This module deliberately separates *deriving evidence from immutable run
artifacts* from *asserting that a repair passed*. A caller cannot turn a local
run into qualification evidence by setting booleans after the fact.

A canonical fresh reattack must be label-released, bind the repaired verifier,
bind the repair artifact in the campaign definition before execution, expose a
finite query budget and an integrity-checked spend ledger, use an explicit
non-learning holdout split, and carry execution-boundary records on every
qualification row. Security-grade freshness additionally requires every such
boundary to be security-grade and mount-free.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.cas import ContentAddressedStore
from verifierlab.campaigns.lifecycle import LifecycleState, read_tip_index
from verifierlab.config.campaign import CampaignSpec


class CanonicalFreshRunEvidence(BaseModel):
    """Machine-derived evidence from one released canonical campaign run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1"
    run_id: str = Field(min_length=1)
    release_tip_digest: str = Field(min_length=64, max_length=64)
    sealed_run_digest: str = Field(min_length=64, max_length=64)
    campaign_digest: str = Field(min_length=64, max_length=64)
    verifier_profile_digest: str = Field(min_length=64, max_length=64)
    ledger_digest: str = Field(min_length=64, max_length=64)
    split_manifest_digest: str = Field(min_length=64, max_length=64)
    results_digest: str = Field(min_length=64, max_length=64)
    repair_parent_digest: str = Field(min_length=64, max_length=64)
    budget_limit_queries: int = Field(gt=0)
    queries_used: int = Field(ge=0)
    holdout_unit_ids: tuple[str, ...]
    execution_boundary_digests: tuple[str, ...]
    labels_released: bool
    holdout_isolated: bool
    execution_security_grade: bool
    fresh_attacker_established: bool
    qualification_blockers: tuple[str, ...] = ()

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"required run artifact missing: {path.name}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError(f"run artifact must be a JSON object: {path.name}")
    return data


def _verified_embedded_digest(payload: dict[str, Any], *, name: str) -> tuple[dict[str, Any], str]:
    body = dict(payload)
    claimed = str(body.pop("content_digest", ""))
    actual = digest_of(body)
    if len(claimed) != 64 or claimed != actual:
        raise RuntimeError(f"{name} content digest mismatch")
    return body, actual


def _hex64(value: Any, *, field: str) -> str:
    text = str(value or "")
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise RuntimeError(f"{field} must be a lowercase sha256 digest")
    return text


def _holdout_units(split_manifest: dict[str, Any]) -> tuple[str, ...]:
    units = split_manifest.get("units")
    if not isinstance(units, list):
        raise RuntimeError("split manifest missing units")
    holdout: list[str] = []
    for row in units:
        if not isinstance(row, dict):
            raise RuntimeError("split manifest unit must be an object")
        learning = row.get("learning")
        split = str(row.get("split") or "").strip().lower()
        if learning is False or split in {"holdout", "test", "eval", "evaluation", "private_holdout"}:
            if learning is not False:
                raise RuntimeError("holdout split is not marked non-learning")
            unit_id = str(row.get("unit_id") or "")
            if not unit_id:
                raise RuntimeError("holdout split contains unit without id")
            holdout.append(unit_id)
    if not holdout:
        raise RuntimeError("qualification run has no explicit non-learning holdout units")
    return tuple(sorted(holdout))


def _qualification_rows(run_dir: Path, holdout_ids: tuple[str, ...]) -> list[dict[str, Any]]:
    root = run_dir / "analysis" / "work_units"
    rows: list[dict[str, Any]] = []
    for unit_id in holdout_ids:
        row = _read_json(root / f"{unit_id}.json")
        if str(row.get("unit_id") or "") != unit_id:
            raise RuntimeError(f"analysis row id mismatch for {unit_id}")
        if row.get("labels_released") is not True:
            raise RuntimeError(f"analysis row is not label-released: {unit_id}")
        if not isinstance(row.get("gt_valid"), bool):
            raise RuntimeError(f"analysis row lacks adjudicated ground truth: {unit_id}")
        rows.append(row)
    return rows


def _execution_evidence(rows: list[dict[str, Any]]) -> tuple[tuple[str, ...], bool, list[str]]:
    digests: list[str] = []
    blockers: list[str] = []
    all_security_grade = True
    for row in rows:
        unit_id = str(row.get("unit_id") or "unknown")
        boundary = row.get("execution_boundary")
        boundary_digest = str(row.get("execution_boundary_digest") or "")
        if not isinstance(boundary, dict):
            blockers.append(f"execution_boundary_missing:{unit_id}")
            all_security_grade = False
            continue
        actual = digest_of(boundary)
        if boundary_digest != actual:
            raise RuntimeError(f"execution boundary digest mismatch: {unit_id}")
        digests.append(actual)
        if boundary.get("security_grade") is not True:
            blockers.append(f"execution_not_security_grade:{unit_id}")
            all_security_grade = False
        if boundary.get("no_host_mounts") is not True:
            blockers.append(f"host_mount_boundary_not_closed:{unit_id}")
            all_security_grade = False
    return tuple(sorted(digests)), all_security_grade and len(digests) == len(rows), blockers


def load_canonical_fresh_run(
    run_dir: Path | str,
    *,
    expected_repair_artifact_digest: str,
) -> tuple[list[dict[str, Any]], CanonicalFreshRunEvidence]:
    """Derive fresh-reattack evidence from a released canonical run bundle.

    `fresh_attacker_established` is true only when the campaign was pre-bound to
    `expected_repair_artifact_digest`, every qualification row was executed in a
    security-grade mount-free boundary, and no persistent attacker checkpoint
    channel appears on those rows. This is intentionally stronger than a caller
    assertion and intentionally impossible for the current process-local path.
    """
    run_dir = Path(run_dir)
    expected_repair = _hex64(expected_repair_artifact_digest, field="expected_repair_artifact_digest")
    index = read_tip_index(run_dir)
    lifecycle = str(index.get("lifecycle") or "")
    if lifecycle != LifecycleState.LABEL_RELEASE.value:
        raise RuntimeError("fresh reattack evidence requires label-released lifecycle")
    if str(index.get("tip_kind") or "") != "adjudication_release":
        raise RuntimeError("fresh reattack evidence requires adjudication-release tip")

    release_tip = _hex64(index.get("tip_digest"), field="release_tip_digest")
    campaign_digest = _hex64(index.get("campaign_digest"), field="campaign_digest")
    ledger_digest = _hex64(index.get("ledger_digest"), field="ledger_digest")

    sealed_payload = _read_json(run_dir / "sealed_run.json")
    sealed, sealed_digest = _verified_embedded_digest(sealed_payload, name="sealed_run")
    if str(sealed.get("campaign_digest") or "") != campaign_digest:
        raise RuntimeError("sealed run campaign digest does not match lifecycle index")
    verifier_digest = _hex64(sealed.get("verifier_digest"), field="verifier_profile_digest")

    split_payload = _read_json(run_dir / "splits" / "manifest.json")
    split_manifest, split_digest = _verified_embedded_digest(split_payload, name="split_manifest")
    holdout_ids = _holdout_units(split_manifest)
    rows = _qualification_rows(run_dir, holdout_ids)

    workspace = run_dir.parent.parent
    store = ContentAddressedStore(workspace / "store")
    campaign_raw = store.get_json(campaign_digest)
    spec = CampaignSpec.model_validate(campaign_raw)
    metadata = dict(spec.metadata or {})
    repair_parent = _hex64(metadata.get("repair_parent_digest"), field="repair_parent_digest")
    if repair_parent != expected_repair:
        raise RuntimeError("campaign was not pre-bound to the expected repair artifact")
    if spec.budget.max_queries is None or int(spec.budget.max_queries) <= 0:
        raise RuntimeError("qualification run requires a finite positive query budget")
    budget_limit = int(spec.budget.max_queries)

    ledger = store.get_json(ledger_digest)
    if not isinstance(ledger, dict):
        raise RuntimeError("ledger CAS object must be a JSON object")
    queries_used = int(ledger.get("queries") or 0)
    if queries_used < 0 or queries_used > budget_limit:
        raise RuntimeError("ledger query spend is inconsistent with campaign budget")

    boundary_digests, execution_security_grade, blockers = _execution_evidence(rows)
    persistent_rows = [
        str(row.get("unit_id") or "unknown")
        for row in rows
        if row.get("attacker_checkpoint") or row.get("persistent") is True
    ]
    if persistent_rows:
        blockers.extend(f"persistent_attacker_state_present:{unit_id}" for unit_id in persistent_rows)

    holdout_isolated = all(row.get("learning") is False for row in rows)
    if not holdout_isolated:
        blockers.append("holdout_row_marked_learning")

    fresh_attacker_established = (
        execution_security_grade
        and holdout_isolated
        and not persistent_rows
        and repair_parent == expected_repair
    )
    if not fresh_attacker_established:
        blockers.append("fresh_attacker_not_established")

    evidence = CanonicalFreshRunEvidence(
        run_id=str(index.get("run_id") or ""),
        release_tip_digest=release_tip,
        sealed_run_digest=sealed_digest,
        campaign_digest=campaign_digest,
        verifier_profile_digest=verifier_digest,
        ledger_digest=ledger_digest,
        split_manifest_digest=split_digest,
        results_digest=digest_of(rows),
        repair_parent_digest=repair_parent,
        budget_limit_queries=budget_limit,
        queries_used=queries_used,
        holdout_unit_ids=holdout_ids,
        execution_boundary_digests=boundary_digests,
        labels_released=True,
        holdout_isolated=holdout_isolated,
        execution_security_grade=execution_security_grade,
        fresh_attacker_established=fresh_attacker_established,
        qualification_blockers=tuple(sorted(set(blockers))),
    )
    return rows, evidence


__all__ = ["CanonicalFreshRunEvidence", "load_canonical_fresh_run"]
