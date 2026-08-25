"""Evidence derivation for qualification-grade fresh reattack runs.

This module deliberately separates *deriving evidence from immutable run
artifacts* from *asserting that a repair passed*. A caller cannot turn a local
run into qualification evidence by setting booleans after the fact.

A canonical fresh reattack must be label-released, bind the repaired verifier,
bind a pre-reattack repair candidate in the campaign definition, expose a
finite query budget and an integrity-checked spend ledger, use an explicit
non-learning holdout split, and carry execution-boundary records on every
qualification row. Released analysis rows must trace back to the work-unit CAS
objects bound by the sealed run. Security-grade freshness additionally requires
every such boundary to be security-grade and mount-free.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.cas import ContentAddressedStore
from verifierlab.campaigns.lifecycle import LifecycleState, read_tip_index
from verifierlab.campaigns.splits import materialize_split_manifest
from verifierlab.config.campaign import CampaignSpec

_RELEASE_ONLY_FIELDS = frozenset({"gt_valid", "exploit", "vault_commitment", "labels_released"})


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
    repair_candidate_digest: str = Field(min_length=64, max_length=64)
    budget_limit_queries: int = Field(gt=0)
    queries_used: int = Field(ge=0)
    holdout_unit_ids: tuple[str, ...]
    sealed_holdout_work_digests: tuple[str, ...]
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


def _assert_cas_object(
    store: ContentAddressedStore,
    digest: str,
    expected: dict[str, Any],
    *,
    name: str,
) -> None:
    stored = store.get_json(digest)
    if stored != expected:
        raise RuntimeError(f"{name} CAS object does not match the run artifact")


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
        if learning is False or split in {
            "holdout",
            "test",
            "eval",
            "evaluation",
            "private_holdout",
        }:
            if learning is not False:
                raise RuntimeError("holdout split is not marked non-learning")
            unit_id = str(row.get("unit_id") or "")
            if not unit_id:
                raise RuntimeError("holdout split contains unit without id")
            holdout.append(unit_id)
    if not holdout:
        raise RuntimeError("qualification run has no explicit non-learning holdout units")
    return tuple(sorted(holdout))


def _assert_split_matches_campaign(spec: CampaignSpec, split_manifest: dict[str, Any]) -> None:
    units = split_manifest.get("units")
    if not isinstance(units, list):
        raise RuntimeError("split manifest missing units")
    unit_ids = [str(row.get("unit_id") or "") for row in units if isinstance(row, dict)]
    if len(unit_ids) != len(units) or any(not unit_id for unit_id in unit_ids):
        raise RuntimeError("split manifest contains invalid unit ids")
    expected = materialize_split_manifest(spec, unit_ids=unit_ids, run_dir=None)
    expected_body = {k: v for k, v in expected.items() if k != "content_digest"}
    if expected_body != split_manifest:
        raise RuntimeError("split manifest does not reconstruct from campaign specification")


def _qualification_rows(
    run_dir: Path,
    holdout_ids: tuple[str, ...],
    *,
    store: ContentAddressedStore,
    sealed_attack_digests: set[str],
) -> tuple[list[dict[str, Any]], tuple[str, ...]]:
    analysis_root = run_dir / "analysis" / "work_units"
    attack_root = run_dir / "work_units"
    rows: list[dict[str, Any]] = []
    work_digests: list[str] = []
    for unit_id in holdout_ids:
        attack_row = _read_json(attack_root / f"{unit_id}.json")
        if str(attack_row.get("unit_id") or "") != unit_id:
            raise RuntimeError(f"attack row id mismatch for {unit_id}")
        cas_digest = _hex64(attack_row.get("cas_digest"), field=f"cas_digest:{unit_id}")
        if cas_digest not in sealed_attack_digests:
            raise RuntimeError(f"holdout work unit is not bound by sealed run: {unit_id}")
        cas_body = dict(attack_row)
        cas_body.pop("cas_digest", None)
        _assert_cas_object(store, cas_digest, cas_body, name=f"work_unit:{unit_id}")

        row = _read_json(analysis_root / f"{unit_id}.json")
        if str(row.get("unit_id") or "") != unit_id:
            raise RuntimeError(f"analysis row id mismatch for {unit_id}")
        if row.get("labels_released") is not True:
            raise RuntimeError(f"analysis row is not label-released: {unit_id}")
        if not isinstance(row.get("gt_valid"), bool):
            raise RuntimeError(f"analysis row lacks adjudicated ground truth: {unit_id}")
        analysis_attack_fields = {k: v for k, v in row.items() if k not in _RELEASE_ONLY_FIELDS}
        original_attack_fields = {
            k: v for k, v in attack_row.items() if k not in _RELEASE_ONLY_FIELDS
        }
        if analysis_attack_fields != original_attack_fields:
            raise RuntimeError(
                f"released analysis row diverges from sealed attack artifact: {unit_id}"
            )
        rows.append(row)
        work_digests.append(cas_digest)
    return rows, tuple(sorted(work_digests))


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
    expected_repair_candidate_digest: str,
) -> tuple[list[dict[str, Any]], CanonicalFreshRunEvidence]:
    """Derive fresh-reattack evidence from a released canonical run bundle.

    `fresh_attacker_established` is true only when the campaign was pre-bound to
    `expected_repair_candidate_digest`, every qualification row was executed in
    a security-grade mount-free boundary, no persistent attacker checkpoint
    channel appears on those rows, and each released row traces back to an
    attack-plane CAS object bound by the sealed run.
    """
    run_dir = Path(run_dir)
    expected_candidate = _hex64(
        expected_repair_candidate_digest,
        field="expected_repair_candidate_digest",
    )
    index = read_tip_index(run_dir)
    lifecycle = str(index.get("lifecycle") or "")
    if lifecycle != LifecycleState.LABEL_RELEASE.value:
        raise RuntimeError("fresh reattack evidence requires label-released lifecycle")
    if str(index.get("tip_kind") or "") != "adjudication_release":
        raise RuntimeError("fresh reattack evidence requires adjudication-release tip")

    release_tip = _hex64(index.get("tip_digest"), field="release_tip_digest")
    campaign_digest = _hex64(index.get("campaign_digest"), field="campaign_digest")
    ledger_digest = _hex64(index.get("ledger_digest"), field="ledger_digest")
    run_id = str(index.get("run_id") or "")
    if not run_id:
        raise RuntimeError("release index is missing run id")

    workspace = run_dir.parent.parent
    store = ContentAddressedStore(workspace / "store")
    release_payload = store.get_json(release_tip)
    if not isinstance(release_payload, dict):
        raise RuntimeError("release tip CAS object must be a JSON object")
    if (
        release_payload.get("kind") != "adjudication_release"
        or str(release_payload.get("run_id") or "") != run_id
    ):
        raise RuntimeError("release tip CAS object does not match lifecycle index")

    sealed_payload = _read_json(run_dir / "sealed_run.json")
    sealed, sealed_digest = _verified_embedded_digest(sealed_payload, name="sealed_run")
    _assert_cas_object(store, sealed_digest, sealed, name="sealed_run")
    if str(sealed.get("campaign_digest") or "") != campaign_digest:
        raise RuntimeError("sealed run campaign digest does not match lifecycle index")
    verifier_digest = _hex64(sealed.get("verifier_digest"), field="verifier_profile_digest")
    raw_attack_digests = sealed.get("attack_digests")
    if not isinstance(raw_attack_digests, list) or not raw_attack_digests:
        raise RuntimeError("sealed run has no attack digests")
    sealed_attack_digests = {
        _hex64(value, field="sealed_attack_digest") for value in raw_attack_digests
    }

    campaign_raw = store.get_json(campaign_digest)
    spec = CampaignSpec.model_validate(campaign_raw)
    metadata = dict(spec.metadata or {})
    repair_candidate = _hex64(
        metadata.get("repair_candidate_digest"),
        field="repair_candidate_digest",
    )
    if repair_candidate != expected_candidate:
        raise RuntimeError("campaign was not pre-bound to the expected repair candidate")
    if spec.budget.max_queries is None or int(spec.budget.max_queries) <= 0:
        raise RuntimeError("qualification run requires a finite positive query budget")
    budget_limit = int(spec.budget.max_queries)

    split_payload = _read_json(run_dir / "splits" / "manifest.json")
    split_manifest, split_digest = _verified_embedded_digest(split_payload, name="split_manifest")
    _assert_split_matches_campaign(spec, split_manifest)
    holdout_ids = _holdout_units(split_manifest)
    rows, holdout_work_digests = _qualification_rows(
        run_dir,
        holdout_ids,
        store=store,
        sealed_attack_digests=sealed_attack_digests,
    )

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
        blockers.extend(
            f"persistent_attacker_state_present:{unit_id}" for unit_id in persistent_rows
        )
    inherited_state_rows = [
        str(row.get("unit_id") or "unknown")
        for row in rows
        if row.get("parent_state_digest")
        or (
            isinstance(row.get("attacker_state"), dict)
            and row["attacker_state"].get("parent_state_digest")
        )
    ]
    if inherited_state_rows:
        blockers.extend(
            f"fresh_reattack_inheritance_blocker:{unit_id}" for unit_id in inherited_state_rows
        )
        persistent_rows = list(dict.fromkeys([*persistent_rows, *inherited_state_rows]))

    holdout_isolated = all(row.get("learning") is False for row in rows)
    if not holdout_isolated:
        blockers.append("holdout_row_marked_learning")

    fresh_attacker_established = (
        execution_security_grade
        and holdout_isolated
        and not persistent_rows
        and repair_candidate == expected_candidate
    )
    if not fresh_attacker_established:
        blockers.append("fresh_attacker_not_established")

    evidence = CanonicalFreshRunEvidence(
        run_id=run_id,
        release_tip_digest=release_tip,
        sealed_run_digest=sealed_digest,
        campaign_digest=campaign_digest,
        verifier_profile_digest=verifier_digest,
        ledger_digest=ledger_digest,
        split_manifest_digest=split_digest,
        results_digest=digest_of(rows),
        repair_candidate_digest=repair_candidate,
        budget_limit_queries=budget_limit,
        queries_used=queries_used,
        holdout_unit_ids=holdout_ids,
        sealed_holdout_work_digests=holdout_work_digests,
        execution_boundary_digests=boundary_digests,
        labels_released=True,
        holdout_isolated=holdout_isolated,
        execution_security_grade=execution_security_grade,
        fresh_attacker_established=fresh_attacker_established,
        qualification_blockers=tuple(sorted(set(blockers))),
    )
    return rows, evidence


__all__ = ["CanonicalFreshRunEvidence", "load_canonical_fresh_run"]
