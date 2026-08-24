"""Coordinator-side adjudication after freeze (VAL-R03)."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from verifierlab.artifacts.cas import ContentAddressedStore
from verifierlab.artifacts.lifecycle_records import AdjudicationRecord
from verifierlab.campaigns.episode import enrich_episode_with_gt
from verifierlab.campaigns.lifecycle import (
    LifecycleState,
    assert_transition,
    lifecycle_of,
    read_tip_index,
    write_tip_index,
)
from verifierlab.config.campaign import CampaignSpec
from verifierlab.labels.vault import LabelVault
from verifierlab.plugins.loader import load_object


def resolve_is_valid(spec: CampaignSpec) -> Callable[[dict[str, Any]], bool] | None:
    """Resolve a callable is_valid for planted / configured ground truth."""
    provider = spec.ground_truth.provider
    candidates: list[str] = []
    if ":" in provider:
        mod = provider.split(":", 1)[0]
        candidates.append(f"{mod}:refund_is_valid")
        candidates.append(f"{mod}:_is_valid")
    if spec.environment.kind == "fake" or "fake" in spec.environment.ref:
        candidates.append("verifierlab.labels.planted_fake:PlantedOracleGroundTruth._is_valid")
    for ref in candidates:
        try:
            fn = load_object(ref)
            if callable(fn):
                return fn  # type: ignore[no-any-return]
        except Exception:
            continue
    try:
        gt_cls = load_object(provider) if ":" in provider or "." in provider else None
        if gt_cls is not None and hasattr(gt_cls, "_is_valid"):
            return gt_cls._is_valid  # type: ignore[no-any-return]
    except Exception:
        return None
    return None


def adjudicate_run(
    run_dir: Path,
    *,
    spec: CampaignSpec | None = None,
    store: ContentAddressedStore | None = None,
    workspace: Path | None = None,
    is_valid: Callable[[dict[str, Any]], bool] | None = None,
) -> AdjudicationRecord:
    """Load GT after freeze, seal encrypted labels, append adjudication tip.

    Attack work-unit artifacts are not mutated. Sealed labels live only in the
    vault; ``gt_valid`` is not written to work units until label release.
    """
    run_dir = Path(run_dir)
    index = read_tip_index(run_dir)
    current = lifecycle_of(run_dir)
    assert_transition(current, LifecycleState.ADJUDICATION)

    if not (run_dir / "vault" / "FROZEN").is_file() and not (run_dir / "freeze.json").is_file():
        raise RuntimeError("cannot adjudicate before freeze")

    if is_valid is None:
        if spec is None:
            raise ValueError("adjudicate_run requires spec or is_valid")
        is_valid = resolve_is_valid(spec)
    if is_valid is None:
        raise RuntimeError("no ground-truth is_valid callable resolved for adjudication")

    ws = workspace or run_dir.parent.parent
    if store is None:
        store = ContentAddressedStore(ws / "store")

    vault = LabelVault.open(run_dir / "vault", workspace=ws)
    if vault.released:
        raise RuntimeError("cannot adjudicate after label release")

    wu_dir = run_dir / "work_units"
    sealed: list[str] = []
    exploit_count = 0
    unit_count = 0
    adj_dir = run_dir / "adjudications"
    adj_dir.mkdir(exist_ok=True)

    for path in sorted(wu_dir.glob("*.json")):
        row = json.loads(path.read_text(encoding="utf-8"))
        if row.get("error") and "trajectory" not in row:
            continue
        traj = row.get("trajectory")
        if traj is None:
            continue
        unit_count += 1
        enriched = enrich_episode_with_gt(
            row,
            is_valid=is_valid,
            cohort=str(row.get("cohort") or "optimized"),
            access_model=str(row.get("access_model") or "black-box"),
        )
        gt_valid = bool(enriched["gt_valid"])
        if enriched.get("exploit"):
            exploit_count += 1
        dimensions = {
            "outcome": "pass" if gt_valid else "fail",
        }
        extra_dims = enriched.get("adjudication_dimensions") or enriched.get("dimensions")
        if isinstance(extra_dims, dict):
            for key, value in extra_dims.items():
                dimensions[str(key)] = value
        external = str(row.get("commitment") or "")
        vault_c = vault.commit(
            traj,
            {
                "valid": gt_valid,
                "reason": "adjudicator",
                "unit_id": row.get("unit_id"),
                "dimensions": dimensions,
            },
            role="adjudicator",
            external_commitment=external or None,
            nonce=str(row.get("commitment_nonce") or row.get("unit_id") or ""),
        )
        sealed.append(vault_c)
        side = {
            "unit_id": row.get("unit_id"),
            "external_commitment": external,
            "vault_commitment": vault_c,
            "gt_valid": gt_valid,
            "dimensions": dimensions,
            "exploit": enriched.get("exploit"),
            "verifier_accepted": row.get("verifier_accepted"),
            "cohort": row.get("cohort"),
            "access_model": row.get("access_model"),
        }
        (adj_dir / f"{row.get('unit_id')}.json").write_text(
            json.dumps(side, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    freeze_digest = str(index.get("tip_digest") or index.get("run_digest") or "")
    record = AdjudicationRecord(
        adjudication_id=f"adj-{index['run_id']}",
        run_id=str(index["run_id"]),
        prev_digest=freeze_digest,
        freeze_digest=freeze_digest,
        sealed_commitments=sorted(sealed),
        unit_count=unit_count,
        exploit_count=exploit_count,
        adjudicated_at=time.time(),
        metadata={"gt_evaluated_on": "adjudicator"},
    )
    tip_payload = record.model_dump(mode="json")
    tip_digest, _ = write_tip_index(
        run_dir,
        store=store,
        tip_payload=tip_payload,
        tip_kind="adjudication",
        lifecycle=LifecycleState.ADJUDICATION,
        run_id=str(index["run_id"]),
        prev_chain=list(index.get("chain") or [freeze_digest]),
        extra_index={
            "campaign_digest": index.get("campaign_digest"),
            "work_unit_digests": index.get("work_unit_digests") or [],
            "ledger_digest": index.get("ledger_digest"),
            "status": index.get("status"),
            "overrun": index.get("overrun", False),
            "metadata": {
                **dict(index.get("metadata") or {}),
                "exploit_count": exploit_count,
                "gt_evaluated_on": "adjudicator",
            },
        },
    )
    (run_dir / "adjudication.json").write_text(
        json.dumps({**tip_payload, "content_digest": tip_digest}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return record
