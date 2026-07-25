"""Campaign lifecycle states and append-only tip helpers."""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Any

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.cas import ContentAddressedStore
from verifierlab.artifacts.lifecycle_records import LifecycleTipIndex


class LifecycleState(str, Enum):
    DRAFT = "draft"
    VALIDATED = "validated"
    BASELINE = "baseline"
    ATTACK = "attack"
    FREEZE = "freeze"
    ADJUDICATION = "adjudication"
    LABEL_RELEASE = "label_release"
    TRIAGE = "triage"
    STATS = "stats"
    REPAIR = "repair"
    DISCLOSURE = "disclosure"


_ALLOWED: dict[LifecycleState, frozenset[LifecycleState]] = {
    LifecycleState.DRAFT: frozenset({LifecycleState.VALIDATED}),
    LifecycleState.VALIDATED: frozenset({LifecycleState.BASELINE, LifecycleState.ATTACK}),
    LifecycleState.BASELINE: frozenset({LifecycleState.ATTACK}),
    LifecycleState.ATTACK: frozenset({LifecycleState.FREEZE}),
    LifecycleState.FREEZE: frozenset({LifecycleState.ADJUDICATION}),
    LifecycleState.ADJUDICATION: frozenset({LifecycleState.LABEL_RELEASE}),
    LifecycleState.LABEL_RELEASE: frozenset(
        {LifecycleState.TRIAGE, LifecycleState.STATS, LifecycleState.REPAIR}
    ),
    LifecycleState.TRIAGE: frozenset(
        {LifecycleState.STATS, LifecycleState.REPAIR, LifecycleState.DISCLOSURE}
    ),
    LifecycleState.STATS: frozenset({LifecycleState.REPAIR, LifecycleState.DISCLOSURE}),
    LifecycleState.REPAIR: frozenset({LifecycleState.DISCLOSURE}),
    LifecycleState.DISCLOSURE: frozenset(),
}


def can_transition(current: LifecycleState | str, nxt: LifecycleState | str) -> bool:
    cur = LifecycleState(current)
    nxt_s = LifecycleState(nxt)
    return nxt_s in _ALLOWED[cur]


def assert_transition(current: LifecycleState | str, nxt: LifecycleState | str) -> None:
    if not can_transition(current, nxt):
        raise ValueError(f"illegal lifecycle transition: {current} → {nxt}")


def read_tip_index(run_dir: Path) -> dict[str, Any]:
    path = Path(run_dir) / "manifest.json"
    if not path.is_file():
        raise FileNotFoundError(f"missing manifest tip index: {path}")
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def lifecycle_of(run_dir: Path) -> str:
    data = read_tip_index(run_dir)
    meta = data.get("metadata") or {}
    return str(data.get("lifecycle") or meta.get("lifecycle") or LifecycleState.ATTACK.value)


def labels_released(run_dir: Path) -> bool:
    """True when the tip index (or vault marker) shows labels are released."""
    run_dir = Path(run_dir)
    try:
        life = lifecycle_of(run_dir)
        if life in {
            LifecycleState.LABEL_RELEASE.value,
            LifecycleState.TRIAGE.value,
            LifecycleState.STATS.value,
            LifecycleState.REPAIR.value,
            LifecycleState.DISCLOSURE.value,
        }:
            return True
    except FileNotFoundError:
        pass
    return (run_dir / "vault" / "RELEASED").is_file()


def write_tip_index(
    run_dir: Path,
    *,
    store: ContentAddressedStore,
    tip_payload: dict[str, Any],
    tip_kind: str,
    lifecycle: LifecycleState | str,
    run_id: str,
    prev_chain: list[str] | None = None,
    extra_index: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Persist an immutable tip to CAS and update ``manifest.json`` pointer only."""
    run_dir = Path(run_dir)
    tip_digest = store.put_json(tip_payload)
    chain = list(prev_chain or [])
    if tip_digest not in chain:
        chain.append(tip_digest)
    index = LifecycleTipIndex(
        run_id=run_id,
        tip_digest=tip_digest,
        tip_kind=tip_kind,
        lifecycle=str(lifecycle.value if isinstance(lifecycle, LifecycleState) else lifecycle),
        campaign_digest=tip_payload.get("campaign_digest"),
        chain=chain,
        status=tip_payload.get("status"),
        work_unit_digests=list(tip_payload.get("work_unit_digests") or []),
        ledger_digest=tip_payload.get("ledger_digest"),
        overrun=bool(tip_payload.get("overrun")),
        metadata={
            **dict(tip_payload.get("metadata") or {}),
            "lifecycle": str(
                lifecycle.value if isinstance(lifecycle, LifecycleState) else lifecycle
            ),
            **dict((extra_index or {}).get("metadata") or {}),
        },
    )
    body = index.model_dump(mode="json")
    # Convenience mirrors for older readers.
    body["run_digest"] = tip_digest
    body["campaign_digest"] = body.get("campaign_digest") or tip_payload.get("campaign_digest")
    if extra_index:
        for key, value in extra_index.items():
            if key == "metadata":
                continue
            body[key] = value
    # Pointer file — intentionally rewritten; CAS tip objects stay immutable.
    (run_dir / "manifest.json").write_text(
        json.dumps(body, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    # Also store the tip payload under run_dir/lifecycle/ for local inspection.
    life_dir = run_dir / "lifecycle"
    life_dir.mkdir(exist_ok=True)
    (life_dir / f"{tip_kind}-{tip_digest[:16]}.json").write_text(
        json.dumps({**tip_payload, "content_digest": tip_digest}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return tip_digest, body


def tip_payload_digest(payload: dict[str, Any]) -> str:
    return digest_of(payload)
