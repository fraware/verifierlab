"""Co-evolution epochs with pinned verifier versions and lineage."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from verifierlab.artifacts.canonical import digest_of


def run_coevolution_epoch(
    *,
    epoch: int,
    verifier_fn: Callable[[dict[str, Any]], bool],
    verifier_version: str,
    attack_results: list[dict[str, Any]],
    parent_epoch_digest: str | None = None,
) -> dict[str, Any]:
    """Record one co-evolution epoch: pinned verifier + attack outcomes + lineage."""
    exploits = [
        r
        for r in attack_results
        if r.get("verifier_accepted") is True and r.get("gt_valid") is False
    ]
    record = {
        "schema_version": "1",
        "epoch": epoch,
        "verifier_version": verifier_version,
        "verifier_digest": digest_of(
            {"version": verifier_version, "module": getattr(verifier_fn, "__module__", "")}
        ),
        "parent_epoch_digest": parent_epoch_digest,
        "n_results": len(attack_results),
        "n_exploits": len(exploits),
        "exploit_unit_ids": [e.get("unit_id") for e in exploits],
    }
    record["epoch_digest"] = digest_of(record)
    return record


def lineage_chain(epochs: list[dict[str, Any]]) -> list[str]:
    return [e["epoch_digest"] for e in epochs]
