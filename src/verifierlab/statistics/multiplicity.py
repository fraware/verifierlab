"""Multiplicity adjustments: Bonferroni and Holm step-down (WP-06)."""

from __future__ import annotations

from typing import Any


def bonferroni_alpha(nominal_alpha: float, family_size: int) -> float:
    if family_size <= 0:
        raise ValueError("family_size must be positive")
    return float(nominal_alpha) / float(family_size)


def holm_step_down(
    p_values: list[tuple[str, float]],
    *,
    alpha: float,
) -> dict[str, Any]:
    """Holm step-down adjusted decisions for a family of tests.

    ``p_values`` is a list of ``(estimand_id, raw_p)``. Returns ordered
    decisions with Holm-adjusted thresholds. Never treats non-rejection as
    equivalence.
    """
    if not p_values:
        return {
            "policy": "holm",
            "alpha": float(alpha),
            "family_size": 0,
            "decisions": [],
            "applied": True,
        }
    n = len(p_values)
    ordered = sorted(p_values, key=lambda item: item[1])
    decisions: list[dict[str, Any]] = []
    reject_rest = False
    for rank, (estimand_id, p) in enumerate(ordered, start=1):
        threshold = float(alpha) / float(n - rank + 1)
        reject = (not reject_rest) and (p <= threshold)
        if not reject:
            reject_rest = True
        decisions.append(
            {
                "estimand_id": estimand_id,
                "rank": rank,
                "raw_p": float(p),
                "holm_threshold": threshold,
                "reject_null": reject,
            }
        )
    # Restore original order for consumers that key by id.
    by_id = {d["estimand_id"]: d for d in decisions}
    restored = [by_id[eid] for eid, _ in p_values]
    return {
        "policy": "holm",
        "alpha": float(alpha),
        "family_size": n,
        "decisions": restored,
        "ordered_decisions": decisions,
        "applied": True,
    }


__all__ = ["bonferroni_alpha", "holm_step_down"]
