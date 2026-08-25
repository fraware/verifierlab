"""Lan-DeMets alpha spending for preregistered sequential looks (WP-06).

The compiler fails closed when ``sequential_alpha`` is declared without a
preregistered ``StoppingPlan``.
"""

from __future__ import annotations

import math
from typing import Any

from verifierlab.config.preregistration import StoppingPlan


def _z_alpha(alpha: float) -> float:
    table = {0.1: 1.6448536269514722, 0.05: 1.959963984540054, 0.01: 2.5758293035489004}
    if alpha in table:
        return table[alpha]
    probability = 1 - alpha / 2
    t = math.sqrt(-2 * math.log(max(1e-12, 1 - probability)))
    return t - (2.515517 + 0.802853 * t + 0.010328 * t * t) / (
        1 + 1.432788 * t + 0.189269 * t * t + 0.001308 * t * t * t
    )


def obrien_fleming_spend(alpha: float, information_fraction: float) -> float:
    """Approximate O'Brien-Fleming cumulative alpha spent at information t.

    Uses the Lan-DeMets two-sided approximation
    ``2 * (1 - Phi(z_(alpha/2) / sqrt(t)))``.
    """
    if information_fraction <= 0:
        return 0.0
    if information_fraction >= 1.0:
        return float(alpha)
    z = _z_alpha(alpha)
    boundary = z / math.sqrt(information_fraction)
    return min(float(alpha), math.erfc(boundary / math.sqrt(2.0)))


def pocock_spend(
    alpha: float,
    information_fraction: float,
    n_looks: int | None = None,
) -> float:
    """Lan-DeMets Pocock-type cumulative alpha spending function.

    ``alpha * log(1 + (e - 1) * t)`` is the standard continuous Pocock-type
    spending family. ``n_looks`` is retained only for API compatibility with
    the former discrete implementation; the spending function is determined by
    information fraction rather than look index.
    """
    del n_looks
    if information_fraction <= 0:
        return 0.0
    if information_fraction >= 1.0:
        return float(alpha)
    return float(alpha) * math.log(1.0 + (math.e - 1.0) * information_fraction)


def alpha_spent_at_look(plan: StoppingPlan, look_index: int) -> dict[str, Any]:
    """Return cumulative and incremental alpha at a zero-based look index."""
    if look_index < 0 or look_index >= len(plan.looks):
        raise ValueError(f"look_index out of range: {look_index}")
    information_fraction = float(plan.looks[look_index])
    if plan.spending_function == "obrien_fleming":
        cumulative = obrien_fleming_spend(plan.nominal_alpha, information_fraction)
    else:
        cumulative = pocock_spend(plan.nominal_alpha, information_fraction)

    previous = 0.0
    if look_index > 0:
        previous_fraction = float(plan.looks[look_index - 1])
        if plan.spending_function == "obrien_fleming":
            previous = obrien_fleming_spend(plan.nominal_alpha, previous_fraction)
        else:
            previous = pocock_spend(plan.nominal_alpha, previous_fraction)

    incremental = max(0.0, cumulative - previous)
    return {
        "look_index": look_index,
        "information_fraction": information_fraction,
        "cumulative_alpha": cumulative,
        "incremental_alpha": incremental,
        "spending_function": plan.spending_function,
        "stopping_plan_digest": plan.content_digest,
    }


def require_sequential_plan(stopping_plan: StoppingPlan | None) -> StoppingPlan:
    if stopping_plan is None:
        raise ValueError(
            "sequential_alpha is declared but no preregistered StoppingPlan with looks "
            "was provided; refusing fake sequential analysis"
        )
    return stopping_plan


__all__ = [
    "StoppingPlan",
    "alpha_spent_at_look",
    "obrien_fleming_spend",
    "pocock_spend",
    "require_sequential_plan",
]
