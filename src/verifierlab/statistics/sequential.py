"""Lan-DeMets / O'Brien-Fleming alpha spending for preregistered looks (WP-06).

Fail closed when ``sequential_alpha`` is declared without a preregistered
``StoppingPlan``. This is not a decorative path.
"""

from __future__ import annotations

import math
from typing import Any

from verifierlab.config.preregistration import StoppingPlan


def _z_alpha(alpha: float) -> float:
    table = {0.1: 1.6448536269514722, 0.05: 1.959963984540054, 0.01: 2.5758293035489004}
    if alpha in table:
        return table[alpha]
    p = 1 - alpha / 2
    t = math.sqrt(-2 * math.log(max(1e-12, 1 - p)))
    return t - (2.515517 + 0.802853 * t + 0.010328 * t * t) / (
        1 + 1.432788 * t + 0.189269 * t * t + 0.001308 * t * t * t
    )


def obrien_fleming_spend(alpha: float, information_fraction: float) -> float:
    """Approximate O'Brien-Fleming cumulative alpha spent at information t.

    Uses the Lan-DeMets approximation ``2(1-Phi(z_{alpha/2}/sqrt(t)))`` for two-sided tests.
    """
    if information_fraction <= 0:
        return 0.0
    if information_fraction >= 1.0:
        return float(alpha)
    z = _z_alpha(alpha)
    boundary = z / math.sqrt(information_fraction)
    return min(float(alpha), 2.0 * (0.5 * math.erfc(boundary / math.sqrt(2.0))))


def pocock_spend(alpha: float, information_fraction: float, n_looks: int) -> float:
    """Uniform Pocock-style cumulative spend proportional to look index."""
    if information_fraction <= 0:
        return 0.0
    if information_fraction >= 1.0:
        return float(alpha)
    look_idx = max(1, min(n_looks, math.ceil(information_fraction * n_looks)))
    return float(alpha) * (look_idx / n_looks)


def alpha_spent_at_look(plan: StoppingPlan, look_index: int) -> dict[str, Any]:
    """Return cumulative and incremental alpha at a 0-based look index."""
    if look_index < 0 or look_index >= len(plan.looks):
        raise ValueError(f"look_index out of range: {look_index}")
    t = float(plan.looks[look_index])
    if plan.spending_function == "obrien_fleming":
        cumulative = obrien_fleming_spend(plan.nominal_alpha, t)
    else:
        cumulative = pocock_spend(plan.nominal_alpha, t, len(plan.looks))
    prev = 0.0
    if look_index > 0:
        t_prev = float(plan.looks[look_index - 1])
        if plan.spending_function == "obrien_fleming":
            prev = obrien_fleming_spend(plan.nominal_alpha, t_prev)
        else:
            prev = pocock_spend(plan.nominal_alpha, t_prev, len(plan.looks))
    incremental = max(0.0, cumulative - prev)
    return {
        "look_index": look_index,
        "information_fraction": t,
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
