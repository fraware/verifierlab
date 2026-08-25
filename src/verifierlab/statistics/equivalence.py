"""Equivalence testing (TOST-compatible) — never non-rejection-as-equivalence (WP-06)."""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any


def paired_binary_tost(
    before: Sequence[int],
    after: Sequence[int],
    *,
    margin: float,
    alpha: float = 0.05,
) -> dict[str, Any]:
    """TOST for paired binary proportions (mean difference within ±margin).

    Uses a normal approximation on paired differences with Wald intervals.
    Equivalence is declared only when *both* one-sided tests reject at ``alpha``.
    Non-rejection of a superiority/difference null is never treated as equivalence.
    """
    if len(before) != len(after) or not before:
        return {
            "method": "paired_binary_tost",
            "status": "indeterminate",
            "equivalent": False,
            "reason": "empty_or_unpaired",
            "margin": float(margin),
            "alpha": float(alpha),
        }
    if margin <= 0:
        raise ValueError("equivalence margin must be positive")
    diffs = [float(a) - float(b) for a, b in zip(after, before, strict=True)]
    n = len(diffs)
    mean = sum(diffs) / n
    if n == 1:
        se = 0.0
    else:
        var = sum((d - mean) ** 2 for d in diffs) / (n - 1)
        se = math.sqrt(var / n)
    # One-sided tests: H0: mean <= -margin and H0: mean >= +margin
    # Reject lower if (mean + margin) / se > z_alpha
    # Reject upper if (margin - mean) / se > z_alpha
    z = _z_one_sided(alpha)
    if se <= 0:
        lower_reject = mean > -margin
        upper_reject = mean < margin
        p_lower = 0.0 if lower_reject else 1.0
        p_upper = 0.0 if upper_reject else 1.0
    else:
        t_lower = (mean + margin) / se
        t_upper = (margin - mean) / se
        lower_reject = t_lower > z
        upper_reject = t_upper > z
        p_lower = _norm_sf(t_lower)
        p_upper = _norm_sf(t_upper)
    equivalent = bool(lower_reject and upper_reject)
    return {
        "method": "paired_binary_tost",
        "status": "estimated",
        "equivalent": equivalent,
        "estimate": mean,
        "se": se,
        "n_pairs": n,
        "margin": float(margin),
        "alpha": float(alpha),
        "p_lower": p_lower,
        "p_upper": p_upper,
        "reject_lower_null": lower_reject,
        "reject_upper_null": upper_reject,
        "note": "equivalence requires both one-sided TOST rejections",
    }


def _z_one_sided(alpha: float) -> float:
    # Φ^{-1}(1-alpha)
    table = {0.1: 1.2815515655446004, 0.05: 1.6448536269514722, 0.01: 2.3263478740408408}
    if alpha in table:
        return table[alpha]
    p = 1 - alpha
    t = math.sqrt(-2 * math.log(max(1e-12, 1 - p)))
    return t - (2.515517 + 0.802853 * t + 0.010328 * t * t) / (
        1 + 1.432788 * t + 0.189269 * t * t + 0.001308 * t * t * t
    )


def _norm_sf(z: float) -> float:
    """Survival function 1-Φ(z)."""
    return 0.5 * math.erfc(z / math.sqrt(2.0))


__all__ = ["paired_binary_tost"]
