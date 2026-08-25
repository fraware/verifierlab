"""Equivalence testing: never treat non-rejection as equivalence (WP-06)."""

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
    min_pairs: int = 8,
) -> dict[str, Any]:
    """TOST-style analysis for a paired binary mean difference.

    The executable path uses a normal approximation on paired differences.
    Equivalence is declared only when both one-sided tests reject at ``alpha``.
    Small samples and zero-variance samples are explicitly indeterminate rather
    than being allowed to manufacture an equivalence claim.
    """
    if len(before) != len(after) or not before:
        return {
            "method": "paired_binary_tost",
            "status": "indeterminate",
            "equivalent": False,
            "reason": "empty_or_unpaired",
            "margin": float(margin),
            "alpha": float(alpha),
            "min_pairs": int(min_pairs),
        }
    if margin <= 0:
        raise ValueError("equivalence margin must be positive")
    if min_pairs < 2:
        raise ValueError("min_pairs must be at least 2")

    diffs = [float(a) - float(b) for a, b in zip(after, before, strict=True)]
    n = len(diffs)
    mean = sum(diffs) / n
    if n < min_pairs:
        return {
            "method": "paired_binary_tost",
            "status": "indeterminate",
            "equivalent": False,
            "reason": "insufficient_pairs_for_equivalence",
            "estimate": mean,
            "n_pairs": n,
            "margin": float(margin),
            "alpha": float(alpha),
            "min_pairs": int(min_pairs),
        }

    variance = sum((difference - mean) ** 2 for difference in diffs) / (n - 1)
    se = math.sqrt(variance / n)
    if se <= 0.0:
        return {
            "method": "paired_binary_tost",
            "status": "indeterminate",
            "equivalent": False,
            "reason": "degenerate_zero_variance",
            "estimate": mean,
            "se": se,
            "n_pairs": n,
            "margin": float(margin),
            "alpha": float(alpha),
            "min_pairs": int(min_pairs),
        }

    # One-sided tests: H0: mean <= -margin and H0: mean >= +margin.
    z = _z_one_sided(alpha)
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
        "min_pairs": int(min_pairs),
        "p_lower": p_lower,
        "p_upper": p_upper,
        "reject_lower_null": lower_reject,
        "reject_upper_null": upper_reject,
        "note": "equivalence requires both one-sided TOST rejections",
    }


def _z_one_sided(alpha: float) -> float:
    table = {0.1: 1.2815515655446004, 0.05: 1.6448536269514722, 0.01: 2.3263478740408408}
    if alpha in table:
        return table[alpha]
    probability = 1 - alpha
    t = math.sqrt(-2 * math.log(max(1e-12, 1 - probability)))
    return t - (2.515517 + 0.802853 * t + 0.010328 * t * t) / (
        1 + 1.432788 * t + 0.189269 * t * t + 0.001308 * t * t * t
    )


def _norm_sf(z: float) -> float:
    """Return the standard-normal survival function."""
    return 0.5 * math.erfc(z / math.sqrt(2.0))


__all__ = ["paired_binary_tost"]
