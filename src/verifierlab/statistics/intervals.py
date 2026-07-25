"""Wilson/exact CIs, bootstrap helpers, robustness curves, power analysis.

Limitations (documented honestly):
- Wilson uses a fixed z-table for common alphas with a rational fallback.
- Clopper-Pearson uses a pure-Python regularized incomplete beta (continued
  fraction + series) - no SciPy dependency in the base package. Extremely
  skewed (a,b) near machine limits may lose a few ulps vs SciPy; golden tests
  lock common (successes, n, alpha) vectors.
- Bootstrap helpers use Python's ``random.Random`` (not cryptographic).
"""

from __future__ import annotations

import math
import random
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Interval:
    estimate: float
    low: float
    high: float
    method: str
    n: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "estimate": self.estimate,
            "low": self.low,
            "high": self.high,
            "method": self.method,
            "n": self.n,
        }


def wilson_interval(successes: int, n: int, *, alpha: float = 0.05) -> Interval:
    """Wilson score interval for a binomial proportion."""
    if n <= 0:
        return Interval(0.0, 0.0, 1.0, "wilson", 0)
    if successes < 0 or successes > n:
        raise ValueError(f"successes must be in [0, n], got {successes} / {n}")
    z = _z_alpha(alpha)
    p = successes / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return Interval(p, max(0.0, center - margin), min(1.0, center + margin), "wilson", n)


def exact_clopper_pearson(successes: int, n: int, *, alpha: float = 0.05) -> Interval:
    """Central Clopper-Pearson exact interval via beta quantiles.

    low  = BetaInv(alpha/2; successes, n-successes+1)   when successes > 0 else 0
    high = BetaInv(1-alpha/2; successes+1, n-successes) when successes < n else 1
    """
    if n <= 0:
        return Interval(0.0, 0.0, 1.0, "exact", 0)
    if successes < 0 or successes > n:
        raise ValueError(f"successes must be in [0, n], got {successes} / {n}")
    p = successes / n
    low = _beta_ppf(alpha / 2, successes, n - successes + 1) if successes > 0 else 0.0
    high = (
        _beta_ppf(1 - alpha / 2, successes + 1, n - successes) if successes < n else 1.0
    )
    return Interval(p, float(low), float(high), "exact", n)


def _z_alpha(alpha: float) -> float:
    # Inverse CDF for standard normal; table for common alphas + rational approx.
    table = {0.1: 1.6448536269514722, 0.05: 1.959963984540054, 0.01: 2.5758293035489004}
    if alpha in table:
        return table[alpha]
    # Beasley-Springer/Moro-style rational approximation for Phi^{-1}(1-alpha/2)
    # used as two-sided z for Wilson / power helpers.
    p = 1 - alpha / 2
    t = math.sqrt(-2 * math.log(max(1e-12, 1 - p)))
    return t - (2.515517 + 0.802853 * t + 0.010328 * t * t) / (
        1 + 1.432788 * t + 0.189269 * t * t + 0.001308 * t * t * t
    )


def _beta_ppf(p: float, a: float, b: float) -> float:
    """Inverse regularized incomplete beta via bisection on I_x(a,b)."""
    if p <= 0:
        return 0.0
    if p >= 1:
        return 1.0
    if a <= 0 or b <= 0:
        raise ValueError(f"beta parameters must be positive, got a={a}, b={b}")
    lo, hi = 0.0, 1.0
    for _ in range(80):
        mid = 0.5 * (lo + hi)
        if _betainc(mid, a, b) < p:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


def _betainc(x: float, a: float, b: float) -> float:
    """Regularized incomplete beta I_x(a,b).

    Uses the power series when x is below the mean switch point, otherwise the
    continued-fraction complement via the identity I_x(a,b) = 1 - I_{1-x}(b,a).
    """
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    if a <= 0.0 or b <= 0.0:
        raise ValueError(f"beta parameters must be positive, got a={a}, b={b}")

    # Switch to the complementary argument when it yields faster convergence.
    use_complement = x > (a + 1.0) / (a + b + 2.0)
    if use_complement:
        return 1.0 - _betainc_series(1.0 - x, b, a)
    return _betainc_series(x, a, b)


def _betainc_series(x: float, a: float, b: float) -> float:
    """I_x(a,b) via power series + Lentz continued fraction hybrid."""
    # Prefactor: x^a (1-x)^b / (a B(a,b))
    ln_beta = math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)
    log_front = a * math.log(x) + b * math.log1p(-x) - ln_beta - math.log(a)
    if log_front < -700:
        return 0.0
    front = math.exp(log_front)

    # Continued fraction for the incomplete beta (Lentz).
    # See Numerical Recipes / AS 26.5.8.
    eps = 1e-14
    fpmin = 1e-300
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < fpmin:
        d = fpmin
    d = 1.0 / d
    h = d
    for m in range(1, 200):
        m2 = 2 * m
        # Even step
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        h *= d * c
        # Odd step
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return min(1.0, max(0.0, front * h))


def cluster_bootstrap(
    clusters: Sequence[Sequence[int]],
    *,
    alpha: float = 0.05,
    samples: int = 1000,
    seed: int = 0,
) -> Interval:
    """Bootstrap CI on mean rate where each cluster is a Bernoulli mean."""
    rng = random.Random(seed)
    if not clusters:
        return Interval(0.0, 0.0, 1.0, "cluster_bootstrap", 0)
    rates = []
    for _ in range(samples):
        chosen = [clusters[rng.randrange(len(clusters))] for _ in range(len(clusters))]
        flat = [x for c in chosen for x in c]
        rates.append(sum(flat) / len(flat) if flat else 0.0)
    rates.sort()
    estimate = sum(sum(c) / len(c) for c in clusters if c) / max(1, len(clusters))
    lo = rates[int(alpha / 2 * (samples - 1))]
    hi = rates[int((1 - alpha / 2) * (samples - 1))]
    return Interval(estimate, lo, hi, "cluster_bootstrap", len(clusters))


def paired_bootstrap(
    a: Sequence[float],
    b: Sequence[float],
    *,
    alpha: float = 0.05,
    samples: int = 1000,
    seed: int = 0,
) -> Interval:
    """Bootstrap CI on mean(a - b)."""
    if len(a) != len(b) or not a:
        return Interval(0.0, 0.0, 0.0, "paired_bootstrap", 0)
    rng = random.Random(seed)
    diffs = [x - y for x, y in zip(a, b, strict=True)]
    boots = []
    for _ in range(samples):
        sample = [diffs[rng.randrange(len(diffs))] for _ in range(len(diffs))]
        boots.append(sum(sample) / len(sample))
    boots.sort()
    est = sum(diffs) / len(diffs)
    lo = boots[int(alpha / 2 * (samples - 1))]
    hi = boots[int((1 - alpha / 2) * (samples - 1))]
    return Interval(est, lo, hi, "paired_bootstrap", len(diffs))


def robustness_curve(
    scores: Sequence[float],
    labels_invalid: Sequence[bool],
    *,
    thresholds: Sequence[float] | None = None,
) -> list[dict[str, float]]:
    """FAR/FRR vs threshold curve for continuous scores (accept if score >= t).

    ``labels_invalid`` is True when ground truth marks the sample invalid.
    Also returns true-positive / false-negative rates among valid samples.
    """
    if thresholds is None:
        thresholds = [i / 10 for i in range(11)]
    curve: list[dict[str, float]] = []
    for t in thresholds:
        fp = tn = tp = fn = 0
        for score, invalid in zip(scores, labels_invalid, strict=True):
            accepted = score >= t
            if invalid and accepted:
                fp += 1
            elif invalid and not accepted:
                tn += 1
            elif (not invalid) and accepted:
                tp += 1
            else:
                fn += 1
        far_denom = fp + tn
        frr_denom = fn + tp
        curve.append(
            {
                "threshold": float(t),
                "far": (fp / far_denom) if far_denom else 0.0,
                "frr": (fn / frr_denom) if frr_denom else 0.0,
                "fp": float(fp),
                "tn": float(tn),
                "tp": float(tp),
                "fn": float(fn),
            }
        )
    return curve


def time_to_exploit(
    event_times: Sequence[float],
    *,
    exploited: Sequence[bool],
    max_time: float | None = None,
) -> dict[str, Any]:
    """Time-to-first-exploit summary with right-censoring support.

    Parameters
    ----------
    event_times:
        Query/step/wall-time index of each trial endpoint (exploit or censor).
    exploited:
        True when an exploit was observed at ``event_times[i]``; False means
        right-censored (budget exhausted / episode ended without exploit).
    max_time:
        Optional study horizon; times above it are treated as censored at
        ``max_time``.
    """
    if len(event_times) != len(exploited):
        raise ValueError("event_times and exploited must have equal length")
    if not event_times:
        return {
            "schema_version": "1",
            "n": 0,
            "n_events": 0,
            "n_censored": 0,
            "median_time": None,
            "mean_time_events": None,
            "horizon": max_time,
            "method": "tte_summary",
        }

    times: list[float] = []
    events: list[bool] = []
    for t, hit in zip(event_times, exploited, strict=True):
        tt = float(t)
        if max_time is not None and tt > float(max_time):
            times.append(float(max_time))
            events.append(False)
        else:
            times.append(tt)
            events.append(bool(hit))

    event_only = [t for t, e in zip(times, events, strict=True) if e]
    n_events = len(event_only)
    n_censored = len(times) - n_events
    median = _median(sorted(event_only)) if event_only else None
    mean_events = (sum(event_only) / n_events) if n_events else None
    return {
        "schema_version": "1",
        "n": len(times),
        "n_events": n_events,
        "n_censored": n_censored,
        "median_time": median,
        "mean_time_events": mean_events,
        "horizon": max_time,
        "method": "tte_summary",
    }


def kaplan_meier_survival(
    event_times: Sequence[float],
    *,
    exploited: Sequence[bool],
) -> list[dict[str, float]]:
    """Kaplan-Meier survival curve S(t) = P(no exploit by time t).

    ``exploited`` True marks an event (exploit); False is right-censored.
    Returns step-function points sorted by time. Empty input → [].
    """
    if len(event_times) != len(exploited):
        raise ValueError("event_times and exploited must have equal length")
    if not event_times:
        return []

    # Group by time: at each distinct time, count events and censorings.
    buckets: dict[float, list[int]] = {}
    for t, hit in zip(event_times, exploited, strict=True):
        key = float(t)
        ev, cens = buckets.setdefault(key, [0, 0])
        if hit:
            buckets[key][0] = ev + 1
        else:
            buckets[key][1] = cens + 1

    at_risk = len(event_times)
    survival = 1.0
    curve: list[dict[str, float]] = [{"time": 0.0, "survival": 1.0, "at_risk": float(at_risk)}]
    for t in sorted(buckets):
        events, censored = buckets[t]
        if at_risk <= 0:
            break
        if events:
            survival *= 1.0 - (events / at_risk)
        curve.append(
            {
                "time": float(t),
                "survival": float(survival),
                "at_risk": float(at_risk),
                "events": float(events),
                "censored": float(censored),
            }
        )
        at_risk -= events + censored
    return curve


def _median(sorted_vals: Sequence[float]) -> float | None:
    if not sorted_vals:
        return None
    n = len(sorted_vals)
    mid = n // 2
    if n % 2:
        return float(sorted_vals[mid])
    return float(0.5 * (sorted_vals[mid - 1] + sorted_vals[mid]))


def power_binomial(
    *,
    p0: float,
    p1: float,
    n: int,
    alpha: float = 0.05,
) -> dict[str, Any]:
    """Approximate power for detecting proportion shift p0→p1 (normal approx)."""
    z = _z_alpha(alpha)
    se0 = math.sqrt(max(p0 * (1 - p0), 1e-12) / max(n, 1))
    se1 = math.sqrt(max(p1 * (1 - p1), 1e-12) / max(n, 1))
    # One-sided-ish detection of increase.
    crit = p0 + z * se0
    power = 1 - _phi((crit - p1) / max(se1, 1e-12))
    return {
        "schema_version": "1",
        "p0": p0,
        "p1": p1,
        "n": n,
        "alpha": alpha,
        "power": max(0.0, min(1.0, power)),
        "critical_value": crit,
        "method": "normal_approx",
    }


def sample_size_for_power(
    *,
    p0: float,
    p1: float,
    power: float = 0.8,
    alpha: float = 0.05,
    n_max: int = 100_000,
) -> dict[str, Any]:
    lo, hi = 1, n_max
    best = n_max
    while lo <= hi:
        mid = (lo + hi) // 2
        est = power_binomial(p0=p0, p1=p1, n=mid, alpha=alpha)
        if est["power"] >= power:
            best = mid
            hi = mid - 1
        else:
            lo = mid + 1
    return {
        "n": best,
        "target_power": power,
        "achieved": power_binomial(p0=p0, p1=p1, n=best, alpha=alpha),
    }


def _phi(x: float) -> float:
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))
