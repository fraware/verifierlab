"""Wilson/exact CIs, bootstrap helpers, robustness curves, and power analysis.

Limitations:
- Wilson uses a fixed z-table for common alphas with a rational fallback.
- Clopper-Pearson uses a pure-Python regularized incomplete beta; extreme
  parameters near machine limits may differ slightly from SciPy.
- Bootstrap helpers use Python's ``random.Random`` (not cryptographic).
- Optional ``[stats]`` SciPy support is for offline cross-validation; it is not
  silently substituted into the executable path.
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
    """Central Clopper-Pearson exact interval via beta quantiles."""
    if n <= 0:
        return Interval(0.0, 0.0, 1.0, "exact", 0)
    if successes < 0 or successes > n:
        raise ValueError(f"successes must be in [0, n], got {successes} / {n}")
    p = successes / n
    low = _beta_ppf(alpha / 2, successes, n - successes + 1) if successes > 0 else 0.0
    high = _beta_ppf(1 - alpha / 2, successes + 1, n - successes) if successes < n else 1.0
    return Interval(p, float(low), float(high), "exact", n)


def _z_alpha(alpha: float) -> float:
    table = {0.1: 1.6448536269514722, 0.05: 1.959963984540054, 0.01: 2.5758293035489004}
    if alpha in table:
        return table[alpha]
    probability = 1 - alpha / 2
    t = math.sqrt(-2 * math.log(max(1e-12, 1 - probability)))
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
    low, high = 0.0, 1.0
    for _ in range(80):
        midpoint = 0.5 * (low + high)
        if _betainc(midpoint, a, b) < p:
            low = midpoint
        else:
            high = midpoint
    return 0.5 * (low + high)


def _betainc(x: float, a: float, b: float) -> float:
    """Regularized incomplete beta I_x(a,b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    if a <= 0.0 or b <= 0.0:
        raise ValueError(f"beta parameters must be positive, got a={a}, b={b}")
    use_complement = x > (a + 1.0) / (a + b + 2.0)
    if use_complement:
        return 1.0 - _betainc_series(1.0 - x, b, a)
    return _betainc_series(x, a, b)


def _betainc_series(x: float, a: float, b: float) -> float:
    """I_x(a,b) via a Lentz continued-fraction evaluation."""
    ln_beta = math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)
    log_front = a * math.log(x) + b * math.log1p(-x) - ln_beta - math.log(a)
    if log_front < -700:
        return 0.0
    front = math.exp(log_front)
    epsilon = 1e-14
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
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        h *= d * c
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
        if abs(delta - 1.0) < epsilon:
            break
    return min(1.0, max(0.0, front * h))


def cluster_bootstrap(
    clusters: Sequence[Sequence[int]],
    *,
    alpha: float = 0.05,
    samples: int = 1000,
    seed: int = 0,
) -> Interval:
    """Cluster bootstrap for the equally weighted mean of cluster rates.

    The task/environment cluster is the statistical sampling unit. Both the
    point estimate and every bootstrap replicate therefore average *cluster
    means*, rather than flattening observations and silently changing to an
    observation-weighted estimand when cluster sizes differ.
    """
    nonempty = [tuple(cluster) for cluster in clusters if cluster]
    if not nonempty:
        return Interval(0.0, 0.0, 1.0, "cluster_bootstrap", 0)
    if samples <= 0:
        raise ValueError("cluster_bootstrap samples must be positive")

    cluster_rates = [sum(cluster) / len(cluster) for cluster in nonempty]
    estimate = sum(cluster_rates) / len(cluster_rates)
    rng = random.Random(seed)
    bootstrap_rates: list[float] = []
    for _ in range(samples):
        sampled_rates = [
            cluster_rates[rng.randrange(len(cluster_rates))] for _ in range(len(cluster_rates))
        ]
        bootstrap_rates.append(sum(sampled_rates) / len(sampled_rates))
    bootstrap_rates.sort()
    low = bootstrap_rates[int(alpha / 2 * (samples - 1))]
    high = bootstrap_rates[int((1 - alpha / 2) * (samples - 1))]
    return Interval(estimate, low, high, "cluster_bootstrap", len(nonempty))


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
    differences = [x - y for x, y in zip(a, b, strict=True)]
    boots = []
    for _ in range(samples):
        sample = [differences[rng.randrange(len(differences))] for _ in range(len(differences))]
        boots.append(sum(sample) / len(sample))
    boots.sort()
    estimate = sum(differences) / len(differences)
    low = boots[int(alpha / 2 * (samples - 1))]
    high = boots[int((1 - alpha / 2) * (samples - 1))]
    return Interval(estimate, low, high, "paired_bootstrap", len(differences))


def robustness_curve(
    scores: Sequence[float],
    labels_invalid: Sequence[bool],
    *,
    thresholds: Sequence[float] | None = None,
) -> list[dict[str, float]]:
    """FAR/FRR versus threshold for continuous scores (accept if score >= t)."""
    if thresholds is None:
        thresholds = [index / 10 for index in range(11)]
    curve: list[dict[str, float]] = []
    for threshold in thresholds:
        fp = tn = tp = fn = 0
        for score, invalid in zip(scores, labels_invalid, strict=True):
            accepted = score >= threshold
            if invalid and accepted:
                fp += 1
            elif invalid and not accepted:
                tn += 1
            elif not invalid and accepted:
                tp += 1
            else:
                fn += 1
        far_denom = fp + tn
        frr_denom = fn + tp
        curve.append(
            {
                "threshold": float(threshold),
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

    ``median_time`` is retained for compatibility and is the median among
    observed event times only. ``km_median_time`` is the censoring-aware
    Kaplan-Meier median and should be preferred for scientific analyses.
    """
    if len(event_times) != len(exploited):
        raise ValueError("event_times and exploited must have equal length")
    if not event_times:
        return {
            "schema_version": "2",
            "n": 0,
            "n_events": 0,
            "n_censored": 0,
            "median_time": None,
            "km_median_time": None,
            "mean_time_events": None,
            "horizon": max_time,
            "method": "tte_summary",
        }

    times: list[float] = []
    events: list[bool] = []
    for event_time, hit in zip(event_times, exploited, strict=True):
        time_value = float(event_time)
        if max_time is not None and time_value > float(max_time):
            times.append(float(max_time))
            events.append(False)
        else:
            times.append(time_value)
            events.append(bool(hit))

    event_only = [time_value for time_value, event in zip(times, events, strict=True) if event]
    event_median = _median(sorted(event_only)) if event_only else None
    mean_events = (sum(event_only) / len(event_only)) if event_only else None
    survival = kaplan_meier_survival(times, exploited=events)
    km_median = next(
        (float(point["time"]) for point in survival if point["survival"] <= 0.5),
        None,
    )
    return {
        "schema_version": "2",
        "n": len(times),
        "n_events": len(event_only),
        "n_censored": len(times) - len(event_only),
        "median_time": event_median,
        "km_median_time": km_median,
        "mean_time_events": mean_events,
        "horizon": max_time,
        "method": "tte_summary",
    }


def kaplan_meier_survival(
    event_times: Sequence[float],
    *,
    exploited: Sequence[bool],
) -> list[dict[str, float]]:
    """Kaplan-Meier curve S(t) = P(no exploit by time t)."""
    if len(event_times) != len(exploited):
        raise ValueError("event_times and exploited must have equal length")
    if not event_times:
        return []

    buckets: dict[float, list[int]] = {}
    for event_time, hit in zip(event_times, exploited, strict=True):
        key = float(event_time)
        events, censored = buckets.setdefault(key, [0, 0])
        if hit:
            buckets[key][0] = events + 1
        else:
            buckets[key][1] = censored + 1

    at_risk = len(event_times)
    survival = 1.0
    curve: list[dict[str, float]] = [
        {"time": 0.0, "survival": 1.0, "at_risk": float(at_risk)}
    ]
    for event_time in sorted(buckets):
        events, censored = buckets[event_time]
        if at_risk <= 0:
            break
        if events:
            survival *= 1.0 - events / at_risk
        curve.append(
            {
                "time": float(event_time),
                "survival": float(survival),
                "at_risk": float(at_risk),
                "events": float(events),
                "censored": float(censored),
            }
        )
        at_risk -= events + censored
    return curve


def _median(sorted_values: Sequence[float]) -> float | None:
    if not sorted_values:
        return None
    n = len(sorted_values)
    middle = n // 2
    if n % 2:
        return float(sorted_values[middle])
    return float(0.5 * (sorted_values[middle - 1] + sorted_values[middle]))


def power_binomial(
    *,
    p0: float,
    p1: float,
    n: int,
    alpha: float = 0.05,
) -> dict[str, Any]:
    """Approximate power for detecting a proportion shift p0 to p1."""
    z = _z_alpha(alpha)
    se0 = math.sqrt(max(p0 * (1 - p0), 1e-12) / max(n, 1))
    se1 = math.sqrt(max(p1 * (1 - p1), 1e-12) / max(n, 1))
    critical = p0 + z * se0
    power = 1 - _phi((critical - p1) / max(se1, 1e-12))
    return {
        "schema_version": "1",
        "p0": p0,
        "p1": p1,
        "n": n,
        "alpha": alpha,
        "power": max(0.0, min(1.0, power)),
        "critical_value": critical,
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
    low, high = 1, n_max
    best = n_max
    while low <= high:
        midpoint = (low + high) // 2
        estimate = power_binomial(p0=p0, p1=p1, n=midpoint, alpha=alpha)
        if estimate["power"] >= power:
            best = midpoint
            high = midpoint - 1
        else:
            low = midpoint + 1
    return {
        "n": best,
        "target_power": power,
        "achieved": power_binomial(p0=p0, p1=p1, n=best, alpha=alpha),
    }


def _phi(x: float) -> float:
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))
