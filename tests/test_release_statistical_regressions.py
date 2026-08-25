"""Release-blocking statistical regression tests."""

from __future__ import annotations

import math

import pytest

from verifierlab.statistics.equivalence import paired_binary_tost
from verifierlab.statistics.intervals import cluster_bootstrap
from verifierlab.statistics.sequential import pocock_spend


def test_cluster_bootstrap_uses_same_cluster_weighted_estimand_in_replicates() -> None:
    # Unequal cluster sizes expose the former estimand mismatch. With seed=4,
    # the one bootstrap replicate samples each cluster once. A cluster-weighted
    # replicate is therefore 0.5; flattening observations would produce 1/11.
    interval = cluster_bootstrap([[1], [0] * 10], samples=1, seed=4)
    assert interval.estimate == pytest.approx(0.5)
    assert interval.low == pytest.approx(0.5)
    assert interval.high == pytest.approx(0.5)
    assert interval.n == 2


def test_paired_equivalence_single_pair_is_indeterminate() -> None:
    result = paired_binary_tost([0], [0], margin=0.1)
    assert result["status"] == "indeterminate"
    assert result["equivalent"] is False
    assert result["reason"] == "insufficient_pairs_for_equivalence"


def test_paired_equivalence_zero_variance_is_indeterminate() -> None:
    result = paired_binary_tost([0] * 8, [0] * 8, margin=0.1)
    assert result["status"] == "indeterminate"
    assert result["equivalent"] is False
    assert result["reason"] == "degenerate_zero_variance"


def test_pocock_spending_is_continuous_lan_demets_family() -> None:
    alpha = 0.05
    half = pocock_spend(alpha, 0.5, n_looks=4)
    expected = alpha * math.log(1.0 + (math.e - 1.0) * 0.5)
    assert half == pytest.approx(expected)
    assert half != pytest.approx(alpha * 0.5)
    assert 0.0 < half < pocock_spend(alpha, 0.75) < alpha
    assert pocock_spend(alpha, 1.0) == pytest.approx(alpha)
