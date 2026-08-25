"""Additional Hypothesis property tests for claim-critical surfaces (WP-18)."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from verifierlab.artifacts.canonical import canonicalize, digest_of
from verifierlab.artifacts.schema_registry import (
    _strip_forbidden_maturity_upgrades,
    load_schema_registry,
    migrate_artifact,
)
from verifierlab.budgets import Budget, ProvenanceLedger
from verifierlab.campaigns.lifecycle import LifecycleState, can_transition


@given(
    st.lists(
        st.one_of(
            st.integers(min_value=-50, max_value=50),
            st.booleans(),
            st.none(),
            st.text(max_size=12, alphabet="abcXYZ012"),
        ),
        max_size=8,
    )
)
@settings(max_examples=30, deadline=None)
def test_list_canonicalize_order_preserving(items: list) -> None:
    assert canonicalize(items) == items
    assert digest_of(items) == digest_of(canonicalize(items))


@given(st.integers(min_value=1, max_value=40), st.integers(min_value=0, max_value=40))
@settings(max_examples=25, deadline=None)
def test_budget_ledger_remaining_nonnegative(limit: int, spend: int) -> None:
    from verifierlab.budgets import BudgetExceeded

    budget = Budget(max_queries=limit)
    ledger = ProvenanceLedger(budget=budget)
    used = min(spend, limit)
    for _ in range(used):
        ledger.add_queries(1)
    remaining = ledger.available_queries()
    assert remaining is not None
    assert remaining >= 0
    if used >= limit:
        with pytest.raises(BudgetExceeded):
            ledger.add_queries(1)



def test_lifecycle_transition_matrix_closed() -> None:
    assert can_transition(LifecycleState.DRAFT, LifecycleState.LABEL_RELEASE) is False
    assert can_transition(LifecycleState.FREEZE, LifecycleState.DRAFT) is False
    assert can_transition(LifecycleState.DRAFT, LifecycleState.VALIDATED) is True


@given(st.sampled_from(["internally_verified", "not_implemented", "scientifically_qualified"]))
@settings(max_examples=10, deadline=None)
def test_migration_never_upgrades_maturity(level: str) -> None:
    registry = load_schema_registry()
    payload = {
        "schema_version": "1",
        "strategy": "beam",
        "beam": [[-1.0, 0, {"op": "noop"}]],
        "maturity": level,
    }
    out = migrate_artifact("beam_checkpoint", payload, to_version="2", registry=registry)
    assert out["maturity"] == level


def test_strip_blocks_new_maturity_flags() -> None:
    before = {"schema_version": "1"}
    after = {
        "schema_version": "2",
        "scientifically_qualified": True,
        "security_grade": True,
        "deployment_calibrated": True,
    }
    cleaned = _strip_forbidden_maturity_upgrades(before, after)
    assert "scientifically_qualified" not in cleaned
    assert "security_grade" not in cleaned
    assert "deployment_calibrated" not in cleaned


@pytest.mark.parametrize(
    "src,dst,expected",
    [
        (LifecycleState.ATTACK, LifecycleState.FREEZE, True),
        (LifecycleState.FREEZE, LifecycleState.ADJUDICATION, True),
        (LifecycleState.ADJUDICATION, LifecycleState.LABEL_RELEASE, True),
    ],
)
def test_lifecycle_happy_path(src: LifecycleState, dst: LifecycleState, expected: bool) -> None:
    assert can_transition(src, dst) is expected
