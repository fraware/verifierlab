"""Budget and provenance ledger tests."""

from __future__ import annotations

import pytest

from verifierlab.budgets import Budget, BudgetExceeded, OverrunPolicy, ProvenanceLedger


def test_ledger_counts_and_snapshot() -> None:
    budget = Budget(max_queries=10, max_steps=100, overrun_policy=OverrunPolicy.STOP)
    ledger = ProvenanceLedger(budget=budget)
    ledger.add_queries(3)
    ledger.add_steps(5)
    ledger.add_tokens(7)
    ledger.add_cost_usd(0.01)
    snap = ledger.snapshot()
    assert snap.queries == 3
    assert snap.steps == 5
    assert snap.tokens == 7
    assert snap.cost_usd == pytest.approx(0.01)
    assert snap.wall_time_s >= 0.0


def test_stop_policy_raises() -> None:
    budget = Budget(max_queries=1, overrun_policy=OverrunPolicy.STOP)
    ledger = ProvenanceLedger(budget=budget)
    ledger.add_queries(1)
    with pytest.raises(BudgetExceeded) as excinfo:
        ledger.add_queries(1)
    assert excinfo.value.record.dimension == "queries"
    assert ledger.stopped is True


def test_record_policy_continues() -> None:
    budget = Budget(max_queries=1, overrun_policy=OverrunPolicy.RECORD)
    ledger = ProvenanceLedger(budget=budget)
    ledger.add_queries(1)
    ledger.add_queries(1)  # records overrun, does not raise
    assert len(ledger.overruns) == 1
    assert ledger.stopped is False
    assert ledger.queries == 2


def test_budget_requires_limit() -> None:
    with pytest.raises(Exception):  # noqa: B017 — pydantic ValidationError
        Budget()


def test_ledger_reconcile_ok() -> None:
    budget = Budget(max_queries=10, overrun_policy=OverrunPolicy.STOP)
    ledger = ProvenanceLedger(budget=budget)
    ledger.add_queries(2)
    ledger.add_steps(3)
    assert ledger.reconcile() == []
    ledger.assert_consistent()
