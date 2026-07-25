"""Provenance ledger for budget spend and overrun recording."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from verifierlab.budgets.budget import Budget, OverrunPolicy


class OverrunRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1"
    dimension: str
    limit: float
    actual: float
    policy: OverrunPolicy
    stopped: bool
    message: str


class LedgerSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1"
    queries: int = 0
    steps: int = 0
    tokens: int = 0
    wall_time_s: float = 0.0
    cost_usd: float = 0.0
    overruns: list[OverrunRecord] = Field(default_factory=list)
    events: list[dict[str, Any]] = Field(default_factory=list)


class BudgetExceeded(RuntimeError):
    """Raised when overrun policy is STOP and a limit is exceeded."""

    def __init__(self, record: OverrunRecord) -> None:
        self.record = record
        super().__init__(record.message)


@dataclass
class ProvenanceLedger:
    """Tracks multi-dimension spend against a :class:`Budget`."""

    budget: Budget
    queries: int = 0
    steps: int = 0
    tokens: int = 0
    cost_usd: float = 0.0
    _started_at: float = field(default_factory=time.monotonic)
    _wall_time_s: float = 0.0
    overruns: list[OverrunRecord] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    stopped: bool = False

    def wall_time_s(self) -> float:
        if self.stopped:
            return self._wall_time_s
        return time.monotonic() - self._started_at

    def record_event(self, kind: str, **payload: Any) -> None:
        self.events.append({"kind": kind, **payload})

    def add_queries(self, n: int = 1) -> None:
        self.queries += n
        self.record_event("queries", amount=n, total=self.queries)
        self._check("queries", self.queries, self.budget.max_queries)

    def add_steps(self, n: int = 1) -> None:
        self.steps += n
        self.record_event("steps", amount=n, total=self.steps)
        self._check("steps", self.steps, self.budget.max_steps)

    def add_tokens(self, n: int) -> None:
        self.tokens += n
        self.record_event("tokens", amount=n, total=self.tokens)
        self._check("tokens", self.tokens, self.budget.max_tokens)

    def add_cost_usd(self, amount: float) -> None:
        self.cost_usd += amount
        self.record_event("cost_usd", amount=amount, total=self.cost_usd)
        self._check("cost_usd", self.cost_usd, self.budget.max_cost_usd)

    def sync_wall_time(self) -> None:
        elapsed = self.wall_time_s()
        self._check("wall_time_s", elapsed, self.budget.max_wall_time_s)

    def _check(self, dimension: str, actual: float, limit: float | int | None) -> None:
        if limit is None or actual <= float(limit):
            return
        stopped = self.budget.overrun_policy == OverrunPolicy.STOP
        record = OverrunRecord(
            dimension=dimension,
            limit=float(limit),
            actual=float(actual),
            policy=self.budget.overrun_policy,
            stopped=stopped,
            message=f"budget exceeded on {dimension}: {actual} > {limit}",
        )
        self.overruns.append(record)
        self.record_event("overrun", **record.model_dump(mode="json"))
        if stopped:
            self.stopped = True
            self._wall_time_s = self.wall_time_s()
            raise BudgetExceeded(record)

    def snapshot(self) -> LedgerSnapshot:
        return LedgerSnapshot(
            queries=self.queries,
            steps=self.steps,
            tokens=self.tokens,
            wall_time_s=self.wall_time_s(),
            cost_usd=self.cost_usd,
            overruns=list(self.overruns),
            events=list(self.events),
        )

    def to_dict(self) -> dict[str, Any]:
        return self.snapshot().model_dump(mode="json")

    def reconcile(self) -> list[str]:
        """Detect budget undercount / event-total drift (adversarial self-check).

        Replays additive events and compares reconstructed totals to the live
        counters. Returns a list of human-readable mismatch messages (empty
        means consistent).
        """
        recon = {"queries": 0, "steps": 0, "tokens": 0, "cost_usd": 0.0}
        for event in self.events:
            kind = event.get("kind")
            amount = event.get("amount")
            if kind == "queries" and isinstance(amount, (int, float)):
                recon["queries"] += int(amount)
            elif kind == "steps" and isinstance(amount, (int, float)):
                recon["steps"] += int(amount)
            elif kind == "tokens" and isinstance(amount, (int, float)):
                recon["tokens"] += int(amount)
            elif kind == "cost_usd" and isinstance(amount, (int, float)):
                recon["cost_usd"] += float(amount)

        mismatches: list[str] = []
        if recon["queries"] != self.queries:
            mismatches.append(
                f"queries undercount/drift: events={recon['queries']} counter={self.queries}"
            )
        if recon["steps"] != self.steps:
            mismatches.append(
                f"steps undercount/drift: events={recon['steps']} counter={self.steps}"
            )
        if recon["tokens"] != self.tokens:
            mismatches.append(
                f"tokens undercount/drift: events={recon['tokens']} counter={self.tokens}"
            )
        if abs(float(recon["cost_usd"]) - float(self.cost_usd)) > 1e-9:
            mismatches.append(
                f"cost_usd undercount/drift: events={recon['cost_usd']} counter={self.cost_usd}"
            )
        return mismatches

    def assert_consistent(self) -> None:
        """Raise ``BudgetUndercount`` if event totals disagree with counters."""
        mismatches = self.reconcile()
        if mismatches:
            raise BudgetUndercount("; ".join(mismatches))


class BudgetUndercount(RuntimeError):
    """Raised when ledger event totals disagree with live counters."""
