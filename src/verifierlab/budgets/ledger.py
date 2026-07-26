"""Provenance ledger for budget spend and overrun recording."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
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

    schema_version: str = "2"
    queries: int = 0
    steps: int = 0
    tokens: int = 0
    wall_time_s: float = 0.0
    cost_usd: float = 0.0
    candidates: int = 0
    compute_units: float = 0.0
    overruns: list[OverrunRecord] = Field(default_factory=list)
    events: list[dict[str, Any]] = Field(default_factory=list)


class BudgetExceeded(RuntimeError):
    """Raised when overrun policy is STOP and a limit is exceeded."""

    def __init__(self, record: OverrunRecord) -> None:
        self.record = record
        super().__init__(record.message)


@dataclass
class ProvenanceLedger:
    """Tracks multi-dimension spend against a :class:`Budget`.

    Mutations are protected by an in-process :class:`threading.Lock` (VALAB-04).
    Process workers use budget vouchers and merge events into the coordinator
    ledger without refunds. Optional ``persist_path`` writes spend events before
    returning so a crash after reserve cannot refund completed queries.
    """

    budget: Budget
    queries: int = 0
    steps: int = 0
    tokens: int = 0
    cost_usd: float = 0.0
    candidates: int = 0
    compute_units: float = 0.0
    _started_at: float = field(default_factory=time.monotonic)
    _wall_time_s: float = 0.0
    overruns: list[OverrunRecord] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    stopped: bool = False
    persist_path: Path | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def wall_time_s(self) -> float:
        if self.stopped:
            return self._wall_time_s
        return time.monotonic() - self._started_at

    def record_event(self, kind: str, **payload: Any) -> None:
        with self._lock:
            self.events.append({"kind": kind, **payload})
            self._persist_unlocked()

    def add_queries(self, n: int = 1) -> None:
        """Meter verifier invocations (broker queries). Alias of query dimension."""
        with self._lock:
            self._stop_if_at_limit_unlocked("queries", self.queries, self.budget.max_queries)
            self.queries += n
            self.events.append({"kind": "queries", "amount": n, "total": self.queries})
            self._persist_unlocked()
            self._check_unlocked("queries", self.queries, self.budget.max_queries)

    def add_steps(self, n: int = 1) -> None:
        with self._lock:
            self._stop_if_at_limit_unlocked("steps", self.steps, self.budget.max_steps)
            self.steps += n
            self.events.append({"kind": "steps", "amount": n, "total": self.steps})
            self._persist_unlocked()
            self._check_unlocked("steps", self.steps, self.budget.max_steps)

    def add_tokens(self, n: int) -> None:
        with self._lock:
            self._stop_if_at_limit_unlocked("tokens", self.tokens, self.budget.max_tokens)
            self.tokens += n
            self.events.append({"kind": "tokens", "amount": n, "total": self.tokens})
            self._persist_unlocked()
            self._check_unlocked("tokens", self.tokens, self.budget.max_tokens)

    def add_cost_usd(self, amount: float) -> None:
        with self._lock:
            self._stop_if_at_limit_unlocked("cost_usd", self.cost_usd, self.budget.max_cost_usd)
            self.cost_usd += amount
            self.events.append({"kind": "cost_usd", "amount": amount, "total": self.cost_usd})
            self._persist_unlocked()
            self._check_unlocked("cost_usd", self.cost_usd, self.budget.max_cost_usd)

    def add_candidates(self, n: int = 1) -> None:
        """Meter candidate generations (BoN / beam / search)."""
        with self._lock:
            self._stop_if_at_limit_unlocked(
                "candidates", self.candidates, self.budget.max_candidates
            )
            self.candidates += n
            self.events.append({"kind": "candidates", "amount": n, "total": self.candidates})
            self._persist_unlocked()
            self._check_unlocked("candidates", self.candidates, self.budget.max_candidates)

    def add_compute_units(self, amount: float = 1.0) -> None:
        """Meter explicit compute units (caller-defined)."""
        with self._lock:
            self._stop_if_at_limit_unlocked(
                "compute_units", self.compute_units, self.budget.max_compute_units
            )
            self.compute_units += amount
            self.events.append(
                {"kind": "compute_units", "amount": amount, "total": self.compute_units}
            )
            self._persist_unlocked()
            self._check_unlocked("compute_units", self.compute_units, self.budget.max_compute_units)

    def sync_wall_time(self) -> None:
        with self._lock:
            elapsed = self.wall_time_s()
            self._check_unlocked("wall_time_s", elapsed, self.budget.max_wall_time_s)

    def _stop_if_at_limit_unlocked(
        self, dimension: str, current: float, limit: float | int | None
    ) -> None:
        """Exact STOP: refuse further increments once the limit is reached."""
        if limit is None or self.budget.overrun_policy != OverrunPolicy.STOP:
            return
        if float(current) < float(limit):
            return
        record = OverrunRecord(
            dimension=dimension,
            limit=float(limit),
            actual=float(current),
            policy=self.budget.overrun_policy,
            stopped=True,
            message=f"budget exceeded on {dimension}: {current} >= {limit}",
        )
        self.overruns.append(record)
        self.events.append({"kind": "overrun", **record.model_dump(mode="json")})
        self.stopped = True
        self._wall_time_s = self.wall_time_s()
        self._persist_unlocked()
        raise BudgetExceeded(record)

    def merge_events(self, events: list[dict[str, Any]], *, refund: bool = False) -> None:
        """Merge worker voucher events into this ledger without refunds.

        Completed query / candidate / compute events remain charged even if the
        worker crashed after reserve (``refund`` must stay False).
        """
        if refund:
            raise ValueError("ledger merges never refund completed spend")
        with self._lock:
            for event in events:
                kind = event.get("kind")
                amount = event.get("amount")
                if kind == "queries" and isinstance(amount, (int, float)):
                    self.queries += int(amount)
                    self.events.append(
                        {"kind": "queries", "amount": int(amount), "total": self.queries}
                    )
                    self._check_unlocked("queries", self.queries, self.budget.max_queries)
                elif kind == "steps" and isinstance(amount, (int, float)):
                    self.steps += int(amount)
                    self.events.append(
                        {"kind": "steps", "amount": int(amount), "total": self.steps}
                    )
                    self._check_unlocked("steps", self.steps, self.budget.max_steps)
                elif kind == "tokens" and isinstance(amount, (int, float)):
                    self.tokens += int(amount)
                    self.events.append(
                        {"kind": "tokens", "amount": int(amount), "total": self.tokens}
                    )
                    self._check_unlocked("tokens", self.tokens, self.budget.max_tokens)
                elif kind == "cost_usd" and isinstance(amount, (int, float)):
                    self.cost_usd += float(amount)
                    self.events.append(
                        {
                            "kind": "cost_usd",
                            "amount": float(amount),
                            "total": self.cost_usd,
                        }
                    )
                    self._check_unlocked("cost_usd", self.cost_usd, self.budget.max_cost_usd)
                elif kind == "candidates" and isinstance(amount, (int, float)):
                    self.candidates += int(amount)
                    self.events.append(
                        {
                            "kind": "candidates",
                            "amount": int(amount),
                            "total": self.candidates,
                        }
                    )
                    self._check_unlocked("candidates", self.candidates, self.budget.max_candidates)
                elif kind == "compute_units" and isinstance(amount, (int, float)):
                    self.compute_units += float(amount)
                    self.events.append(
                        {
                            "kind": "compute_units",
                            "amount": float(amount),
                            "total": self.compute_units,
                        }
                    )
                    self._check_unlocked(
                        "compute_units",
                        self.compute_units,
                        self.budget.max_compute_units,
                    )
                else:
                    # Provenance-only events (verifier_query, overrun, …).
                    self.events.append(dict(event))
            self._persist_unlocked()

    def _persist_unlocked(self) -> None:
        if self.persist_path is None:
            return
        path = Path(self.persist_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        import json

        payload = {
            "queries": self.queries,
            "steps": self.steps,
            "tokens": self.tokens,
            "cost_usd": self.cost_usd,
            "candidates": self.candidates,
            "compute_units": self.compute_units,
            "events": list(self.events),
            "overruns": [o.model_dump(mode="json") for o in self.overruns],
            "stopped": self.stopped,
        }
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(path)

    def flush(self) -> None:
        """Persist current ledger state when ``persist_path`` is set."""
        with self._lock:
            self._persist_unlocked()

    def load_persisted(self) -> None:
        """Reload counters from ``persist_path`` (crash recovery)."""
        if self.persist_path is None or not Path(self.persist_path).is_file():
            return
        import json

        with self._lock:
            data = json.loads(Path(self.persist_path).read_text(encoding="utf-8"))
            self.queries = int(data.get("queries") or 0)
            self.steps = int(data.get("steps") or 0)
            self.tokens = int(data.get("tokens") or 0)
            self.cost_usd = float(data.get("cost_usd") or 0.0)
            self.candidates = int(data.get("candidates") or 0)
            self.compute_units = float(data.get("compute_units") or 0.0)
            self.events = list(data.get("events") or [])
            self.overruns = [OverrunRecord.model_validate(o) for o in data.get("overruns") or []]
            self.stopped = bool(data.get("stopped"))

    def restore_spend(
        self,
        *,
        queries: int = 0,
        steps: int = 0,
        tokens: int = 0,
        cost_usd: float = 0.0,
        candidates: int = 0,
        compute_units: float = 0.0,
        events: list[dict[str, Any]] | None = None,
        overruns: list[OverrunRecord] | None = None,
        stopped: bool = False,
    ) -> None:
        """Restore counters from a prior incomplete run without re-emitting charges.

        Used by LocalLauncher crash/resume so completed work stays charged and
        remaining budget vouchers stay exact (VALAB-04 / VALAB-05).
        """
        with self._lock:
            self.queries = int(queries)
            self.steps = int(steps)
            self.tokens = int(tokens)
            self.cost_usd = float(cost_usd)
            self.candidates = int(candidates)
            self.compute_units = float(compute_units)
            self.events = list(events or [])
            self.overruns = list(overruns or [])
            self.stopped = bool(stopped)
            self._persist_unlocked()

    def _check_unlocked(self, dimension: str, actual: float, limit: float | int | None) -> None:
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
        self.events.append({"kind": "overrun", **record.model_dump(mode="json")})
        self._persist_unlocked()
        if stopped:
            self.stopped = True
            self._wall_time_s = self.wall_time_s()
            raise BudgetExceeded(record)

    def snapshot(self) -> LedgerSnapshot:
        with self._lock:
            return LedgerSnapshot(
                queries=self.queries,
                steps=self.steps,
                tokens=self.tokens,
                wall_time_s=self.wall_time_s(),
                cost_usd=self.cost_usd,
                candidates=self.candidates,
                compute_units=self.compute_units,
                overruns=list(self.overruns),
                events=list(self.events),
            )

    def to_dict(self) -> dict[str, Any]:
        return self.snapshot().model_dump(mode="json")

    def reconcile(self) -> list[str]:
        """Detect budget undercount / event-total drift (adversarial self-check)."""
        recon: dict[str, float] = {
            "queries": 0,
            "steps": 0,
            "tokens": 0,
            "cost_usd": 0.0,
            "candidates": 0,
            "compute_units": 0.0,
        }
        with self._lock:
            events = list(self.events)
            queries = self.queries
            steps = self.steps
            tokens = self.tokens
            cost_usd = self.cost_usd
            candidates = self.candidates
            compute_units = self.compute_units
        for event in events:
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
            elif kind == "candidates" and isinstance(amount, (int, float)):
                recon["candidates"] += int(amount)
            elif kind == "compute_units" and isinstance(amount, (int, float)):
                recon["compute_units"] += float(amount)

        mismatches: list[str] = []
        if recon["queries"] != queries:
            mismatches.append(
                f"queries undercount/drift: events={recon['queries']} counter={queries}"
            )
        if recon["steps"] != steps:
            mismatches.append(f"steps undercount/drift: events={recon['steps']} counter={steps}")
        if recon["tokens"] != tokens:
            mismatches.append(f"tokens undercount/drift: events={recon['tokens']} counter={tokens}")
        if abs(float(recon["cost_usd"]) - float(cost_usd)) > 1e-9:
            mismatches.append(
                f"cost_usd undercount/drift: events={recon['cost_usd']} counter={cost_usd}"
            )
        if recon["candidates"] != candidates:
            mismatches.append(
                f"candidates undercount/drift: events={recon['candidates']} counter={candidates}"
            )
        if abs(float(recon["compute_units"]) - float(compute_units)) > 1e-9:
            mismatches.append(
                f"compute_units undercount/drift: events={recon['compute_units']} "
                f"counter={compute_units}"
            )
        return mismatches

    def assert_consistent(self) -> None:
        """Raise ``BudgetUndercount`` if event totals disagree with counters."""
        mismatches = self.reconcile()
        if mismatches:
            raise BudgetUndercount("; ".join(mismatches))


class BudgetUndercount(RuntimeError):
    """Raised when ledger event totals disagree with live counters."""
