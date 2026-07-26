"""Local asyncio launcher with process workers, idempotency, and resume."""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Callable
from concurrent.futures import Executor, ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.cas import ContentAddressedStore
from verifierlab.budgets.budget import Budget
from verifierlab.budgets.ledger import BudgetExceeded, OverrunRecord, ProvenanceLedger
from verifierlab.campaigns.episode import trajectory_commitment
from verifierlab.targets.fake import FakeEnvironment, fake_refund_verifier, propose_fake_action
from verifierlab.verifiers.broker import VerifierBroker
from verifierlab.verifiers.profile import VerifierProfile


class WorkUnitStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    CANCELLED = "cancelled"
    FAILED = "failed"


def _run_fake_work_unit(payload: dict[str, Any]) -> dict[str, Any]:
    """Process-pool entry point (must be picklable / top-level).

    Fake smoke path aligns with the campaign worker: no GT, broker-metered
    verifier query, commitment = digest(trajectory || nonce).
    """
    unit_id = payload["unit_id"]
    seed = int(payload["seed"])
    unit_index = int(payload["unit_index"])
    max_steps = int(payload.get("max_steps", 3))
    nonce = str(payload.get("commitment_nonce") or f"{unit_id}:{unit_index}")
    access_model = str(payload.get("access_model") or "black-box")

    env = FakeEnvironment(max_steps=max_steps)
    obs = env.reset(seed=seed + unit_index)
    steps_taken = 0
    while steps_taken < max_steps:
        action = propose_fake_action(seed, unit_index + steps_taken)
        result = env.act(action)
        steps_taken += 1
        if result["done"]:
            break
    trajectory = env.finalize()
    profile = VerifierProfile.for_callable(fake_refund_verifier)
    voucher: ProvenanceLedger | None = None
    remaining = payload.get("query_budget_remaining")
    if remaining is not None:
        from verifierlab.budgets.budget import OverrunPolicy

        policy_raw = str(payload.get("budget_overrun_policy") or "stop")
        try:
            policy = OverrunPolicy(policy_raw)
        except ValueError:
            policy = OverrunPolicy.STOP
        voucher = ProvenanceLedger(
            budget=Budget(max_queries=max(0, int(remaining)), overrun_policy=policy)
        )
    broker = VerifierBroker(
        profile=profile,
        verifier=fake_refund_verifier,
        access_model=access_model,
        caller=f"fake:{unit_id}",
        ledger=voucher,
    )
    decision = broker.query(trajectory)
    commitment = trajectory_commitment(trajectory, nonce)
    snap = env.snapshot()
    env2 = FakeEnvironment(max_steps=max_steps)
    env2.restore(snap)

    restored_seed = int(json.loads(snap.decode("utf-8"))["seed"])
    result_body: dict[str, Any] = {
        "schema_version": "2",
        "unit_id": unit_id,
        "seed": seed + unit_index,
        "trajectory": trajectory,
        "commitment": commitment,
        "commitment_nonce": nonce,
        # Preserve None under score_only (do not coerce to False — VALAB-03).
        "verifier_accepted": decision.accepted,
        "verifier_status": decision.status,
        "verifier_score": decision.score,
        "verifier_invocations": broker.event_dicts(),
        "query_count": len(broker.events),
        "gt_valid": None,
        "observation_initial": obs,
        "snapshot_restore_ok": restored_seed == trajectory["seed"] and env2._step == env._step,
        "snapshot_bytes": len(snap),
    }
    if voucher is not None:
        result_body["ledger_events"] = list(voucher.events)
        result_body["candidates"] = voucher.candidates
        result_body["compute_units"] = voucher.compute_units
        result_body["budget_voucher_queries"] = voucher.queries
    from verifierlab.campaigns.episode import _stable_episode_digest_body

    result_body["unit_digest"] = digest_of(_stable_episode_digest_body(result_body))
    return result_body


@dataclass
class LocalLauncher:
    """asyncio coordinator + process (or thread) workers for work units."""

    store: ContentAddressedStore
    run_dir: Path
    budget: Budget
    max_workers: int = 2
    use_processes: bool = True
    ledger: ProvenanceLedger = field(init=False)
    _handles: dict[str, dict[str, Any]] = field(default_factory=dict)
    _cancel_requested: bool = False
    _executor: Executor | None = None

    def __post_init__(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "work_units").mkdir(exist_ok=True)
        self._checkpoint_path = self.run_dir / "checkpoint.json"
        self._spend_path = self.run_dir / "budget_spend.json"
        self.ledger = ProvenanceLedger(budget=self.budget, persist_path=self._spend_path)
        # VALAB-05: incomplete runs (checkpoint present, freeze absent) resume
        # with prior spend restored so completed queries are never refunded or
        # double-charged.
        self._rehydrate_ledger()

    def _rehydrate_ledger(self) -> None:
        """Restore spend from persisted ledger or completed work-unit meters."""
        if self._spend_path.is_file():
            self.ledger.load_persisted()
            return
        wu_dir = self.run_dir / "work_units"
        if not wu_dir.is_dir():
            return
        queries = 0
        steps = 0
        candidates = 0
        compute_units = 0.0
        for path in sorted(wu_dir.glob("*.json")):
            row = json.loads(path.read_text(encoding="utf-8"))
            queries += int(row.get("query_count") or 0)
            traj = row.get("trajectory") or {}
            steps += len(traj.get("steps") or [])
            candidates += int(row.get("candidates") or 0)
            compute_units += float(row.get("compute_units") or 0.0)
        if queries or steps or candidates or compute_units:
            self.ledger.restore_spend(
                queries=queries,
                steps=steps,
                candidates=candidates,
                compute_units=compute_units,
            )

    def _load_checkpoint(self) -> dict[str, Any]:
        if not self._checkpoint_path.is_file():
            return {"schema_version": "1", "completed": {}, "status": "pending"}
        data: dict[str, Any] = json.loads(self._checkpoint_path.read_text(encoding="utf-8"))
        return data

    def _save_checkpoint(self, data: dict[str, Any]) -> None:
        tmp = self._checkpoint_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self._checkpoint_path)

    def submit(self, work_unit: dict[str, Any]) -> str:
        handle = str(work_unit.get("unit_id") or uuid.uuid4())
        work_unit = {**work_unit, "unit_id": handle}
        self._handles[handle] = {
            "status": WorkUnitStatus.PENDING.value,
            "work_unit": work_unit,
            "result": None,
        }
        return handle

    def status(self, handle: str) -> str:
        return str(self._handles[handle]["status"])

    def collect(self, handle: str) -> dict[str, Any]:
        entry = self._handles[handle]
        if entry["result"] is None:
            raise RuntimeError(f"work unit {handle} has no result yet")
        result: dict[str, Any] = entry["result"]
        return result

    def cancel(self, handle: str | None = None) -> None:
        self._cancel_requested = True
        if handle is None:
            for entry in self._handles.values():
                if entry["status"] in {
                    WorkUnitStatus.PENDING.value,
                    WorkUnitStatus.RUNNING.value,
                }:
                    entry["status"] = WorkUnitStatus.CANCELLED.value
            return
        entry = self._handles[handle]
        if entry["status"] in {WorkUnitStatus.PENDING.value, WorkUnitStatus.RUNNING.value}:
            entry["status"] = WorkUnitStatus.CANCELLED.value

    def _unit_result_path(self, unit_id: str) -> Path:
        return self.run_dir / "work_units" / f"{unit_id}.json"

    def _idempotent_load(self, unit_id: str) -> dict[str, Any] | None:
        path = self._unit_result_path(unit_id)
        if path.is_file():
            data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
            return data
        return None

    def _persist_unit(self, result: dict[str, Any]) -> str:
        unit_id = result["unit_id"]
        path = self._unit_result_path(unit_id)
        path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return self.store.put_json(result)

    def persist_unit(self, result: dict[str, Any]) -> str:
        """Persist a work-unit result to the run bundle and CAS (coordinator use)."""
        return self._persist_unit(result)

    def _make_executor(self) -> Executor:
        if self.use_processes:
            return ProcessPoolExecutor(max_workers=self.max_workers)
        return ThreadPoolExecutor(max_workers=self.max_workers)

    async def run_all(
        self,
        work_units: list[dict[str, Any]],
        *,
        executor_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Execute work units with resume and idempotency."""
        fn = executor_fn or _run_fake_work_unit
        checkpoint = self._load_checkpoint()
        completed: dict[str, str] = dict(checkpoint.get("completed") or {})
        results: list[dict[str, Any]] = []

        for wu in work_units:
            self.submit(wu)

        loop = asyncio.get_running_loop()
        self._executor = self._make_executor()
        try:
            pending_handles = [
                h for h, e in self._handles.items() if e["status"] == WorkUnitStatus.PENDING.value
            ]

            async def _one(handle: str) -> None:
                if self._cancel_requested:
                    self._handles[handle]["status"] = WorkUnitStatus.CANCELLED.value
                    return
                existing = self._idempotent_load(handle)
                if existing is not None:
                    self._handles[handle]["status"] = WorkUnitStatus.DONE.value
                    self._handles[handle]["result"] = existing
                    results.append(existing)
                    completed[handle] = existing["unit_digest"]
                    return

                entry = self._handles[handle]
                entry["status"] = WorkUnitStatus.RUNNING.value
                try:
                    # Exact remaining budget voucher for worker-side atomic reserve.
                    self.ledger.sync_wall_time()
                    work_unit = dict(entry["work_unit"])
                    if self.budget.max_queries is not None:
                        remaining = int(self.budget.max_queries) - int(self.ledger.queries)
                        if remaining <= 0 and self.budget.overrun_policy.value == "stop":
                            self.ledger.add_queries(1)
                        work_unit["query_budget_remaining"] = max(0, remaining)
                        work_unit["budget_overrun_policy"] = self.budget.overrun_policy.value
                    result = await loop.run_in_executor(
                        self._executor,
                        fn,
                        work_unit,
                    )
                    # Prefer atomic voucher merge (all dimensions, no mid-batch
                    # drop). Fallback reconstructs meters when workers omit events.
                    voucher_events = result.get("ledger_events")
                    if isinstance(voucher_events, list) and voucher_events:
                        self.ledger.merge_events(voucher_events, refund=False)
                        # Workers meter queries/candidates/compute; steps are often
                        # coordinator-side when the voucher never saw env steps.
                        if not any(
                            isinstance(e, dict) and e.get("kind") == "steps"
                            for e in voucher_events
                        ):
                            steps = len((result.get("trajectory") or {}).get("steps", []))
                            if steps:
                                self.ledger.add_steps(steps)
                    else:
                        query_count = int(
                            result.get("query_count")
                            or len(result.get("verifier_invocations") or [])
                            or 0
                        )
                        if query_count:
                            self.ledger.add_queries(query_count)
                        for inv in result.get("verifier_invocations") or []:
                            if isinstance(inv, dict):
                                self.ledger.record_event(
                                    "verifier_query",
                                    **{
                                        k: inv[k]
                                        for k in (
                                            "query_id",
                                            "input_digest",
                                            "output_digest",
                                            "latency_ms",
                                            "caller",
                                            "access_model",
                                            "profile_digest",
                                            "status",
                                        )
                                        if k in inv
                                    },
                                )
                        steps = len((result.get("trajectory") or {}).get("steps", []))
                        if steps:
                            self.ledger.add_steps(steps)
                        cand = int(result.get("candidates") or 0)
                        if cand:
                            self.ledger.add_candidates(cand)
                        compute = float(result.get("compute_units") or 0.0)
                        if compute:
                            self.ledger.add_compute_units(compute)
                    # Persist spend before continuing so a crash cannot refund.
                    self.ledger.flush()
                    self.ledger.assert_consistent()
                    digest = self._persist_unit(result)
                    result = {**result, "cas_digest": digest}
                    self._persist_unit(result)
                    results.append(result)
                    if result.get("unit_digest"):
                        completed[handle] = result["unit_digest"]
                    self._save_checkpoint(
                        {
                            "schema_version": "1",
                            "completed": completed,
                            "status": "running",
                        }
                    )
                    if result.get("budget_stopped"):
                        entry["status"] = WorkUnitStatus.CANCELLED.value
                        entry["result"] = result
                        record = OverrunRecord(
                            dimension="queries",
                            limit=float(self.budget.max_queries or 0),
                            actual=float(self.ledger.queries),
                            policy=self.budget.overrun_policy,
                            stopped=True,
                            message="worker budget voucher exhausted",
                        )
                        self.ledger.overruns.append(record)
                        self.cancel()
                        raise BudgetExceeded(record)
                    entry["status"] = WorkUnitStatus.DONE.value
                    entry["result"] = result
                except BudgetExceeded:
                    entry["status"] = WorkUnitStatus.CANCELLED.value
                    self.cancel()
                    raise
                except Exception as exc:
                    # Persist failed units so campaigns remain inspectable.
                    fail_result: dict[str, Any] = {
                        "schema_version": "1",
                        "unit_id": handle,
                        "error": str(exc),
                        "error_type": type(exc).__name__,
                        "cohort": entry["work_unit"].get("cohort"),
                        "strategy": entry["work_unit"].get("strategy"),
                        "status": WorkUnitStatus.FAILED.value,
                    }
                    fail_result["unit_digest"] = digest_of(
                        {k: v for k, v in fail_result.items() if k != "unit_digest"}
                    )
                    digest = self._persist_unit(fail_result)
                    fail_result = {**fail_result, "cas_digest": digest}
                    self._persist_unit(fail_result)
                    entry["status"] = WorkUnitStatus.FAILED.value
                    entry["result"] = fail_result
                    results.append(fail_result)
                    # Do not re-raise: remaining units continue; status reflects failures.

            try:
                async with asyncio.TaskGroup() as tg:
                    for handle in pending_handles:
                        tg.create_task(_one(handle))
            except* BudgetExceeded:
                pass
        finally:
            if self._executor is not None:
                self._executor.shutdown(wait=True, cancel_futures=True)
                self._executor = None

        failed = sum(
            1 for e in self._handles.values() if e["status"] == WorkUnitStatus.FAILED.value
        )
        status = "cancelled" if self._cancel_requested else "completed"
        if self.ledger.overruns and self.ledger.stopped:
            status = "budget_exceeded"
        elif failed and status == "completed":
            status = "completed_with_failures"
        self._save_checkpoint(
            {
                "schema_version": "1",
                "completed": completed,
                "status": status,
                "failed_units": failed,
            }
        )
        ledger_snap = self.ledger.snapshot().model_dump(mode="json")
        ledger_digest = self.store.put_json(ledger_snap)
        return {
            "results": results,
            "completed": completed,
            "ledger": ledger_snap,
            "ledger_digest": ledger_digest,
            "status": status,
            "overrun": bool(self.ledger.overruns),
            "failed_units": failed,
        }
