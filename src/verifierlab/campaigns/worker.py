"""Picklable process-pool entry points for campaign work units.

Nested closures cannot be pickled under ``ProcessPoolExecutor`` (spawn). All
worker entry points used by the campaign engine must live at module scope.

Attack workers must not import / instantiate ground-truth providers or evaluate
validity. They may use the environment and :class:`VerifierBroker` only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from verifierlab.attacks.registry import create_strategy
from verifierlab.attacks.runtime import (
    AttackerStore,
    is_learning_strategy,
    restore_strategy,
)
from verifierlab.budgets.budget import Budget, OverrunPolicy
from verifierlab.budgets.ledger import BudgetExceeded, ProvenanceLedger
from verifierlab.campaigns.episode import run_episode
from verifierlab.plugins.loader import load_object
from verifierlab.verifiers.broker import VerifierBroker
from verifierlab.verifiers.capabilities import capabilities_for
from verifierlab.verifiers.profile import VerifierProfile

# Refs that must never be loaded on the attack-worker plane.
_FORBIDDEN_REF_MARKERS = (
    "PlantedOracleGroundTruth",
    "GroundTruthProvider",
    "ground_truth",
    ":_is_valid",
    ":is_valid",
    "refund_is_valid",
)


def execute_work_unit(payload: dict[str, Any] | bytes | str) -> dict[str, Any]:
    """Top-level worker entry for :class:`~concurrent.futures.ProcessPoolExecutor`.

    Accepts a work-unit dict or a JSON ``bytes``/``str`` blob. Ground-truth
    refs are ignored if present (legacy payloads); workers never load GT.
    """
    request = _decode_work_unit_request(payload)
    return _run_work_unit(request)


def _decode_work_unit_request(payload: dict[str, Any] | bytes | str) -> dict[str, Any]:
    if isinstance(payload, bytes):
        data = json.loads(payload.decode("utf-8"))
    elif isinstance(payload, str):
        data = json.loads(payload)
    else:
        data = dict(payload)
    if not isinstance(data, dict):
        raise TypeError(f"work-unit request must be a mapping, got {type(data).__name__}")
    return data


def _reject_gt_ref(ref: str, *, field: str) -> None:
    lowered = ref.lower()
    for marker in _FORBIDDEN_REF_MARKERS:
        if marker.lower() in lowered:
            raise PermissionError(
                f"attack worker refused to load GT-like {field}={ref!r} (matched {marker!r})"
            )


def _worker_ledger(payload: dict[str, Any]) -> ProvenanceLedger | None:
    """Build a per-unit budget voucher for atomic broker reserve (VAL-R10).

    When ``query_budget_remaining`` is set, each ``broker.query`` reserves
    against this ledger before the call. Events are returned to the coordinator
    for exact merge — not post-hoc soft counting alone.
    """
    remaining = payload.get("query_budget_remaining")
    if remaining is None:
        return None
    rem = int(remaining)
    if rem < 0:
        rem = 0
    policy_raw = str(payload.get("budget_overrun_policy") or "stop")
    try:
        policy = OverrunPolicy(policy_raw)
    except ValueError:
        policy = OverrunPolicy.STOP
    # Budget requires at least one limit; voucher always caps queries.
    return ProvenanceLedger(
        budget=Budget(max_queries=rem, overrun_policy=policy),
    )


def _run_work_unit(payload: dict[str, Any]) -> dict[str, Any]:
    # Hard isolation: never import GT providers on the attack worker path.
    if "ground_truth_ref" in payload:
        payload = {k: v for k, v in payload.items() if k != "ground_truth_ref"}

    env_kind = str(payload.get("environment_kind") or "python")
    max_steps = int(payload.get("max_steps", 3))
    access_model = str(payload.get("access_model") or "black-box")
    commitment_nonce = str(payload.get("commitment_nonce") or payload["unit_id"])
    learning = bool(payload.get("learning", True))
    split = payload.get("split")

    if env_kind == "fake":
        from verifierlab.targets.fake import FakeEnvironment, fake_refund_verifier

        env = FakeEnvironment(max_steps=max_steps)
        verifier = fake_refund_verifier
    else:
        env_ref = str(payload.get("environment_ref") or "")
        ver_ref = str(payload.get("verifier_ref") or "")
        _reject_gt_ref(env_ref, field="environment_ref")
        _reject_gt_ref(ver_ref, field="verifier_ref")
        env_cls = load_object(payload["environment_ref"])
        env_cfg = dict(payload.get("environment_config") or {})
        env_cfg.pop("max_steps", None)
        env = env_cls(max_steps=max_steps, **env_cfg) if env_cfg else env_cls(max_steps=max_steps)
        verifier = load_object(payload["verifier_ref"])

    profile = VerifierProfile.for_callable(verifier)
    caps = capabilities_for(access_model)
    voucher = _worker_ledger(payload)
    broker = VerifierBroker(
        profile=profile,
        verifier=verifier,
        access_model=access_model,
        caller=f"worker:{payload['unit_id']}",
        ledger=voucher,
        capabilities=caps,
    )

    strategy_name = str(payload.get("strategy") or "ordinary")
    strategy_config = dict(payload.get("strategy_config") or {})
    strategy = create_strategy(strategy_name, strategy_config)

    store: AttackerStore | None = None
    attacker_dir = payload.get("attacker_dir")
    if attacker_dir and is_learning_strategy(strategy_name):
        store = AttackerStore(Path(attacker_dir))
        if store.frozen:
            learning = False
        prior = store.load_state()
        if prior is not None:
            restore_strategy(strategy, prior)
            strategy._restored = True  # type: ignore[attr-defined]

    # Holdout units must never see train-only artifacts beyond the frozen weights.
    if split and str(split).lower() in {"holdout", "test", "eval", "evaluation"}:
        learning = False

    budget_stopped = False
    try:
        result = run_episode(
            unit_id=str(payload["unit_id"]),
            seed=int(payload["seed"]),
            max_steps=max_steps,
            env=env,
            broker=broker,
            strategy=strategy,
            strategy_config=strategy_config,
            cohort=str(payload.get("cohort") or "optimized"),
            access_model=access_model,
            strategy_name=strategy_name,
            commitment_nonce=commitment_nonce,
            learning=learning,
            split=str(split) if split is not None else None,
        )
    except BudgetExceeded as exc:
        # Exact stop: voucher exhausted mid-search. Surface broker events so far.
        budget_stopped = True
        result = {
            "schema_version": "2",
            "unit_id": str(payload["unit_id"]),
            "seed": int(payload["seed"]),
            "cohort": str(payload.get("cohort") or "optimized"),
            "access_model": access_model,
            "strategy": strategy_name,
            "status": "budget_stopped",
            "error": str(exc),
            "error_type": "BudgetExceeded",
            "gt_valid": None,
            "verifier_invocations": broker.event_dicts(),
            "query_count": len(broker.events),
            "budget_voucher_queries": voucher.queries if voucher is not None else None,
        }

    # Prefer broker event count (true metered queries) over strategy estimates.
    result["query_count"] = len(broker.events)
    result["verifier_invocations"] = broker.event_dicts()
    if voucher is not None:
        result["budget_voucher_queries"] = voucher.queries
        result["budget_metered"] = True
        result["ledger_events"] = list(voucher.events)
        # Persist spend before return so crash after reserve cannot refund
        # completed queries (VALAB-04).
        spend_dir = payload.get("run_dir") or payload.get("attacker_dir")
        if spend_dir:
            spend_path = Path(spend_dir) / "budget_spend.json"
            voucher.persist_path = spend_path
            voucher.flush()
        result["candidates"] = voucher.candidates
        result["compute_units"] = voucher.compute_units
    if budget_stopped:
        result["budget_stopped"] = True
        result["censored"] = True
        result["status"] = result.get("status") or "budget_stopped"

    if store is not None and learning and not store.frozen and not budget_stopped:
        from verifierlab.attacks.runtime import json_safe_rng_state

        state = dict(strategy.checkpoint())
        if "rng_state" in state and state["rng_state"] is not None:
            state["rng_state"] = json_safe_rng_state(state["rng_state"])
        trainer = state.get("trainer")
        if isinstance(trainer, dict) and trainer.get("rng_state") is not None:
            trainer = dict(trainer)
            trainer["rng_state"] = json_safe_rng_state(trainer["rng_state"])
            state["trainer"] = trainer
        state["episodes"] = int(state.get("episodes", 0)) + 1
        store.save_state(state)
        result["attacker_checkpoint"] = str(store.root)
        result["attacker_episodes"] = state["episodes"]
    elif store is not None:
        result["attacker_checkpoint"] = str(store.root)
        result["attacker_frozen"] = store.frozen

    return result
