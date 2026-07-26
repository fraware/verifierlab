"""Episode execution for attack strategies against env + broker (no GT)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from verifierlab.api.decision import DecisionKind
from verifierlab.api.protocols import AttackStrategy, EnvironmentTarget
from verifierlab.api.verifier import normalize_decision
from verifierlab.artifacts.canonical import digest_of
from verifierlab.attacks.runtime import bind_strategy_runtime
from verifierlab.exploits.records import build_exploit_case
from verifierlab.transcripts.audit import audit_transcript
from verifierlab.verifiers.broker import VerifierBroker
from verifierlab.verifiers.capabilities import capabilities_for

# Fields attack strategies may observe. Ground-truth / labels are forbidden.
_PUBLIC_FEEDBACK_ALLOW = frozenset(
    {
        "verifier_accepted",
        "reward",
        "observation",
        "trajectory",
        "coverage",
        "reason_codes",
        "cost",
        "score",
        "novel",
    }
)
_GT_FEEDBACK_DENY = frozenset(
    {
        "gt_valid",
        "label",
        "hidden_label",
        "gt_label",
        "commitment_label",
        "ground_truth",
    }
)


def public_attack_feedback(feedback: dict[str, Any]) -> dict[str, Any]:
    """Return strategy-visible feedback with ground-truth fields stripped.

    Attack strategies must optimize against the public verifier channel only.
    Passing ``gt_valid`` (or sealed labels) into ``observe`` is an integrity
    violation for black-box / gray-box access models.
    """
    out: dict[str, Any] = {}
    for key, value in feedback.items():
        if key in _GT_FEEDBACK_DENY:
            continue
        if key.startswith("gt_") or key.startswith("label"):
            continue
        if key in _PUBLIC_FEEDBACK_ALLOW or key.startswith("_public_"):
            out[key] = value
    return out


def trajectory_commitment(trajectory: dict[str, Any], nonce: str) -> str:
    """Worker-safe commitment: digest(trajectory || coordinator nonce), no label."""
    return digest_of(
        {
            "schema_version": "2",
            "trajectory": trajectory,
            "nonce": nonce,
        }
    )


def enrich_episode_with_gt(
    result: dict[str, Any],
    *,
    is_valid: Callable[[dict[str, Any]], bool],
    cohort: str | None = None,
    access_model: str | None = None,
) -> dict[str, Any]:
    """Coordinator/adjudicator-side GT evaluation (never in attack workers).

    Labels remain sealed in the vault until release; this attaches ``gt_valid``
    for metrics / exploit triage after adjudication.
    """
    traj = result.get("trajectory") or {}
    gt_valid = bool(is_valid(traj))
    enriched = dict(result)
    enriched["gt_valid"] = gt_valid
    enriched["label"] = None
    enriched["_coordinator_label"] = {"valid": gt_valid, "source": "coordinator_is_valid"}

    accepted = enriched.get("verifier_accepted")
    exploit = None
    dimensions = enriched.get("adjudication_dimensions") or enriched.get("dimensions")
    if not isinstance(dimensions, dict):
        dimensions = None
    if accepted is True and (gt_valid is False or dimensions):
        case = build_exploit_case(
            unit_id=str(enriched.get("unit_id") or "unknown"),
            trajectory=traj,
            cohort=str(cohort or enriched.get("cohort") or "optimized"),
            access_model=str(access_model or enriched.get("access_model") or "black-box"),
            dimensions=dimensions,
            public_accepted=True,
            hidden_valid=gt_valid,
        )
        if case.predicate is not None:
            exploit = case.model_dump(mode="json")
    enriched["exploit"] = exploit

    enriched["unit_digest"] = digest_of(
        {
            k: v
            for k, v in enriched.items()
            if k
            not in {
                "unit_digest",
                "label",
                "_coordinator_label",
                "transcript_audit",
                "cas_digest",
            }
        }
    )
    return enriched


def run_episode(
    *,
    unit_id: str,
    seed: int,
    max_steps: int,
    env: EnvironmentTarget,
    strategy: AttackStrategy,
    strategy_config: dict[str, Any],
    cohort: str,
    access_model: str,
    strategy_name: str,
    commitment_nonce: str,
    broker: VerifierBroker | None = None,
    verifier: Callable[[dict[str, Any]], Any] | None = None,
    learning: bool = True,
    split: str | None = None,
) -> dict[str, Any]:
    """Run one episode on the attack plane: env + broker only (no GT).

    Commitment is ``digest(trajectory || coordinator_nonce)`` with no validity
    bit. Ground truth is applied only by the adjudication service after freeze.

    When ``learning`` is False (holdout), strategies must not update parameters;
    the runtime binds ``learning=False`` before the episode loop.
    """
    if broker is None and verifier is None:
        raise ValueError("run_episode requires broker or verifier")

    obs = env.reset(seed=seed)
    cfg = {
        **strategy_config,
        "seed": seed,
        "max_steps": max_steps,
        "balance": obs.get("balance", 500),
    }
    # Only initialize when strategy has no prior restored state marker.
    if not getattr(strategy, "_restored", False):
        strategy.initialize(cfg)

    bind_strategy_runtime(strategy, broker=broker, env=env, learning=learning)

    total_reward = 0.0
    last_obs = obs
    for _ in range(max_steps):
        action = strategy.propose()
        result = env.act(action)
        total_reward += float(result.get("reward") or 0.0)
        last_obs = result.get("observation") or last_obs
        if result.get("done"):
            break

    trajectory = env.finalize()
    if broker is not None:
        decision = broker.query(trajectory, caller=f"episode:{unit_id}")
        invocations = broker.event_dicts()
    else:
        assert verifier is not None
        decision = normalize_decision(verifier(trajectory))
        invocations = [
            {
                "query_id": f"legacy-{unit_id}",
                "input_digest": digest_of(trajectory),
                "output_digest": digest_of(
                    {"status": decision.status, "accepted": decision.accepted}
                ),
                "latency_ms": 0.0,
                "caller": f"episode:{unit_id}",
                "access_model": access_model,
                "profile_digest": None,
                "status": decision.status,
                "accepted": decision.accepted,
            }
        ]

    accepted_value: bool | None = decision.accepted
    if decision.kind in {
        DecisionKind.ABSTAIN,
        DecisionKind.INDETERMINATE,
        DecisionKind.ERROR,
    }:
        accepted_value = None

    # Capability-gated feedback score (VALAB-03): never synthesize a score from
    # accept/reject under label_only; never invent 0.0 when the score channel
    # is empty; never drop a real score under score_only (broker may synthesize
    # score from accept when score_only strips the hard label).
    caps = capabilities_for(access_model)
    feedback_score: float | None = None
    if caps.may_read_score:
        if decision.score is not None:
            feedback_score = float(decision.score)
        elif caps.may_read_decision and accepted_value is not None:
            feedback_score = 1.0 if accepted_value else 0.0

    commitment = trajectory_commitment(trajectory, commitment_nonce)

    coverage: list[str] = []
    verifier_fn = broker.verifier if broker is not None else verifier
    reason_fn = getattr(verifier_fn, "reason_codes", None) if verifier_fn else None
    mod = getattr(verifier_fn, "__module__", None) if verifier_fn else None
    if caps.may_read_reason_codes and callable(reason_fn):
        coverage = caps.filter_reason_codes(list(reason_fn(trajectory)))
    elif caps.may_read_reason_codes and mod:
        try:
            import importlib

            m = importlib.import_module(mod)
            alt = getattr(m, "reason_codes", None)
            if callable(alt):
                coverage = caps.filter_reason_codes(list(alt(trajectory)))
        except Exception:
            coverage = []
    if not coverage:
        if caps.may_read_decision:
            coverage = [
                f"accept:{accepted_value}",
                f"ops:{[s.get('op') for s in trajectory.get('steps', [])]}",
            ]
        elif caps.may_read_score:
            coverage = [f"score:{feedback_score}"]
        else:
            coverage = ["feedback:none"]

    # Black-box strategies only see decision/score; gray may keep allowlisted codes.
    if caps.may_read_reason_codes:
        public_coverage = caps.filter_reason_codes(coverage)
    elif caps.may_read_score and not caps.may_read_decision:
        public_coverage = [f"score:{feedback_score}"]
    elif caps.may_read_decision:
        public_coverage = [f"accept:{accepted_value}"]
    else:
        public_coverage = ["feedback:none"]

    raw_feedback = {
        "verifier_accepted": accepted_value if caps.may_read_decision else None,
        "reward": total_reward,
        "observation": last_obs,
        "trajectory": trajectory,
        "coverage": public_coverage,
        "reason_codes": public_coverage if caps.may_read_reason_codes else [],
        "cost": float(max_steps),
        "score": feedback_score if caps.may_read_score else None,
        "novel": False,
    }
    strategy.observe(public_attack_feedback(raw_feedback))

    result_body: dict[str, Any] = {
        "schema_version": "2",
        "unit_id": unit_id,
        "seed": seed,
        "cohort": cohort,
        "strategy": strategy_name,
        "access_model": access_model,
        "split": split,
        "learning": learning,
        "trajectory": trajectory,
        "commitment": commitment,
        "commitment_nonce": commitment_nonce,
        "verifier_accepted": accepted_value if caps.may_read_decision else None,
        "verifier_status": decision.status,
        "verifier_kind": decision.kind.value,
        "verifier_score": decision.score if caps.may_read_score else None,
        "verifier_invocations": invocations,
        "query_count": len(invocations),
        "coverage": public_coverage,
        "reward": total_reward,
        # GT filled only after freeze + adjudication + release.
        "gt_valid": None,
        "label": None,
        "exploit": None,
        "worker_safe": {"commitment": commitment, "label": None},
    }
    audit = audit_transcript(
        {
            "unit_id": unit_id,
            "trajectory": trajectory,
            "verifier_invocations": result_body["verifier_invocations"],
            "worker_safe": result_body["worker_safe"],
        }
    )
    result_body["transcript_audit"] = audit.as_dict()
    result_body["unit_digest"] = digest_of(_stable_episode_digest_body(result_body))
    return result_body


def _stable_episode_digest_body(result_body: dict[str, Any]) -> dict[str, Any]:
    """Digest semantic episode fields; exclude volatile query ids / latency."""
    body = {
        k: v
        for k, v in result_body.items()
        if k not in {"unit_digest", "label", "transcript_audit", "verifier_invocations"}
    }
    body["verifier_invocation_summaries"] = [
        {
            "input_digest": inv.get("input_digest"),
            "output_digest": inv.get("output_digest"),
            "status": inv.get("status"),
            "accepted": inv.get("accepted"),
            "access_model": inv.get("access_model"),
            "profile_digest": inv.get("profile_digest"),
        }
        for inv in (result_body.get("verifier_invocations") or [])
        if isinstance(inv, dict)
    ]
    return body
