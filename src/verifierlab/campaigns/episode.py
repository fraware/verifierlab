"""Episode execution for attack strategies against env/verifier/GT."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from verifierlab.api.protocols import AttackStrategy, EnvironmentTarget, GroundTruthProvider
from verifierlab.artifacts.canonical import digest_of
from verifierlab.exploits.records import build_exploit_case
from verifierlab.transcripts.audit import audit_transcript

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


def enrich_episode_with_gt(
    result: dict[str, Any],
    *,
    is_valid: Callable[[dict[str, Any]], bool],
    cohort: str | None = None,
    access_model: str | None = None,
) -> dict[str, Any]:
    """Coordinator-side GT evaluation after worker episode completion.

    Workers must not call this. Labels remain sealed in the vault; this only
    attaches ``gt_valid`` for metrics / exploit triage on the coordinator.
    """
    traj = result.get("trajectory") or {}
    gt_valid = bool(is_valid(traj))
    enriched = dict(result)
    enriched["gt_valid"] = gt_valid
    # Coordinator metadata — never feed back into AttackStrategy.observe.
    enriched["label"] = None
    enriched["_coordinator_label"] = {"valid": gt_valid, "source": "coordinator_is_valid"}

    accepted = enriched.get("verifier_accepted")
    exploit = None
    if accepted is True and gt_valid is False:
        exploit = build_exploit_case(
            unit_id=str(enriched.get("unit_id") or "unknown"),
            trajectory=traj,
            cohort=str(cohort or enriched.get("cohort") or "optimized"),
            access_model=str(access_model or enriched.get("access_model") or "black-box"),
        ).model_dump(mode="json")
    enriched["exploit"] = exploit

    # Recompute digest over coordinator-enriched body (excludes private label blob).
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
    verifier: Callable[[dict[str, Any]], Any],
    gt: GroundTruthProvider,
    strategy: AttackStrategy,
    strategy_config: dict[str, Any],
    cohort: str,
    access_model: str,
    strategy_name: str,
    reveal_labels: bool = False,
) -> dict[str, Any]:
    """Run one episode; worker-safe view never includes pre-freeze labels.

    Ground-truth validity is **not** evaluated here. The coordinator must call
    :func:`enrich_episode_with_gt` after collection. Attack ``observe`` receives
    public verifier signals only.
    """
    obs = env.reset(seed=seed)
    cfg = {
        **strategy_config,
        "seed": seed,
        "max_steps": max_steps,
        "balance": obs.get("balance", 500),
    }
    strategy.initialize(cfg)

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
    decision_raw = verifier(trajectory)
    if isinstance(decision_raw, dict):
        accepted = bool(decision_raw.get("accepted", decision_raw.get("decision")))
        abstain = decision_raw.get("decision") == "abstain" or decision_raw.get("abstain") is True
        if abstain:
            accepted_value: bool | None = None
        else:
            accepted_value = accepted
    else:
        accepted_value = bool(decision_raw)

    commitment = gt.commit(trajectory)

    # Labels sealed until freeze+release; workers never see them.
    label: dict[str, Any] | None = None
    if reveal_labels:
        label = gt.label(commitment, after_freeze=True)

    coverage: list[str] = []
    reason_fn = getattr(verifier, "reason_codes", None)
    mod = getattr(verifier, "__module__", None)
    if callable(reason_fn):
        coverage = list(reason_fn(trajectory))
    elif mod:
        try:
            import importlib

            m = importlib.import_module(mod)
            alt = getattr(m, "reason_codes", None)
            if callable(alt):
                coverage = list(alt(trajectory))
        except Exception:
            coverage = []
    if not coverage:
        coverage = [
            f"accept:{accepted_value}",
            f"ops:{[s.get('op') for s in trajectory.get('steps', [])]}",
        ]

    raw_feedback = {
        "verifier_accepted": accepted_value,
        "reward": total_reward,
        "observation": last_obs,
        "trajectory": trajectory,
        "coverage": coverage,
        "reason_codes": coverage,
        "cost": float(max_steps),
        "score": total_reward + (1.0 if accepted_value else 0.0),
        "novel": False,
        # Intentionally omitted: gt_valid / label — integrity boundary.
    }
    strategy.observe(public_attack_feedback(raw_feedback))

    result_body: dict[str, Any] = {
        "schema_version": "1",
        "unit_id": unit_id,
        "seed": seed,
        "cohort": cohort,
        "strategy": strategy_name,
        "access_model": access_model,
        "trajectory": trajectory,
        "commitment": commitment,
        "verifier_accepted": accepted_value,
        "verifier_invocations": [
            {
                "trajectory_digest": digest_of(trajectory),
                "accepted": accepted_value,
            }
        ],
        "coverage": coverage,
        "reward": total_reward,
        # GT filled by coordinator enrichment only.
        "gt_valid": bool(label["valid"]) if label is not None else None,
        "label": label if reveal_labels else None,
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
    result_body["unit_digest"] = digest_of(
        {
            k: v
            for k, v in result_body.items()
            if k not in {"unit_digest", "label", "transcript_audit"}
        }
    )
    return result_body
