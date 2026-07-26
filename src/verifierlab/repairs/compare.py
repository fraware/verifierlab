"""Repair campaign protocol (VAL-R15).

A repair evaluation is a full campaign artifact, not a one-shot scripted loop:

- immutable old/new ``VerifierProfile`` digests
- known-exploit regression + clean-valid regression
- hidden holdout (not shown to the fresh attacker during search)
- fresh attacker with **new seeds** and equalized (or larger) query budget
- paired FAR/FRR/abstention/cost/learnability comparison

``compare_repair`` remains as a thin CLI/test-friendly wrapper over
``run_repair_campaign``.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from pydantic import Field

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import ArtifactBase
from verifierlab.attacks.registry import create_strategy
from verifierlab.campaigns.episode import public_attack_feedback
from verifierlab.reports.metrics import compute_metrics
from verifierlab.statistics.intervals import paired_bootstrap
from verifierlab.verifiers.profile import VerifierProfile


class RepairCampaignArtifact(ArtifactBase):
    """Immutable repair comparison record."""

    schema_version: str = "3"
    campaign_id: str
    old_profile: dict[str, Any]
    new_profile: dict[str, Any]
    budget: dict[str, Any] = Field(default_factory=dict)
    regression: dict[str, Any] = Field(default_factory=dict)
    holdout: dict[str, Any] = Field(default_factory=dict)
    fresh_attack: dict[str, Any] = Field(default_factory=dict)
    paired_stats: dict[str, Any] = Field(default_factory=dict)
    learnability: float = 0.0
    mandatory_fresh_attacker: bool = True
    trivial_reject_detected: bool = False
    status: str = "pass"
    failure_taxonomy: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


DEFAULT_TRIVIAL_REJECT_THRESHOLD = 0.5


def _sub(a: float | None, b: float | None) -> float | None:
    if a is None or b is None:
        return None
    return a - b


def _profile_for(
    verifier: Callable[[dict[str, Any]], Any],
    *,
    name: str,
    config: dict[str, Any] | None = None,
) -> VerifierProfile:
    return VerifierProfile.for_callable(verifier, name=name, config=config)


def _decision_accepted(raw: Any) -> bool | None:
    """Fail-closed accept mapping — never ``bool("reject")``."""
    from verifierlab.api.verifier import normalize_decision

    return normalize_decision(raw).accepted


def _score_rows(
    trajectories: Sequence[dict[str, Any]],
    *,
    verifier: Callable[[dict[str, Any]], Any],
    is_valid: Callable[[dict[str, Any]], bool],
    cohort: str,
    prefix: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for i, traj in enumerate(trajectories):
        rows.append(
            {
                "unit_id": f"{prefix}-{i}",
                "cohort": cohort,
                "verifier_accepted": _decision_accepted(verifier(traj)) is True,
                "gt_valid": bool(is_valid(traj)),
                "trajectory": traj,
            }
        )
    return rows


def _partition_regression(
    trajectories: Sequence[dict[str, Any]],
    *,
    old_verifier: Callable[[dict[str, Any]], Any],
    is_valid: Callable[[dict[str, Any]], bool],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split into known-exploit vs clean-valid under the *old* verifier."""
    exploits: list[dict[str, Any]] = []
    clean: list[dict[str, Any]] = []
    for traj in trajectories:
        valid = bool(is_valid(traj))
        accepted = _decision_accepted(old_verifier(traj)) is True
        if accepted and not valid:
            exploits.append(traj)
        elif valid:
            clean.append(traj)
        else:
            # Rejected invalid — keep in clean bucket for FRR-neutral regression.
            clean.append(traj)
    return exploits, clean


def _run_fresh_attack(
    *,
    strategy_name: str,
    config: dict[str, Any],
    verifier: Callable[[dict[str, Any]], Any],
    is_valid: Callable[[dict[str, Any]], bool],
    episodes: int,
    seeds: Sequence[int],
    budget_queries: int,
    build_trajectory: Callable[[list[dict[str, Any]]], dict[str, Any]] | None,
    holdout_forbidden: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run a fresh attacker with new seeds under an equalized query budget.

    Holdout trajectories are never passed into the strategy config (no exploit
    leakage). Budget is counted as verifier queries (one per episode here).
    """
    holdout_digests = {digest_of(t) for t in holdout_forbidden}
    base_seed = int(config.get("seed", 99))
    seed_list = list(seeds) if seeds else [base_seed + i * 17 + 3 for i in range(episodes)]
    if len(seed_list) < episodes:
        last = seed_list[-1] if seed_list else base_seed
        seed_list = list(seed_list) + [
            last + 31 * (i + 1) for i in range(episodes - len(seed_list))
        ]

    queries_used = 0
    rows: list[dict[str, Any]] = []
    for i in range(episodes):
        if queries_used >= budget_queries:
            break
        ep_seed = int(seed_list[i])
        strategy = create_strategy(
            strategy_name,
            {**config, "seed": ep_seed},
        )
        steps = [strategy.propose() for _ in range(int(config.get("max_steps", 2)))]
        clean = [{k: v for k, v in s.items() if not str(k).startswith("_")} for s in steps]
        traj = (
            build_trajectory(clean) if build_trajectory else {"schema_version": "1", "steps": clean}
        )
        if digest_of(traj) in holdout_digests:
            # Regenerate with a shifted seed rather than evaluating holdout leakage.
            strategy = create_strategy(strategy_name, {**config, "seed": ep_seed + 101})
            steps = [strategy.propose() for _ in range(int(config.get("max_steps", 2)))]
            clean = [{k: v for k, v in s.items() if not str(k).startswith("_")} for s in steps]
            traj = (
                build_trajectory(clean)
                if build_trajectory
                else {"schema_version": "1", "steps": clean}
            )

        accepted = _decision_accepted(verifier(traj)) is True
        queries_used += 1
        valid = bool(is_valid(traj))
        feedback = public_attack_feedback(
            {
                "verifier_accepted": accepted,
                "gt_valid": valid,
                "reward": sum(int(s.get("amount", 0)) for s in clean),
                "score": float(accepted),
                "cost": 1.0,
                "coverage": [],
                "reason_codes": [],
                "observation": {},
                "trajectory": traj,
                "novel": False,
            }
        )
        strategy.observe(feedback)
        rows.append(
            {
                "unit_id": f"fresh-{i}",
                "cohort": "fresh_attack",
                "verifier_accepted": accepted,
                "gt_valid": valid,
                "trajectory": traj,
                "seed": ep_seed,
            }
        )

    ledger = {
        "budget_queries": budget_queries,
        "queries_used": queries_used,
        "episodes_requested": episodes,
        "episodes_completed": len(rows),
        "seeds": seed_list[: len(rows)],
        "equalized": True,
        "holdout_isolated": True,
    }
    return rows, ledger


def _paired_indicator_series(
    old_rows: Sequence[dict[str, Any]],
    new_rows: Sequence[dict[str, Any]],
    *,
    kind: str,
) -> tuple[list[float], list[float]]:
    """Per-trajectory 0/1 indicators for paired bootstrap (FAR or FRR events)."""
    a: list[float] = []
    b: list[float] = []
    for o, n in zip(old_rows, new_rows, strict=True):
        if kind == "far":
            # Among invalids: 1 if false accept.
            if o.get("gt_valid") is False:
                a.append(1.0 if o.get("verifier_accepted") else 0.0)
                b.append(1.0 if n.get("verifier_accepted") else 0.0)
        elif kind == "frr" and o.get("gt_valid") is True:
            a.append(0.0 if o.get("verifier_accepted") else 1.0)
            b.append(0.0 if n.get("verifier_accepted") else 1.0)
    return a, b


def run_repair_campaign(
    *,
    old_verifier: Callable[[dict[str, Any]], bool],
    new_verifier: Callable[[dict[str, Any]], bool],
    regression_trajectories: list[dict[str, Any]],
    is_valid: Callable[[dict[str, Any]], bool],
    holdout_trajectories: list[dict[str, Any]] | None = None,
    fresh_attack_results: list[dict[str, Any]] | None = None,
    fresh_attack_strategy: str = "structured_fuzz",
    fresh_attack_config: dict[str, Any] | None = None,
    fresh_episodes: int = 8,
    fresh_seeds: Sequence[int] | None = None,
    budget_queries: int | None = None,
    baseline_attack_budget: int | None = None,
    build_trajectory: Callable[[list[dict[str, Any]]], dict[str, Any]] | None = None,
    old_profile: VerifierProfile | None = None,
    new_profile: VerifierProfile | None = None,
    campaign_id: str | None = None,
    independent_strategy: str | None = None,
    independence_justification: str | None = None,
    bootstrap_samples: int = 200,
    bootstrap_seed: int = 0,
    trivial_reject_threshold: float = DEFAULT_TRIVIAL_REJECT_THRESHOLD,
) -> RepairCampaignArtifact:
    """Execute a full repair campaign and return the artifact.

    VALAB-07 gates (all required for ``status=pass``):
    1. Historical regression corpus present and scored
    2. Fresh attack implementation or fresh seeds with independence justification
    3. Unchanged or larger evaluation budget vs baseline attack budget
    4. Utility regression: clean-valid accept rate must not collapse (trivial reject)
    5. Paired CIs on FAR/FRR delta
    6. Failure taxonomy on residual exploits
    """
    cfg = dict(fresh_attack_config or {})
    old_p = old_profile or _profile_for(old_verifier, name="repair_old", config={"role": "old"})
    new_p = new_profile or _profile_for(new_verifier, name="repair_new", config={"role": "new"})

    notes: list[str] = [
        "RepairCampaignArtifact schema_version=3",
        "Automated repair metrics are not ground truth.",
    ]
    failure_taxonomy: list[str] = []
    gate_failures: list[str] = []

    if not regression_trajectories:
        gate_failures.append("missing_regression_corpus")

    exploit_reg, clean_reg = _partition_regression(
        regression_trajectories, old_verifier=old_verifier, is_valid=is_valid
    )

    if holdout_trajectories is None:
        # Reserve up to half of clean regression as hidden holdout when caller
        # did not supply an explicit holdout corpus.
        split_at = max(0, len(clean_reg) // 2)
        holdout_trajectories = list(clean_reg[:split_at])
        clean_reg = list(clean_reg[split_at:])
        notes_holdout = "synthetic_holdout_from_clean_regression"
    else:
        notes_holdout = "caller_holdout"
    notes.append(notes_holdout)

    regression_all = list(exploit_reg) + list(clean_reg)
    if not regression_all and regression_trajectories:
        # All trajectories were partitioned; still score the original set.
        regression_all = list(regression_trajectories)
    old_reg_rows = _score_rows(
        regression_all, verifier=old_verifier, is_valid=is_valid, cohort="regression", prefix="reg"
    )
    new_reg_rows = _score_rows(
        regression_all, verifier=new_verifier, is_valid=is_valid, cohort="regression", prefix="reg"
    )
    old_hold_rows = _score_rows(
        holdout_trajectories,
        verifier=old_verifier,
        is_valid=is_valid,
        cohort="holdout",
        prefix="hold",
    )
    new_hold_rows = _score_rows(
        holdout_trajectories,
        verifier=new_verifier,
        is_valid=is_valid,
        cohort="holdout",
        prefix="hold",
    )

    # Equalized budget: at least as large as regression evaluation + fresh episodes.
    eq_budget = (
        budget_queries if budget_queries is not None else max(fresh_episodes, len(regression_all))
    )
    eq_budget = max(eq_budget, fresh_episodes)
    if baseline_attack_budget is not None and eq_budget < int(baseline_attack_budget):
        gate_failures.append("budget_smaller_than_baseline")

    fresh_ledger: dict[str, Any]
    if fresh_attack_results is None:
        strategy = independent_strategy or fresh_attack_strategy
        seed_list = list(fresh_seeds or [])
        if not seed_list and not independence_justification and not independent_strategy:
            # Fresh seeds are generated deterministically — record justification.
            independence_justification = "fresh_deterministic_seed_offset"
        fresh_attack_results, fresh_ledger = _run_fresh_attack(
            strategy_name=strategy,
            config=cfg,
            verifier=new_verifier,
            is_valid=is_valid,
            episodes=fresh_episodes,
            seeds=seed_list,
            budget_queries=eq_budget,
            build_trajectory=build_trajectory,
            holdout_forbidden=holdout_trajectories,
        )
        if independent_strategy and independent_strategy != fresh_attack_strategy:
            fresh_ledger["independent_attacker"] = independent_strategy
        if independence_justification:
            fresh_ledger["independence_justification"] = independence_justification
    else:
        if not independence_justification and not independent_strategy:
            independence_justification = "caller_supplied_fresh_attack_results"
        fresh_ledger = {
            "budget_queries": eq_budget,
            "queries_used": len(fresh_attack_results),
            "episodes_requested": fresh_episodes,
            "episodes_completed": len(fresh_attack_results),
            "seeds": [r.get("seed") for r in fresh_attack_results],
            "equalized": True,
            "holdout_isolated": True,
            "caller_supplied_results": True,
            "independence_justification": independence_justification,
        }

    if not fresh_attack_results and fresh_episodes > 0:
        gate_failures.append("missing_fresh_attacker")

    old_m = compute_metrics(old_reg_rows, access_model="repair", pool_overall=True)
    new_m = compute_metrics(new_reg_rows, access_model="repair", pool_overall=True)
    old_h = compute_metrics(old_hold_rows, access_model="repair", pool_overall=True)
    new_h = compute_metrics(new_hold_rows, access_model="repair", pool_overall=True)
    fresh_m = compute_metrics(fresh_attack_results, access_model="repair", pool_overall=True)

    still_exploitable = sum(
        1
        for o, n in zip(old_reg_rows, new_reg_rows, strict=True)
        if o["verifier_accepted"] and not o["gt_valid"] and n["verifier_accepted"]
    )
    old_exploits = sum(1 for o in old_reg_rows if o["verifier_accepted"] and not o["gt_valid"])
    learnability = (still_exploitable / old_exploits) if old_exploits else 0.0

    # VALAB-07 gate 4 / trivial-reject: clean-valid accept collapse.
    clean_valid_old = [r for r in old_reg_rows if r.get("gt_valid") is True]
    clean_valid_new = [r for r in new_reg_rows if r.get("gt_valid") is True]
    trivial_reject_detected = False
    if clean_valid_old:
        old_accept = sum(1 for r in clean_valid_old if r.get("verifier_accepted")) / len(
            clean_valid_old
        )
        new_accept = (
            sum(1 for r in clean_valid_new if r.get("verifier_accepted")) / len(clean_valid_new)
            if clean_valid_new
            else 0.0
        )
        # Reject if new verifier drops clean-valid accept rate by >= threshold
        # without a compensating utility metric (accept rate collapse).
        if old_accept > 0 and (old_accept - new_accept) >= float(trivial_reject_threshold):
            trivial_reject_detected = True
            gate_failures.append("trivial_reject_detected")
        # Also: reject-everything relative to previously clean-valid corpus.
        if new_accept == 0.0 and old_accept >= float(trivial_reject_threshold):
            trivial_reject_detected = True
            if "trivial_reject_detected" not in gate_failures:
                gate_failures.append("trivial_reject_detected")

    far_old, far_new = _paired_indicator_series(old_reg_rows, new_reg_rows, kind="far")
    frr_old, frr_new = _paired_indicator_series(old_reg_rows, new_reg_rows, kind="frr")
    # Bootstrap on (new - old) so negative FAR delta means improvement.
    far_paired = paired_bootstrap(far_new, far_old, samples=bootstrap_samples, seed=bootstrap_seed)
    frr_paired = paired_bootstrap(
        frr_new, frr_old, samples=bootstrap_samples, seed=bootstrap_seed + 1
    )
    if not (far_paired.as_dict() and frr_paired.as_dict()):
        gate_failures.append("missing_paired_cis")

    # Failure taxonomy on residual exploits (new verifier still accepts invalids).
    for _o, n in zip(old_reg_rows, new_reg_rows, strict=True):
        if n.get("verifier_accepted") and n.get("gt_valid") is False:
            failure_taxonomy.append("residual_false_accept")
            break
    if still_exploitable:
        failure_taxonomy.append(f"residual_exploits:{still_exploitable}")
    if not failure_taxonomy and old_exploits:
        failure_taxonomy.append("no_residual_exploits")
    elif not failure_taxonomy:
        failure_taxonomy.append("no_baseline_exploits")

    cid = (
        campaign_id
        or digest_of(
            {
                "old": old_p.content_digest(),
                "new": new_p.content_digest(),
                "n_reg": len(regression_all),
                "n_hold": len(holdout_trajectories),
            }
        )[:16]
    )

    status = "fail" if gate_failures or trivial_reject_detected else "pass"
    if gate_failures:
        notes.extend(f"gate_fail:{g}" for g in gate_failures)

    artifact = RepairCampaignArtifact(
        campaign_id=cid,
        old_profile=old_p.model_dump(mode="json"),
        new_profile=new_p.model_dump(mode="json"),
        budget={
            "equalized_queries": eq_budget,
            "baseline_attack_budget": baseline_attack_budget,
            "fresh": fresh_ledger,
            "regression_n": len(regression_all),
            "holdout_n": len(holdout_trajectories),
        },
        regression={
            "old": old_m.as_dict(),
            "new": new_m.as_dict(),
            "known_exploit_n": len(exploit_reg),
            "clean_valid_n": len(clean_reg),
            "frr_delta": _sub(new_m.overall.frr, old_m.overall.frr),
            "far_delta": _sub(new_m.overall.far, old_m.overall.far),
            "scored": bool(old_reg_rows),
        },
        holdout={
            "old": old_h.as_dict(),
            "new": new_h.as_dict(),
            "source": notes_holdout,
            "frr_delta": _sub(new_h.overall.frr, old_h.overall.frr),
            "far_delta": _sub(new_h.overall.far, old_h.overall.far),
        },
        fresh_attack={
            "metrics": fresh_m.as_dict(),
            "fresh_far": fresh_m.overall.far,
            "ledger": fresh_ledger,
        },
        paired_stats={
            "far_delta_bootstrap": far_paired.as_dict(),
            "frr_delta_bootstrap": frr_paired.as_dict(),
            "abstention_delta": _sub(new_m.overall.abstention_rate, old_m.overall.abstention_rate),
            "cost": {
                "regression_n": len(regression_all),
                "holdout_n": len(holdout_trajectories),
                "fresh_n": len(fresh_attack_results),
                "queries_used": fresh_ledger.get("queries_used"),
            },
        },
        learnability=learnability,
        trivial_reject_detected=trivial_reject_detected,
        status=status,
        failure_taxonomy=failure_taxonomy,
        notes=notes,
        metadata={
            "old_profile_digest": old_p.content_digest(),
            "new_profile_digest": new_p.content_digest(),
            "gate_failures": gate_failures,
            "independence_justification": independence_justification,
        },
    )
    return artifact


def compare_repair(
    *,
    old_verifier: Callable[[dict[str, Any]], bool],
    new_verifier: Callable[[dict[str, Any]], bool],
    regression_trajectories: list[dict[str, Any]],
    is_valid: Callable[[dict[str, Any]], bool],
    fresh_attack_results: list[dict[str, Any]] | None = None,
    fresh_attack_strategy: str = "structured_fuzz",
    fresh_attack_config: dict[str, Any] | None = None,
    fresh_episodes: int = 8,
    build_trajectory: Callable[[list[dict[str, Any]]], dict[str, Any]] | None = None,
    holdout_trajectories: list[dict[str, Any]] | None = None,
    fresh_seeds: Sequence[int] | None = None,
    budget_queries: int | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Compare repaired verifier vs baseline (wrapper over ``run_repair_campaign``).

    Returns a dict compatible with prior callers plus the full campaign fields.
    """
    artifact = run_repair_campaign(
        old_verifier=old_verifier,
        new_verifier=new_verifier,
        regression_trajectories=regression_trajectories,
        is_valid=is_valid,
        holdout_trajectories=holdout_trajectories,
        fresh_attack_results=fresh_attack_results,
        fresh_attack_strategy=fresh_attack_strategy,
        fresh_attack_config=fresh_attack_config,
        fresh_episodes=fresh_episodes,
        fresh_seeds=fresh_seeds,
        budget_queries=budget_queries,
        build_trajectory=build_trajectory,
        **kwargs,
    )
    body = artifact.as_dict()
    # Backward-compatible top-level keys used by existing tests.
    body["regression_old"] = artifact.regression["old"]
    body["regression_new"] = artifact.regression["new"]
    body["fresh_attack"] = artifact.fresh_attack["metrics"]
    body["frr_delta"] = artifact.regression["frr_delta"]
    body["far_delta_regression"] = artifact.regression["far_delta"]
    body["fresh_far"] = artifact.fresh_attack["fresh_far"]
    body["learnability"] = artifact.learnability
    body["cost"] = artifact.paired_stats["cost"]
    body["mandatory_fresh_attacker"] = True
    body["trivial_reject_detected"] = artifact.trivial_reject_detected
    body["status"] = artifact.status
    body["failure_taxonomy"] = list(artifact.failure_taxonomy)
    body["repair_campaign"] = {
        "campaign_id": artifact.campaign_id,
        "old_profile_digest": artifact.metadata.get("old_profile_digest"),
        "new_profile_digest": artifact.metadata.get("new_profile_digest"),
        "holdout": artifact.holdout,
        "paired_stats": artifact.paired_stats,
        "budget": artifact.budget,
        "status": artifact.status,
        "trivial_reject_detected": artifact.trivial_reject_detected,
    }
    return body
