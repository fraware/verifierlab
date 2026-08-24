"""Repair + fresh-reattack protocol (VAL-R15).

A qualification-grade repair result must bind the repaired verifier to a real
fresh campaign executed by VerifierLab's canonical campaign engine. The
lightweight helper in this module remains useful for development smoke tests,
but it is intentionally incapable of self-certifying a qualification pass.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import ArtifactBase
from verifierlab.attacks.registry import create_strategy
from verifierlab.campaigns.episode import public_attack_feedback
from verifierlab.reports.metrics import compute_metrics
from verifierlab.statistics.intervals import paired_bootstrap
from verifierlab.verifiers.profile import VerifierProfile


class FreshAttackProvenance(BaseModel):
    """Binding for post-adjudication results from a canonical fresh campaign."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1"
    attack_engine: Literal["campaign_engine"]
    run_digest: str = Field(min_length=8)
    results_digest: str = Field(min_length=8)
    verifier_profile_digest: str = Field(min_length=8)
    budget_queries: int = Field(ge=0)
    holdout_isolated: bool
    fresh_attacker: bool
    independent_implementation: bool = False
    execution_isolation: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RepairCampaignArtifact(ArtifactBase):
    """Immutable repair comparison record."""

    schema_version: str = "4"
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
    qualification_grade: bool = False
    trivial_reject_detected: bool = False
    status: str = "fail"
    failure_taxonomy: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


DEFAULT_TRIVIAL_REJECT_THRESHOLD = 0.5
_RUNTIME_BOUND_STRATEGIES = frozenset({"best_of_n", "beam"})


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
    """Fail-closed accept mapping — never Python truthiness."""
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
    exploits: list[dict[str, Any]] = []
    clean: list[dict[str, Any]] = []
    for traj in trajectories:
        valid = bool(is_valid(traj))
        accepted = _decision_accepted(old_verifier(traj)) is True
        if accepted and not valid:
            exploits.append(traj)
        else:
            clean.append(traj)
    return exploits, clean


def _run_development_fresh_attack(
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
    """Development-only persistent fresh attacker.

    One strategy instance persists across episodes so learning is not discarded.
    Runtime-bound search strategies are refused here because using their
    brokerless test path would create a systematically weaker attacker. Use a
    canonical CampaignSpec/run for BestOfN, Beam, and qualification evidence.
    """
    if strategy_name in _RUNTIME_BOUND_STRATEGIES:
        raise ValueError(
            f"{strategy_name} requires the canonical campaign runtime/broker; "
            "the repair development helper refuses its weaker brokerless path"
        )

    holdout_digests = {digest_of(t) for t in holdout_forbidden}
    base_seed = int(config.get("seed", 99))
    attacker_seed = int(seeds[0]) if seeds else base_seed + 3
    strategy = create_strategy(strategy_name, {**config, "seed": attacker_seed})
    max_steps = int(config.get("max_steps", 2))

    queries_used = 0
    rows: list[dict[str, Any]] = []
    for i in range(episodes):
        if queries_used >= budget_queries:
            break

        traj: dict[str, Any] | None = None
        clean: list[dict[str, Any]] = []
        # Collision avoidance advances the same attacker state; it never resets
        # into a convenient independent strategy instance.
        for _attempt in range(4):
            steps = [strategy.propose() for _ in range(max_steps)]
            clean = [{k: v for k, v in step.items() if not str(k).startswith("_")} for step in steps]
            candidate = (
                build_trajectory(clean)
                if build_trajectory
                else {"schema_version": "1", "steps": clean}
            )
            if digest_of(candidate) not in holdout_digests:
                traj = candidate
                break
        if traj is None:
            break

        accepted = _decision_accepted(verifier(traj)) is True
        queries_used += 1
        valid = bool(is_valid(traj))
        feedback = public_attack_feedback(
            {
                "verifier_accepted": accepted,
                "gt_valid": valid,
                "reward": sum(int(step.get("amount", 0)) for step in clean),
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
                "attacker_seed": attacker_seed,
                "episode_index": i,
            }
        )

    ledger = {
        "attack_engine": "repair_development_helper",
        "qualification_grade": False,
        "persistent_strategy": True,
        "strategy": strategy_name,
        "attacker_seed": attacker_seed,
        "budget_queries": budget_queries,
        "queries_used": queries_used,
        "episodes_requested": episodes,
        "episodes_completed": len(rows),
        "holdout_isolated_by_digest_only": True,
        "note": "development helper cannot establish VAL-R15 qualification",
    }
    return rows, ledger


def _validate_fresh_provenance(
    provenance: FreshAttackProvenance,
    *,
    results: list[dict[str, Any]],
    new_profile_digest: str,
    minimum_budget: int,
) -> list[str]:
    failures: list[str] = []
    if provenance.results_digest != digest_of(results):
        failures.append("fresh_results_digest_mismatch")
    if provenance.verifier_profile_digest != new_profile_digest:
        failures.append("fresh_verifier_profile_mismatch")
    if provenance.budget_queries < minimum_budget:
        failures.append("fresh_budget_smaller_than_required")
    if not provenance.holdout_isolated:
        failures.append("fresh_holdout_not_isolated")
    if not provenance.fresh_attacker:
        failures.append("attacker_not_fresh")
    return failures


def _paired_indicator_series(
    old_rows: Sequence[dict[str, Any]],
    new_rows: Sequence[dict[str, Any]],
    *,
    kind: str,
) -> tuple[list[float], list[float]]:
    a: list[float] = []
    b: list[float] = []
    for old, new in zip(old_rows, new_rows, strict=True):
        if kind == "far" and old.get("gt_valid") is False:
            a.append(1.0 if old.get("verifier_accepted") else 0.0)
            b.append(1.0 if new.get("verifier_accepted") else 0.0)
        elif kind == "frr" and old.get("gt_valid") is True:
            a.append(0.0 if old.get("verifier_accepted") else 1.0)
            b.append(0.0 if new.get("verifier_accepted") else 1.0)
    return a, b


def run_repair_campaign(
    *,
    old_verifier: Callable[[dict[str, Any]], bool],
    new_verifier: Callable[[dict[str, Any]], bool],
    regression_trajectories: list[dict[str, Any]],
    is_valid: Callable[[dict[str, Any]], bool],
    holdout_trajectories: list[dict[str, Any]] | None = None,
    fresh_attack_results: list[dict[str, Any]] | None = None,
    fresh_attack_provenance: FreshAttackProvenance | dict[str, Any] | None = None,
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
    """Compare old/new verifiers and require canonical evidence for qualification.

    A `status="pass"` is possible only when fresh results are caller-supplied
    with a valid :class:`FreshAttackProvenance` binding to the canonical campaign
    engine. The built-in helper can produce development diagnostics only.
    """
    del independent_strategy  # textual independence is not a qualification boundary
    cfg = dict(fresh_attack_config or {})
    old_p = old_profile or _profile_for(old_verifier, name="repair_old", config={"role": "old"})
    new_p = new_profile or _profile_for(new_verifier, name="repair_new", config={"role": "new"})
    new_profile_digest = new_p.content_digest()

    notes: list[str] = [
        "RepairCampaignArtifact schema_version=4",
        "Automated repair metrics are not ground truth.",
        "Qualification requires canonical fresh-campaign provenance.",
    ]
    failure_taxonomy: list[str] = []
    gate_failures: list[str] = []

    if not regression_trajectories:
        gate_failures.append("missing_regression_corpus")

    exploit_reg, clean_reg = _partition_regression(
        regression_trajectories,
        old_verifier=old_verifier,
        is_valid=is_valid,
    )

    if holdout_trajectories is None:
        split_at = max(0, len(clean_reg) // 2)
        holdout_trajectories = list(clean_reg[:split_at])
        clean_reg = list(clean_reg[split_at:])
        holdout_source = "synthetic_holdout_from_regression"
        gate_failures.append("synthetic_holdout_not_qualification_grade")
    else:
        holdout_source = "caller_holdout"
    notes.append(holdout_source)

    regression_all = list(exploit_reg) + list(clean_reg)
    if not regression_all and regression_trajectories:
        regression_all = list(regression_trajectories)

    old_reg_rows = _score_rows(
        regression_all,
        verifier=old_verifier,
        is_valid=is_valid,
        cohort="regression",
        prefix="reg",
    )
    new_reg_rows = _score_rows(
        regression_all,
        verifier=new_verifier,
        is_valid=is_valid,
        cohort="regression",
        prefix="reg",
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

    eq_budget = budget_queries if budget_queries is not None else max(fresh_episodes, len(regression_all))
    eq_budget = max(int(eq_budget), fresh_episodes)
    minimum_budget = max(eq_budget, int(baseline_attack_budget or 0))
    if baseline_attack_budget is not None and eq_budget < int(baseline_attack_budget):
        gate_failures.append("budget_smaller_than_baseline")

    qualification_grade = False
    fresh_ledger: dict[str, Any]
    if fresh_attack_results is None:
        try:
            fresh_attack_results, fresh_ledger = _run_development_fresh_attack(
                strategy_name=fresh_attack_strategy,
                config=cfg,
                verifier=new_verifier,
                is_valid=is_valid,
                episodes=fresh_episodes,
                seeds=list(fresh_seeds or []),
                budget_queries=eq_budget,
                build_trajectory=build_trajectory,
                holdout_forbidden=holdout_trajectories,
            )
        except ValueError as exc:
            fresh_attack_results = []
            fresh_ledger = {
                "attack_engine": "repair_development_helper",
                "qualification_grade": False,
                "error": str(exc),
            }
        gate_failures.append("fresh_attack_not_canonical_campaign")
    else:
        if fresh_attack_provenance is None:
            fresh_ledger = {
                "attack_engine": "caller_supplied_unbound",
                "qualification_grade": False,
                "results_digest": digest_of(fresh_attack_results),
            }
            gate_failures.append("missing_fresh_attack_provenance")
        else:
            provenance = (
                fresh_attack_provenance
                if isinstance(fresh_attack_provenance, FreshAttackProvenance)
                else FreshAttackProvenance.model_validate(fresh_attack_provenance)
            )
            provenance_failures = _validate_fresh_provenance(
                provenance,
                results=fresh_attack_results,
                new_profile_digest=new_profile_digest,
                minimum_budget=minimum_budget,
            )
            gate_failures.extend(provenance_failures)
            qualification_grade = not provenance_failures
            fresh_ledger = {
                **provenance.model_dump(mode="json"),
                "qualification_grade": qualification_grade,
            }

    if not fresh_attack_results and fresh_episodes > 0:
        gate_failures.append("missing_fresh_attacker_results")

    old_m = compute_metrics(old_reg_rows, access_model="repair", pool_overall=True)
    new_m = compute_metrics(new_reg_rows, access_model="repair", pool_overall=True)
    old_h = compute_metrics(old_hold_rows, access_model="repair", pool_overall=True)
    new_h = compute_metrics(new_hold_rows, access_model="repair", pool_overall=True)
    fresh_m = compute_metrics(fresh_attack_results, access_model="repair", pool_overall=True)

    still_exploitable = sum(
        1
        for old, new in zip(old_reg_rows, new_reg_rows, strict=True)
        if old["verifier_accepted"] and not old["gt_valid"] and new["verifier_accepted"]
    )
    old_exploits = sum(
        1 for row in old_reg_rows if row["verifier_accepted"] and not row["gt_valid"]
    )
    learnability = (still_exploitable / old_exploits) if old_exploits else 0.0

    clean_valid_old = [row for row in old_reg_rows if row.get("gt_valid") is True]
    clean_valid_new = [row for row in new_reg_rows if row.get("gt_valid") is True]
    trivial_reject_detected = False
    if clean_valid_old:
        old_accept = sum(bool(row.get("verifier_accepted")) for row in clean_valid_old) / len(
            clean_valid_old
        )
        new_accept = (
            sum(bool(row.get("verifier_accepted")) for row in clean_valid_new) / len(clean_valid_new)
            if clean_valid_new
            else 0.0
        )
        if old_accept > 0 and (old_accept - new_accept) >= float(trivial_reject_threshold):
            trivial_reject_detected = True
            gate_failures.append("trivial_reject_detected")
        if new_accept == 0.0 and old_accept >= float(trivial_reject_threshold):
            trivial_reject_detected = True
            if "trivial_reject_detected" not in gate_failures:
                gate_failures.append("trivial_reject_detected")

    far_old, far_new = _paired_indicator_series(old_reg_rows, new_reg_rows, kind="far")
    frr_old, frr_new = _paired_indicator_series(old_reg_rows, new_reg_rows, kind="frr")
    far_paired = paired_bootstrap(
        far_new,
        far_old,
        samples=bootstrap_samples,
        seed=bootstrap_seed,
    )
    frr_paired = paired_bootstrap(
        frr_new,
        frr_old,
        samples=bootstrap_samples,
        seed=bootstrap_seed + 1,
    )
    if far_paired.n == 0:
        gate_failures.append("missing_paired_far_evidence")
    if frr_paired.n == 0:
        gate_failures.append("missing_paired_frr_evidence")

    if any(row.get("verifier_accepted") and row.get("gt_valid") is False for row in new_reg_rows):
        failure_taxonomy.append("residual_false_accept")
    if still_exploitable:
        failure_taxonomy.append(f"residual_exploits:{still_exploitable}")
    elif old_exploits:
        failure_taxonomy.append("no_residual_exploits")
    else:
        failure_taxonomy.append("no_baseline_exploits")

    cid = campaign_id or digest_of(
        {
            "old": old_p.content_digest(),
            "new": new_profile_digest,
            "n_reg": len(regression_all),
            "n_hold": len(holdout_trajectories),
            "fresh_results": digest_of(fresh_attack_results),
        }
    )[:16]

    gate_failures = list(dict.fromkeys(gate_failures))
    status = "pass" if qualification_grade and not gate_failures and not trivial_reject_detected else "fail"
    notes.extend(f"gate_fail:{failure}" for failure in gate_failures)

    return RepairCampaignArtifact(
        campaign_id=cid,
        old_profile=old_p.model_dump(mode="json"),
        new_profile=new_p.model_dump(mode="json"),
        budget={
            "equalized_queries": eq_budget,
            "minimum_required_queries": minimum_budget,
            "baseline_attack_budget": baseline_attack_budget,
            "fresh": fresh_ledger,
            "regression_n": len(regression_all),
            "holdout_n": len(holdout_trajectories),
        },
        regression={
            "old": old_m.as_dict(),
            "new": new_m.as_dict(),
            "known_exploit_n": len(exploit_reg),
            "clean_n": len(clean_reg),
            "frr_delta": _sub(new_m.overall.frr, old_m.overall.frr),
            "far_delta": _sub(new_m.overall.far, old_m.overall.far),
            "scored": bool(old_reg_rows),
        },
        holdout={
            "old": old_h.as_dict(),
            "new": new_h.as_dict(),
            "source": holdout_source,
            "frr_delta": _sub(new_h.overall.frr, old_h.overall.frr),
            "far_delta": _sub(new_h.overall.far, old_h.overall.far),
        },
        fresh_attack={
            "metrics": fresh_m.as_dict(),
            "fresh_far": fresh_m.overall.far,
            "ledger": fresh_ledger,
            "results_digest": digest_of(fresh_attack_results),
        },
        paired_stats={
            "far_delta_bootstrap": far_paired.as_dict(),
            "frr_delta_bootstrap": frr_paired.as_dict(),
            "abstention_delta": _sub(new_m.overall.abstention_rate, old_m.overall.abstention_rate),
            "cost": {
                "regression_n": len(regression_all),
                "holdout_n": len(holdout_trajectories),
                "fresh_n": len(fresh_attack_results),
                "queries_used": fresh_ledger.get("queries_used", fresh_ledger.get("budget_queries")),
            },
        },
        learnability=learnability,
        qualification_grade=qualification_grade,
        trivial_reject_detected=trivial_reject_detected,
        status=status,
        failure_taxonomy=failure_taxonomy,
        notes=notes,
        metadata={
            "old_profile_digest": old_p.content_digest(),
            "new_profile_digest": new_profile_digest,
            "gate_failures": gate_failures,
            "independence_justification": independence_justification,
        },
    )


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
    """Compatibility wrapper over :func:`run_repair_campaign`."""
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
    body["regression_old"] = artifact.regression["old"]
    body["regression_new"] = artifact.regression["new"]
    body["fresh_attack"] = artifact.fresh_attack["metrics"]
    body["frr_delta"] = artifact.regression["frr_delta"]
    body["far_delta_regression"] = artifact.regression["far_delta"]
    body["fresh_far"] = artifact.fresh_attack["fresh_far"]
    body["learnability"] = artifact.learnability
    body["cost"] = artifact.paired_stats["cost"]
    body["mandatory_fresh_attacker"] = True
    body["qualification_grade"] = artifact.qualification_grade
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
        "qualification_grade": artifact.qualification_grade,
        "trivial_reject_detected": artifact.trivial_reject_detected,
    }
    return body


__all__ = [
    "FreshAttackProvenance",
    "RepairCampaignArtifact",
    "compare_repair",
    "run_repair_campaign",
]
