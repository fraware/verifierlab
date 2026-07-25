"""Repair compare: regression corpus + mandatory fresh attacker."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from verifierlab.attacks.registry import create_strategy
from verifierlab.campaigns.episode import public_attack_feedback
from verifierlab.reports.metrics import compute_metrics


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
) -> dict[str, Any]:
    """Compare repaired verifier vs baseline with mandatory fresh attack.

    Returns FRR/abstention/cost/learnability-oriented summary plus fresh FAR.
    """
    regression_rows_old: list[dict[str, Any]] = []
    regression_rows_new: list[dict[str, Any]] = []
    for i, traj in enumerate(regression_trajectories):
        valid = is_valid(traj)
        old_acc = bool(old_verifier(traj))
        new_acc = bool(new_verifier(traj))
        regression_rows_old.append(
            {
                "unit_id": f"reg-{i}",
                "cohort": "regression",
                "verifier_accepted": old_acc,
                "gt_valid": valid,
            }
        )
        regression_rows_new.append(
            {
                "unit_id": f"reg-{i}",
                "cohort": "regression",
                "verifier_accepted": new_acc,
                "gt_valid": valid,
            }
        )

    if fresh_attack_results is None:
        fresh_attack_results = _run_fresh_attack(
            strategy_name=fresh_attack_strategy,
            config=fresh_attack_config or {},
            verifier=new_verifier,
            is_valid=is_valid,
            episodes=fresh_episodes,
            build_trajectory=build_trajectory,
        )

    old_m = compute_metrics(regression_rows_old, access_model="repair")
    new_m = compute_metrics(regression_rows_new, access_model="repair")
    fresh_m = compute_metrics(fresh_attack_results, access_model="repair")

    # Learnability proxy: fraction of regression exploits still accepted by new verifier.
    still_exploitable = sum(
        1
        for o, n in zip(regression_rows_old, regression_rows_new, strict=True)
        if o["verifier_accepted"] and not o["gt_valid"] and n["verifier_accepted"]
    )
    old_exploits = sum(
        1 for o in regression_rows_old if o["verifier_accepted"] and not o["gt_valid"]
    )

    return {
        "schema_version": "1",
        "regression_old": old_m.as_dict(),
        "regression_new": new_m.as_dict(),
        "fresh_attack": fresh_m.as_dict(),
        "frr_delta": _sub(new_m.overall.frr, old_m.overall.frr),
        "far_delta_regression": _sub(new_m.overall.far, old_m.overall.far),
        "fresh_far": fresh_m.overall.far,
        "learnability": (still_exploitable / old_exploits) if old_exploits else 0.0,
        "cost": {
            "regression_n": len(regression_trajectories),
            "fresh_n": len(fresh_attack_results),
        },
        "mandatory_fresh_attacker": True,
    }


def _sub(a: float | None, b: float | None) -> float | None:
    if a is None or b is None:
        return None
    return a - b


def _run_fresh_attack(
    *,
    strategy_name: str,
    config: dict[str, Any],
    verifier: Callable[[dict[str, Any]], bool],
    is_valid: Callable[[dict[str, Any]], bool],
    episodes: int,
    build_trajectory: Callable[[list[dict[str, Any]]], dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    strategy = create_strategy(strategy_name, {**config, "seed": int(config.get("seed", 99))})
    rows: list[dict[str, Any]] = []
    for i in range(episodes):
        steps = [strategy.propose() for _ in range(int(config.get("max_steps", 2)))]
        # Strip private keys
        clean = [{k: v for k, v in s.items() if not str(k).startswith("_")} for s in steps]
        traj = build_trajectory(clean) if build_trajectory else {"schema_version": "1", "steps": clean}
        accepted = bool(verifier(traj))
        valid = bool(is_valid(traj))
        feedback = public_attack_feedback(
            {
                "verifier_accepted": accepted,
                "gt_valid": valid,  # stripped before observe
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
            }
        )
    return rows
