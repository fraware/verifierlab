"""Delta-debugging minimization and optional causal branch analysis.

Minimization preserves **public acceptance** and **hidden invalidity**
(VAL-R14). Multidimensional predicates may additionally require specific
intent-clause violations to remain true on the reduced trajectory.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from verifierlab.exploits.dimensions import (
    ExploitPredicate,
    ValidityStatus,
    public_accept_hidden_invalid,
)


def delta_debug(
    steps: list[dict[str, Any]],
    is_interesting: Callable[[list[dict[str, Any]]], bool],
) -> list[dict[str, Any]]:
    """Classic ddmin over trajectory steps.

    ``is_interesting`` should return True when the reduced step list still
    reproduces the failure predicate (e.g. public accept ∧ hidden invalid).
    """
    if not steps:
        return []
    if not is_interesting(steps):
        return list(steps)

    n = 2
    current = list(steps)
    while len(current) >= 2:
        subset_size = max(1, len(current) // n)
        reduced = False
        for i in range(0, len(current), subset_size):
            complement = current[:i] + current[i + subset_size :]
            if complement and is_interesting(complement):
                current = complement
                n = max(2, n - 1)
                reduced = True
                break
        if not reduced:
            if n >= len(current):
                break
            n = min(len(current), n * 2)
    return current


def causal_branch_analysis(
    steps: list[dict[str, Any]],
    is_interesting: Callable[[list[dict[str, Any]]], bool],
) -> dict[str, Any]:
    """Optional snapshot-style causal branch: drop each step independently."""
    necessary: list[int] = []
    for i in range(len(steps)):
        without = steps[:i] + steps[i + 1 :]
        if not without or not is_interesting(without):
            necessary.append(i)
    return {
        "schema_version": "1",
        "necessary_indices": necessary,
        "necessary_steps": [steps[i] for i in necessary],
        "original_len": len(steps),
        "minimized_len": len(necessary),
    }


def _evaluate_public_hidden(
    traj: dict[str, Any],
    *,
    verifier: Callable[[dict[str, Any]], Any],
    is_valid: Callable[[dict[str, Any]], bool],
) -> tuple[bool, bool]:
    from verifierlab.api.verifier import normalize_decision

    accepted = normalize_decision(verifier(traj)).accepted is True
    valid = bool(is_valid(traj))
    return accepted, valid


def minimize_exploit(
    trajectory: dict[str, Any],
    *,
    verifier: Callable[[dict[str, Any]], bool],
    is_valid: Callable[[dict[str, Any]], bool],
    predicate: ExploitPredicate | None = None,
    dimension_evaluator: Callable[[dict[str, Any]], dict[str, ValidityStatus]] | None = None,
    stochastic_reruns: int = 1,
) -> dict[str, Any]:
    """Minimize a failing trajectory preserving public accept + hidden invalidity.

    When ``predicate`` is supplied, reduction must keep the predicate holding
    (public accept plus violated intent clauses). ``stochastic_reruns`` > 1
    re-evaluates the minimized trajectory for stability under non-determinism.
    """

    def interesting(subset: list[dict[str, Any]]) -> bool:
        traj = {**trajectory, "steps": subset}
        accepted, valid = _evaluate_public_hidden(traj, verifier=verifier, is_valid=is_valid)
        if predicate is None:
            return public_accept_hidden_invalid(verifier_accepted=accepted, is_valid=valid)
        dim_status: dict[str, ValidityStatus] | None = None
        if dimension_evaluator is not None:
            dim_status = dimension_evaluator(traj)
        elif not valid:
            dim_status = {"outcome": "fail"}
        else:
            dim_status = {"outcome": "pass"}
        return predicate.holds(public_accepted=accepted, dimension_status=dim_status)

    steps = list(trajectory.get("steps") or [])
    minimized = delta_debug(steps, interesting)
    causal = causal_branch_analysis(steps, interesting)

    min_traj = {**trajectory, "steps": minimized}
    accepted, valid = _evaluate_public_hidden(min_traj, verifier=verifier, is_valid=is_valid)
    preservation = {
        "public_accept_preserved": accepted,
        "hidden_invalid_preserved": (not valid) if accepted else False,
        "classic_predicate_holds": public_accept_hidden_invalid(
            verifier_accepted=accepted, is_valid=valid
        ),
        "access_budget_conditions": "caller_responsibility",
    }
    if predicate is not None:
        dim_status: dict[str, ValidityStatus] | None = None
        if dimension_evaluator is not None:
            dim_status = dimension_evaluator(min_traj)
        elif not valid:
            dim_status = {"outcome": "fail"}
        preservation["predicate_holds"] = predicate.holds(
            public_accepted=accepted, dimension_status=dim_status
        )
        preservation["violated_dimensions"] = predicate.violated_dimensions

    rerun_results: list[dict[str, Any]] = []
    reruns = max(1, int(stochastic_reruns))
    for i in range(reruns):
        a, v = _evaluate_public_hidden(min_traj, verifier=verifier, is_valid=is_valid)
        rerun_results.append(
            {
                "run": i,
                "accepted": a,
                "valid": v,
                "holds": public_accept_hidden_invalid(verifier_accepted=a, is_valid=v),
            }
        )
    stable = all(r["holds"] for r in rerun_results) if rerun_results else False
    preservation["stochastic_reruns"] = rerun_results
    preservation["stochastic_stable"] = stable

    return {
        "schema_version": "2",
        "original_steps": steps,
        "minimized_steps": minimized,
        "causal": causal,
        "preservation": preservation,
        "predicate": predicate.model_dump(mode="json") if predicate is not None else None,
    }
