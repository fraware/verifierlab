"""Delta-debugging minimization and optional causal branch analysis."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def delta_debug(
    steps: list[dict[str, Any]],
    is_interesting: Callable[[list[dict[str, Any]]], bool],
) -> list[dict[str, Any]]:
    """Classic ddmin over trajectory steps.

    ``is_interesting`` should return True when the reduced step list still
    reproduces the failure predicate (e.g. verifier accept ∧ GT invalid).
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


def minimize_exploit(
    trajectory: dict[str, Any],
    *,
    verifier: Callable[[dict[str, Any]], bool],
    is_valid: Callable[[dict[str, Any]], bool],
) -> dict[str, Any]:
    """Minimize a failing trajectory preserving accept∧invalid."""

    def interesting(subset: list[dict[str, Any]]) -> bool:
        traj = {**trajectory, "steps": subset}
        return bool(verifier(traj)) and (not is_valid(traj))

    steps = list(trajectory.get("steps") or [])
    minimized = delta_debug(steps, interesting)
    causal = causal_branch_analysis(steps, interesting)
    return {
        "schema_version": "1",
        "original_steps": steps,
        "minimized_steps": minimized,
        "causal": causal,
    }
