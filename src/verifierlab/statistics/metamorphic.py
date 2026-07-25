"""Metamorphic / isomorphic invariance helpers (plan §13).

Ground-truth validity must be invariant under label-preserving remaps.
A sound verifier should match that invariance; planted buggy verifiers may not.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from typing import Any

# Actor aliases that preserve unauthorized / authorized semantics for GT.
DEFAULT_USER_REMAP = {
    "eve": "malory",
    "malory": "eve",
    "admin": "root_user",
    "root_user": "admin",
    "alice": "authorized_user",
    "authorized_user": "alice",
}


def isomorphic_remap(
    trajectory: dict[str, Any],
    *,
    user_map: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Deep-copy a trajectory with isomorphic actor remapping.

    Marks remapped steps with ``relabel=True`` for pack-C taxonomy binding.
    Cosmetic fields (``note``, ``display``) are flipped to stress surface form.
    """
    users = dict(user_map or DEFAULT_USER_REMAP)
    out = deepcopy(trajectory)
    new_steps: list[dict[str, Any]] = []
    for step in out.get("steps") or []:
        if not isinstance(step, dict):
            new_steps.append(step)
            continue
        s = dict(step)
        uid = s.get("user_id")
        if isinstance(uid, str) and uid in users:
            s["user_id"] = users[uid]
            s["relabel"] = True
            s["alias_of"] = uid
        # Surface-only noise that must not affect GT.
        if "note" in s:
            s["note"] = f"remap:{s['note']}"
        else:
            s["note"] = "isomorphic-surface"
        if s.get("op") == "duplicate":
            s["relabel"] = True
        new_steps.append(s)
    out["steps"] = new_steps
    if "pack_theme" in trajectory:
        out["pack_theme"] = trajectory["pack_theme"]
    out["isomorphic_remap"] = True
    return out


def assert_gt_invariance(
    trajectory: dict[str, Any],
    *,
    is_valid: Callable[[dict[str, Any]], bool],
    remap: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assert ground-truth validity is unchanged under isomorphic remap."""
    transformed = (remap or isomorphic_remap)(trajectory)
    before = bool(is_valid(trajectory))
    after = bool(is_valid(transformed))
    if before != after:
        raise AssertionError(
            f"GT metamorphic invariance violated: before={before} after={after}"
        )
    return {
        "invariant": "gt_validity",
        "before": before,
        "after": after,
        "held": True,
        "transformed": transformed,
    }


def verifier_invariance_report(
    trajectory: dict[str, Any],
    *,
    verifier: Callable[[dict[str, Any]], Any],
    is_valid: Callable[[dict[str, Any]], bool],
    remap: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compare verifier decisions before/after remap against GT invariance."""
    transformed = (remap or isomorphic_remap)(trajectory)
    gt_before = bool(is_valid(trajectory))
    gt_after = bool(is_valid(transformed))
    v_before = bool(verifier(trajectory))
    v_after = bool(verifier(transformed))
    return {
        "gt_invariant": gt_before == gt_after,
        "gt_before": gt_before,
        "gt_after": gt_after,
        "verifier_before": v_before,
        "verifier_after": v_after,
        "verifier_invariant": v_before == v_after,
    }
