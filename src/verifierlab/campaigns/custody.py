"""Hidden-holdout custody: opaque IDs and attack-plane side-channel hygiene (WP-04)."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Any

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import LabelTier

# Tokens that must never appear on the attack plane when encoding *hidden*
# (private_holdout) membership. Ordinary named holdout/eval splits may appear.
_HOLDOUT_LEAK_PATTERNS = (
    re.compile(r"private[_-]?holdout", re.IGNORECASE),
    re.compile(r"\bhidden[_-]?split\b", re.IGNORECASE),
    re.compile(r"\bhidden[_-]?holdout\b", re.IGNORECASE),
)

_ATTACK_PLANE_FORBIDDEN_KEYS = frozenset(
    {
        "true_unit_id",
        "custody_unit_id",
        "holdout_membership",
        "hidden_split",
        "private_holdout",
    }
)


def opaque_unit_token(*, run_salt: str, logical_unit_id: str, index: int) -> str:
    """Derive a non-predictable opaque ID that does not encode split membership.

    The token is a truncated HMAC so filenames and IDs cannot be inverted to
    recover campaign name, seed, or split role from the attack plane alone.
    """
    mac = hmac.new(
        run_salt.encode("utf-8"),
        f"{logical_unit_id}|{index}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"u-{mac[:32]}"


def is_private_holdout_tier(tier: str | LabelTier) -> bool:
    value = tier.value if isinstance(tier, LabelTier) else str(tier)
    return value == LabelTier.PRIVATE_HOLDOUT.value


def build_custody_map(
    units: list[dict[str, Any]],
    *,
    run_salt: str,
) -> dict[str, Any]:
    """Build sealed custody binding opaque IDs to true split membership."""
    entries: list[dict[str, Any]] = []
    for idx, unit in enumerate(units):
        logical_id = str(unit["unit_id"])
        opaque = opaque_unit_token(run_salt=run_salt, logical_unit_id=logical_id, index=idx)
        tier = str(unit.get("label_tier") or LabelTier.DEVELOPMENT.value)
        entries.append(
            {
                "opaque_id": opaque,
                "logical_unit_id": logical_id,
                "split": unit.get("split"),
                "label_tier": tier,
                "learning": bool(unit.get("learning", True)),
                "attack_visible": bool(unit.get("attack_visible", True)),
                "index": idx,
            }
        )
    body = {
        "schema_version": "1",
        "kind": "hidden_split_custody",
        "run_salt_digest": digest_of({"salt": run_salt}),
        "entries": entries,
    }
    body["content_digest"] = digest_of({k: v for k, v in body.items() if k != "content_digest"})
    return body


def public_split_view(custody: dict[str, Any]) -> dict[str, Any]:
    """Attack-plane split view: opaque IDs only; no holdout membership labels."""
    public_units: list[dict[str, Any]] = []
    for entry in custody.get("entries") or []:
        tier = str(entry.get("label_tier") or "")
        if is_private_holdout_tier(tier):
            public_units.append(
                {
                    "unit_id": entry["opaque_id"],
                    "split": "sealed",
                    "learning": False,
                    "label_tier": "sealed",
                    "attack_visible": False,
                }
            )
        else:
            public_units.append(
                {
                    "unit_id": entry["opaque_id"],
                    "split": entry.get("split"),
                    "learning": bool(entry.get("learning", True)),
                    "label_tier": entry.get("label_tier"),
                    "attack_visible": bool(entry.get("attack_visible", True)),
                }
            )
    body = {
        "schema_version": "2",
        "kind": "public_split_view",
        "custody_digest": custody.get("content_digest"),
        "units": public_units,
    }
    body["content_digest"] = digest_of({k: v for k, v in body.items() if k != "content_digest"})
    return body


def apply_opaque_ids_to_work_units(
    units: list[dict[str, Any]],
    custody: dict[str, Any],
) -> list[dict[str, Any]]:
    """Rewrite work units for the attack plane using opaque IDs and sealed splits."""
    by_logical = {str(e["logical_unit_id"]): e for e in custody.get("entries") or []}
    out: list[dict[str, Any]] = []
    for unit in units:
        logical = str(unit["unit_id"])
        entry = by_logical[logical]
        rewritten = dict(unit)
        rewritten["unit_id"] = entry["opaque_id"]
        # Never place the logical ID on the attack plane.
        rewritten.pop("logical_unit_id", None)
        tier = str(entry.get("label_tier") or "")
        if is_private_holdout_tier(tier):
            rewritten["split"] = "sealed"
            rewritten["learning"] = False
            rewritten["label_tier"] = "sealed"
            rewritten["attack_visible"] = False
        else:
            rewritten["split"] = entry.get("split")
            rewritten["learning"] = bool(entry.get("learning", True))
            rewritten["label_tier"] = entry.get("label_tier")
            rewritten["attack_visible"] = bool(entry.get("attack_visible", True))
        for key in _ATTACK_PLANE_FORBIDDEN_KEYS:
            rewritten.pop(key, None)
        out.append(rewritten)
    return out


def persist_custody(run_dir: Path, custody: dict[str, Any]) -> Path:
    """Write sealed custody under coordinator-only custody/ (not attack plane)."""
    path = Path(run_dir) / "custody" / "hidden_split.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(custody, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def persist_public_split_view(run_dir: Path, public_view: dict[str, Any]) -> Path:
    path = Path(run_dir) / "splits" / "public_view.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(public_view, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def scan_attack_plane_for_holdout_leakage(run_dir: Path) -> list[dict[str, str]]:
    """Recursive scan of attack-plane paths for holdout membership side channels."""
    run_dir = Path(run_dir)
    roots = [
        run_dir / "work_units",
        run_dir / "splits" / "public_view.json",
        run_dir / "attackers",
    ]
    hits: list[dict[str, str]] = []
    for root in roots:
        if root.is_file():
            _scan_file(root, run_dir, hits)
        elif root.is_dir():
            for path in root.rglob("*"):
                if path.is_file():
                    _scan_file(path, run_dir, hits)
    return hits


def _scan_file(path: Path, run_dir: Path, hits: list[dict[str, str]]) -> None:
    rel = path.relative_to(run_dir).as_posix()
    for pattern in _HOLDOUT_LEAK_PATTERNS:
        if pattern.search(rel):
            hits.append({"path": rel, "channel": "filename", "match": pattern.pattern})
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return
    # Public split view may use the literal token "sealed" only.
    for pattern in _HOLDOUT_LEAK_PATTERNS:
        if pattern.search(text):
            hits.append({"path": rel, "channel": "content", "match": pattern.pattern})
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    if isinstance(data, dict):
        for key in _ATTACK_PLANE_FORBIDDEN_KEYS:
            if key in data:
                hits.append({"path": rel, "channel": "key", "match": key})


def assert_no_holdout_side_channels(run_dir: Path) -> None:
    hits = scan_attack_plane_for_holdout_leakage(run_dir)
    if hits:
        raise ValueError(f"hidden-holdout side-channel leakage detected: {hits[:5]}")


def assert_split_rebind_rejected(
    *,
    sealed_split_digest: str,
    candidate_split_digest: str,
) -> None:
    if sealed_split_digest != candidate_split_digest:
        raise ValueError("split rebind rejected: sealed split digest mismatch")


__all__ = [
    "apply_opaque_ids_to_work_units",
    "assert_no_holdout_side_channels",
    "assert_split_rebind_rejected",
    "build_custody_map",
    "is_private_holdout_tier",
    "opaque_unit_token",
    "persist_custody",
    "persist_public_split_view",
    "public_split_view",
    "scan_attack_plane_for_holdout_leakage",
]
