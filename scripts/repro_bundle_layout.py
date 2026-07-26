#!/usr/bin/env python3
"""Canonical reproducibility-bundle layout (Milestone D3).

Shared by ``build_repro_bundle.py``, ``verify_repro_bundle.py``, and tests.
Bundles never include vault keys, unreleased labels, or confidential trajectories.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"

# Required relative paths (files). Directories are implied by parents.
REQUIRED_FILES: tuple[str, ...] = (
    "README.md",
    "CITATION.cff",
    "MANIFEST.json",
    "verify.sh",
    "reproduce.sh",
    "campaign/campaign_plan.yaml",
    "profiles/verifier.json",
    "profiles/environment.json",
    "attacks/checkpoints/.gitkeep",
    "ledger/query_ledger.json",
    "freeze/freeze_record.json",
    "adjudication/release_public.json",
    "analysis/analysis_manifest.json",
    "analysis/stats_plan.json",
    "analysis/result_tables.json",
    "digests/container_digests.json",
    "digests/source_manifest.json",
    "digests/release_manifest.json",
    "locks/dependencies.lock.json",
    "seeds/seeds.json",
    "hardware/hardware.json",
)

# Path substrings / name patterns that must never appear in a published bundle.
FORBIDDEN_NAME_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\.pem$"),
    re.compile(r"(?i)\.key$"),
    re.compile(r"(?i)secret"),
    re.compile(r"(?i)private[_-]?key"),
    re.compile(r"(?i)^vault[/\\]"),
    re.compile(r"(?i)[/\\]vault[/\\]"),
    re.compile(r"(?i)unreleased[_-]?label"),
    re.compile(r"(?i)decrypt[_-]?key"),
)

FORBIDDEN_JSON_KEYS: frozenset[str] = frozenset(
    {
        "gt_valid",
        "ground_truth_label",
        "hidden_label",
        "vault_key",
        "decrypt_key",
        "encryption_key",
        "private_key",
    }
)


def required_member_list() -> list[str]:
    return list(REQUIRED_FILES)


def is_forbidden_relpath(rel: str) -> str | None:
    """Return a reason string if ``rel`` is forbidden, else None."""
    normalized = rel.replace("\\", "/")
    for pat in FORBIDDEN_NAME_PATTERNS:
        if pat.search(normalized):
            return f"forbidden path pattern matched: {pat.pattern}"
    return None


def _scan_json_for_forbidden_keys(obj: Any, *, path: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_s = str(key)
            loc = f"{path}.{key_s}" if path else key_s
            if key_s in FORBIDDEN_JSON_KEYS:
                hits.append(loc)
            hits.extend(_scan_json_for_forbidden_keys(value, path=loc))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            hits.extend(_scan_json_for_forbidden_keys(item, path=f"{path}[{i}]"))
    return hits


def validate_bundle_tree(root: Path) -> dict[str, Any]:
    """Validate a unpacked bundle directory against the Milestone D layout."""
    root = Path(root)
    missing = [rel for rel in REQUIRED_FILES if not (root / rel).is_file()]
    forbidden_paths: list[dict[str, str]] = []
    forbidden_keys: list[dict[str, str]] = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        reason = is_forbidden_relpath(rel)
        if reason:
            forbidden_paths.append({"path": rel, "reason": reason})
            continue
        if path.suffix.lower() == ".json":
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for hit in _scan_json_for_forbidden_keys(payload):
                forbidden_keys.append({"path": rel, "key": hit})

    manifest_ok = False
    manifest_errors: list[str] = []
    manifest_path = root / "MANIFEST.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            members = manifest.get("members")
            if not isinstance(members, list):
                manifest_errors.append("MANIFEST.json.members must be a list")
            else:
                member_set = {str(m) for m in members}
                for rel in REQUIRED_FILES:
                    if rel == "MANIFEST.json":
                        continue  # the index itself need not list its own path
                    if rel.endswith(".gitkeep"):
                        # Directory presence is enough when other checkpoint files exist.
                        if (root / Path(rel).parent).is_dir():
                            continue
                    if rel not in member_set and not (root / rel).is_file():
                        manifest_errors.append(f"MANIFEST missing member entry: {rel}")
                    elif rel not in member_set and (root / rel).is_file():
                        # File exists but omitted from MANIFEST — still an error except gitkeep.
                        if not rel.endswith(".gitkeep"):
                            manifest_errors.append(f"MANIFEST missing member entry: {rel}")
                manifest_ok = not manifest_errors
        except (OSError, json.JSONDecodeError) as exc:
            manifest_errors.append(f"MANIFEST.json unreadable: {exc}")

    ok = not missing and not forbidden_paths and not forbidden_keys and (
        not manifest_path.is_file() or manifest_ok or not manifest_errors
    )
    # If MANIFEST exists, require it to be consistent.
    if manifest_path.is_file() and manifest_errors:
        ok = False

    return {
        "schema_version": SCHEMA_VERSION,
        "root": str(root),
        "ok": ok,
        "missing": missing,
        "forbidden_paths": forbidden_paths,
        "forbidden_keys": forbidden_keys,
        "manifest_errors": manifest_errors,
        "required": list(REQUIRED_FILES),
    }


__all__ = [
    "FORBIDDEN_JSON_KEYS",
    "FORBIDDEN_NAME_PATTERNS",
    "REQUIRED_FILES",
    "SCHEMA_VERSION",
    "is_forbidden_relpath",
    "required_member_list",
    "validate_bundle_tree",
]
