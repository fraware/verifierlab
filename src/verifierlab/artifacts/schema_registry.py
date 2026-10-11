"""Central artifact schema registry and one-way migrations (WP-17).

Unknown versions fail closed. Migrations run only when semantics are
recoverable. Migrations must never upgrade maturity labels.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from verifierlab.artifacts.canonical import canonical_dumps, digest_of

REGISTRY_CANDIDATES = (
    Path(__file__).resolve().parents[3] / "registry" / "schema-registry-v1.json",
    Path.cwd() / "registry" / "schema-registry-v1.json",
)


def _default_registry_path() -> Path:
    for candidate in REGISTRY_CANDIDATES:
        if candidate.is_file():
            return candidate
    return REGISTRY_CANDIDATES[0]


REGISTRY_PATH = REGISTRY_CANDIDATES[0]

# Maturity-related keys that migrations must never elevate.
_MATURITY_KEYS = frozenset(
    {
        "maturity",
        "maturity_level",
        "assurance_maturity",
        "scientifically_qualified",
        "security_grade",
        "deployment_calibrated",
        "independently_verified",
    }
)

MigrationFn = Callable[[dict[str, Any]], dict[str, Any]]


class SchemaRegistryError(ValueError):
    """Fail-closed schema / migration error."""


class ArtifactSchemaEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_type: str
    current_version: str
    supported_versions: tuple[str, ...]
    migrations: tuple[dict[str, str], ...] = ()
    module: str | None = None
    notes: str | None = None


class SchemaRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1"
    title: str = "VerifierLab artifact schema registry"
    artifacts: tuple[ArtifactSchemaEntry, ...] = ()
    canonical_serialization: dict[str, Any] = Field(default_factory=dict)
    deprecation_policy: str = ""

    def entry(self, artifact_type: str) -> ArtifactSchemaEntry:
        for item in self.artifacts:
            if item.artifact_type == artifact_type:
                return item
        raise SchemaRegistryError(f"unknown artifact_type={artifact_type!r}")

    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def load_schema_registry(path: Path | None = None) -> SchemaRegistry:
    target = path or _default_registry_path()
    if not target.is_file():
        raise SchemaRegistryError(f"schema registry missing: {target}")
    raw = json.loads(target.read_text(encoding="utf-8"))
    artifacts = tuple(
        ArtifactSchemaEntry(
            artifact_type=str(row["artifact_type"]),
            current_version=str(row["current_version"]),
            supported_versions=tuple(str(v) for v in row.get("supported_versions") or []),
            migrations=tuple(dict(m) for m in row.get("migrations") or []),
            module=row.get("module"),
            notes=row.get("notes"),
        )
        for row in raw.get("artifacts") or []
    )
    return SchemaRegistry(
        schema_version=str(raw.get("schema_version") or "1"),
        title=str(raw.get("title") or "VerifierLab artifact schema registry"),
        artifacts=artifacts,
        canonical_serialization=dict(raw.get("canonical_serialization") or {}),
        deprecation_policy=str(raw.get("deprecation_policy") or ""),
    )


def _strip_forbidden_maturity_upgrades(
    before: dict[str, Any], after: dict[str, Any]
) -> dict[str, Any]:
    """Ensure migrations cannot promote maturity-related fields."""
    out = dict(after)
    for key in _MATURITY_KEYS:
        if key in before:
            out[key] = before[key]
        elif key in out:
            # Drop newly introduced maturity claims.
            out.pop(key, None)
    return out


def migrate_beam_checkpoint_v1_to_v2(payload: dict[str, Any]) -> dict[str, Any]:
    """Recover real beam scores from the v1 negated-score bug."""
    out = dict(payload)
    version = str(out.get("schema_version", "1"))
    if version != "1":
        raise SchemaRegistryError(f"beam_checkpoint v1→v2 expects schema_version=1, got {version!r}")
    beam = []
    for item in out.get("beam") or []:
        stored_score, counter, action = item
        beam.append([-float(stored_score), int(counter), dict(action)])
    out["beam"] = beam
    out["schema_version"] = "2"
    return out


def migrate_verifier_profile_v1_to_v2(payload: dict[str, Any]) -> dict[str, Any]:
    """Lift v1 profiles into v2 with explicit decision semantics (no mapping invent)."""
    out = dict(payload)
    version = str(out.get("schema_version", "1"))
    if version != "1":
        raise SchemaRegistryError(
            f"verifier_profile v1→v2 expects schema_version=1, got {version!r}"
        )
    out.setdefault(
        "decision_semantics",
        {
            "status_set": ["accept", "reject", "abstain", "indeterminate", "error"],
            "fail_closed": True,
            "numeric_scores_imply_acceptance": out.get("decision_mapping") is not None,
            "score_mapping": out.get("decision_mapping"),
        },
    )
    out.setdefault("applicability", {})
    out.setdefault("access_surface", {})
    # Do not invent a ScoreDecisionMapping; leave None so scores stay indeterminate.
    out.setdefault("decision_mapping", None)
    out["schema_version"] = "2"
    return out


def migrate_label_vault_v1_to_v2(payload: dict[str, Any]) -> dict[str, Any]:
    """Mark v1 sealed envelopes as requiring v2 re-seal (semantics-preserving flag)."""
    out = dict(payload)
    version = str(out.get("schema_version", "1"))
    if version != "1":
        raise SchemaRegistryError(f"label_vault v1→v2 expects schema_version=1, got {version!r}")
    out["schema_version"] = "2"
    out["migration"] = {
        "from": "1",
        "to": "2",
        "requires_reseal": True,
        "note": "v1 envelopes are readable but must be re-sealed under v2 crypto",
    }
    return out


_MIGRATIONS: dict[str, MigrationFn] = {
    "beam_checkpoint_v1_to_v2": migrate_beam_checkpoint_v1_to_v2,
    "verifier_profile_v1_to_v2": migrate_verifier_profile_v1_to_v2,
    "label_vault_v1_to_v2": migrate_label_vault_v1_to_v2,
}


def migrate_artifact(
    artifact_type: str,
    payload: dict[str, Any],
    *,
    to_version: str,
    registry: SchemaRegistry | None = None,
) -> dict[str, Any]:
    """One-way migrate ``payload`` to ``to_version``; unknown versions fail closed."""
    reg = registry or load_schema_registry()
    entry = reg.entry(artifact_type)
    current = str(payload.get("schema_version") or "")
    if not current:
        raise SchemaRegistryError(f"{artifact_type}: missing schema_version")
    if current == to_version:
        return dict(payload)
    if to_version not in entry.supported_versions:
        raise SchemaRegistryError(
            f"{artifact_type}: unsupported target version {to_version!r}; "
            f"supported={list(entry.supported_versions)}"
        )
    if current not in entry.supported_versions:
        raise SchemaRegistryError(
            f"{artifact_type}: unknown source version {current!r} (fail closed)"
        )

    # Walk registered one-step migrations until target reached.
    working = dict(payload)
    guard = 0
    while str(working.get("schema_version")) != to_version:
        src = str(working.get("schema_version"))
        step = next(
            (m for m in entry.migrations if m.get("from") == src and m.get("to")),
            None,
        )
        if step is None:
            raise SchemaRegistryError(
                f"{artifact_type}: no migration path from {src!r} to {to_version!r}"
            )
        mid = step.get("id")
        if not mid or mid not in _MIGRATIONS:
            raise SchemaRegistryError(f"{artifact_type}: unknown migration id {mid!r}")
        before = dict(working)
        working = _MIGRATIONS[mid](working)
        working = _strip_forbidden_maturity_upgrades(before, working)
        if str(working.get("schema_version")) == src:
            raise SchemaRegistryError(f"{artifact_type}: migration {mid} did not advance version")
        guard += 1
        if guard > 16:
            raise SchemaRegistryError(f"{artifact_type}: migration loop detected")
    return working


def verify_artifact_payload(
    artifact_type: str,
    payload: dict[str, Any],
    *,
    expected_digest: str | None = None,
    registry: SchemaRegistry | None = None,
) -> dict[str, Any]:
    """Verify schema_version support + optional digest; return a report dict."""
    reg = registry or load_schema_registry()
    entry = reg.entry(artifact_type)
    version = str(payload.get("schema_version") or "")
    ok = True
    reasons: list[str] = []
    if version not in entry.supported_versions:
        ok = False
        reasons.append(f"unsupported schema_version={version!r}")
    digest = digest_of(payload)
    if expected_digest is not None and digest != expected_digest:
        ok = False
        reasons.append("digest_mismatch")
    return {
        "ok": ok,
        "artifact_type": artifact_type,
        "schema_version": version,
        "current_version": entry.current_version,
        "digest": digest,
        "reasons": reasons,
    }


def verify_bundle_dir(path: Path, *, registry: SchemaRegistry | None = None) -> dict[str, Any]:
    """Verify a run or study bundle directory for reconstructability basics."""
    root = Path(path)
    reg = registry or load_schema_registry()
    reasons: list[str] = []
    artifacts: list[dict[str, Any]] = []
    if not root.is_dir():
        return {"ok": False, "path": str(root), "reasons": ["not_a_directory"], "artifacts": []}

    manifest = root / "manifest.json"
    bundle_json = root / "bundle.json"
    tip: dict[str, Any] | None = None
    if manifest.is_file():
        tip = json.loads(manifest.read_text(encoding="utf-8"))
        artifacts.append(
            {
                "path": "manifest.json",
                "digest": digest_of(tip),
                "schema_version": tip.get("schema_version"),
            }
        )
    elif bundle_json.is_file():
        tip = json.loads(bundle_json.read_text(encoding="utf-8"))
        report = verify_artifact_payload(
            "reproduction_bundle",
            tip if isinstance(tip, dict) else {"schema_version": "1", "body": tip},
            registry=reg,
        )
        artifacts.append({"path": "bundle.json", **report})
        if not report["ok"]:
            reasons.extend(report["reasons"])
    else:
        reasons.append("missing_manifest_or_bundle")

    # Optional maturity file: migrations/verify must not invent promotions.
    for name in ("maturity_qualification.json", "claim.json"):
        candidate = root / name
        if candidate.is_file():
            body = json.loads(candidate.read_text(encoding="utf-8"))
            artifacts.append(
                {
                    "path": name,
                    "digest": digest_of(body),
                    "maturity": body.get("maturity") or body.get("maturity_level"),
                }
            )

    # One-byte tamper surface: digests of listed JSON files.
    digests: dict[str, str] = {}
    for json_path in sorted(root.rglob("*.json")):
        rel = str(json_path.relative_to(root)).replace("\\", "/")
        digests[rel] = digest_of(json.loads(json_path.read_text(encoding="utf-8")))

    return {
        "ok": not reasons,
        "path": str(root),
        "registry_digest": reg.content_digest(),
        "reasons": reasons,
        "artifacts": artifacts,
        "file_digests": digests,
        "canonical_bytes_probe": canonical_dumps({"schema_registry": reg.schema_version}).hex()[:16],
    }


__all__ = [
    "REGISTRY_PATH",
    "ArtifactSchemaEntry",
    "SchemaRegistry",
    "SchemaRegistryError",
    "load_schema_registry",
    "migrate_artifact",
    "migrate_beam_checkpoint_v1_to_v2",
    "migrate_label_vault_v1_to_v2",
    "migrate_verifier_profile_v1_to_v2",
    "verify_artifact_payload",
    "verify_bundle_dir",
]
