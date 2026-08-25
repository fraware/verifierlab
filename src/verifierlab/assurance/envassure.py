"""EnvAssure interoperability (WP-14).

``EnvironmentAssuranceRef`` binds a frozen environment-assurance evidence bundle
into VerifierLab campaign/run/study identity. Upstream EnvAssure indeterminate
or conflict status propagates and cannot be erased by verifier success.

Cross-repo schema mismatches fail closed with migration guidance.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from verifierlab.artifacts.canonical import digest_of

ENVAASSURE_SCHEMA_VERSION = "1"
SUPPORTED_BUNDLE_SCHEMA_VERSIONS = frozenset({"1"})
EXPECTED_COMPILER_SCHEMA = "eac-r15"

EnvAssureStatus = Literal[
    "determinate",
    "indeterminate",
    "conflict",
    "abstention",
    "missing",
]
ClaimBoundary = Literal[
    "environment_only",
    "verifier_bound",
    "agent_bound",
    "full_chain",
    "none",
]


class EnvironmentAssuranceRef(BaseModel):
    """Reference to a frozen EnvAssure-style evidence bundle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    bundle_digest: str = Field(min_length=64, max_length=64)
    compiler_commit: str = Field(min_length=7)
    compiler_schema: str = Field(default=EXPECTED_COMPILER_SCHEMA, min_length=1)
    ir_runtime_digest: str = Field(min_length=64, max_length=64)
    assumption_set_digest: str = Field(min_length=64, max_length=64)
    reconciliation_digest: str | None = Field(default=None, min_length=64, max_length=64)
    validation_status: EnvAssureStatus = "determinate"
    eac_r15_registration_refs: tuple[str, ...] = ()
    eac_r15_evidence_refs: tuple[str, ...] = ()
    claim_boundary: ClaimBoundary = "environment_only"
    source_package_digest: str | None = Field(default=None, min_length=64, max_length=64)
    source_manifest_digest: str | None = Field(default=None, min_length=64, max_length=64)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _refs_nonempty_when_present(self) -> EnvironmentAssuranceRef:
        for ref in self.eac_r15_registration_refs + self.eac_r15_evidence_refs:
            if not str(ref).strip():
                raise ValueError("EAC-R15 refs must be non-empty strings")
        return self

    @property
    def digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))

    @property
    def is_determinate(self) -> bool:
        return self.validation_status == "determinate"

    @property
    def propagates_uncertainty(self) -> bool:
        return self.validation_status in {"indeterminate", "conflict", "abstention", "missing"}


class AssuranceChainManifest(BaseModel):
    """Binds environment + verifier + agent + proposition + applicability."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    chain_id: str = Field(min_length=1)
    environment_assurance_digest: str = Field(min_length=64, max_length=64)
    verifier_assurance_digest: str = Field(min_length=64, max_length=64)
    agent_configuration_digest: str = Field(min_length=64, max_length=64)
    proposition_digest: str = Field(min_length=64, max_length=64)
    applicability_regime: str = Field(min_length=1)
    claim_boundary: ClaimBoundary = "full_chain"
    envassure_status: EnvAssureStatus = "determinate"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))

    @property
    def chain_indeterminate(self) -> bool:
        return self.envassure_status in {"indeterminate", "conflict", "abstention", "missing"}


class EnvAssureBundleError(ValueError):
    """Fail-closed EnvAssure binding / schema error."""


def load_environment_assurance_ref(path: Path | str) -> EnvironmentAssuranceRef:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise EnvAssureBundleError("EnvironmentAssuranceRef must be a JSON object")
    return EnvironmentAssuranceRef.model_validate(data)


def verify_frozen_envassure_bundle(
    bundle_path: Path | str,
    *,
    expected_digest: str | None = None,
    expected_compiler_schema: str = EXPECTED_COMPILER_SCHEMA,
) -> EnvironmentAssuranceRef:
    """Load and verify a frozen EnvAssure-style evidence bundle.

    Tamper, digest drift, and unsupported schema versions fail closed.
    """
    path = Path(bundle_path)
    if not path.is_file():
        raise EnvAssureBundleError(f"EnvAssure bundle missing: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EnvAssureBundleError(f"EnvAssure bundle unreadable: {exc}") from exc
    if not isinstance(raw, dict):
        raise EnvAssureBundleError("EnvAssure bundle root must be an object")

    schema_ver = str(raw.get("schema_version") or "")
    if schema_ver not in SUPPORTED_BUNDLE_SCHEMA_VERSIONS:
        raise EnvAssureBundleError(
            f"unsupported EnvAssure bundle schema_version={schema_ver!r}; "
            f"supported={sorted(SUPPORTED_BUNDLE_SCHEMA_VERSIONS)}; "
            "migration guidance: re-compile the environment evidence with a "
            f"compiler emitting schema {ENVAASSURE_SCHEMA_VERSION} and refresh "
            "EnvironmentAssuranceRef digests (cross-repo schema mismatch is fail-closed)"
        )

    compiler_schema = str(raw.get("compiler_schema") or "")
    if compiler_schema != expected_compiler_schema:
        raise EnvAssureBundleError(
            f"EnvAssure compiler_schema mismatch: got {compiler_schema!r}, "
            f"expected {expected_compiler_schema!r}; "
            "migration guidance: upgrade/downgrade environment-assurance-compiler "
            "to the pinned EAC-R15 line or update VerifierLab's expected schema "
            "via an explicit one-way migration artifact (unknown versions refuse)"
        )

    # Bundle body excluding optional content_digest for identity.
    body = {k: v for k, v in raw.items() if k != "content_digest"}
    computed = digest_of(body)
    declared = raw.get("content_digest")
    if declared is not None and str(declared) != computed:
        raise EnvAssureBundleError(
            "EnvAssure bundle content_digest drift/tamper detected (fail closed)"
        )
    if expected_digest is not None and computed != expected_digest:
        raise EnvAssureBundleError(
            "EnvAssure bundle digest does not match EnvironmentAssuranceRef.bundle_digest"
        )

    ref_payload = raw.get("environment_assurance_ref") or raw.get("ref")
    if isinstance(ref_payload, dict):
        ref = EnvironmentAssuranceRef.model_validate(ref_payload)
    else:
        # Synthetic frozen fixture may embed the ref fields at top level.
        ref = EnvironmentAssuranceRef.model_validate(
            {
                "bundle_digest": computed,
                "compiler_commit": raw.get("compiler_commit") or ("0" * 40),
                "compiler_schema": compiler_schema or expected_compiler_schema,
                "ir_runtime_digest": raw.get("ir_runtime_digest") or ("0" * 64),
                "assumption_set_digest": raw.get("assumption_set_digest") or ("0" * 64),
                "reconciliation_digest": raw.get("reconciliation_digest"),
                "validation_status": raw.get("validation_status") or "determinate",
                "eac_r15_registration_refs": tuple(raw.get("eac_r15_registration_refs") or ()),
                "eac_r15_evidence_refs": tuple(raw.get("eac_r15_evidence_refs") or ()),
                "claim_boundary": raw.get("claim_boundary") or "environment_only",
                "source_package_digest": raw.get("source_package_digest"),
                "source_manifest_digest": raw.get("source_manifest_digest"),
                "metadata": dict(raw.get("metadata") or {}),
            }
        )
    if (
        ref.bundle_digest != computed
        and expected_digest is None
        and (declared is None or ref.bundle_digest != str(declared))
    ):
        raise EnvAssureBundleError(
            "EnvironmentAssuranceRef.bundle_digest does not match frozen bundle body"
        )
    return ref


def build_assurance_chain(
    *,
    chain_id: str,
    env_ref: EnvironmentAssuranceRef,
    verifier_assurance_digest: str,
    agent_configuration_digest: str,
    proposition_digest: str,
    applicability_regime: str,
    claim_boundary: ClaimBoundary = "full_chain",
    metadata: dict[str, Any] | None = None,
) -> AssuranceChainManifest:
    """Compose a chain manifest; EnvAssure status is copied, never upgraded."""
    return AssuranceChainManifest(
        chain_id=chain_id,
        environment_assurance_digest=env_ref.digest,
        verifier_assurance_digest=verifier_assurance_digest,
        agent_configuration_digest=agent_configuration_digest,
        proposition_digest=proposition_digest,
        applicability_regime=applicability_regime,
        claim_boundary=claim_boundary,
        envassure_status=env_ref.validation_status,
        metadata=dict(metadata or {}),
    )


FactOutcomeLike = Literal["true", "false", "indeterminate"]


def propagate_envassure_into_qualification(
    *,
    env_ref: EnvironmentAssuranceRef | None,
    verifier_success: bool,
) -> tuple[FactOutcomeLike, tuple[str, ...]]:
    """Return (outcome, reasons) for environment_assurance_determinate fact.

    Verifier success never upgrades EnvAssure indeterminate/conflict/abstention.
    """
    if env_ref is None:
        return "indeterminate", ("environment_assurance_ref_absent",)
    if env_ref.propagates_uncertainty:
        return (
            "indeterminate" if env_ref.validation_status != "conflict" else "false",
            (
                f"envassure_status={env_ref.validation_status}",
                "verifier_success_cannot_erase_envassure_uncertainty"
                if verifier_success
                else "upstream_envassure_uncertainty",
            ),
        )
    if env_ref.is_determinate:
        return "true", ()
    return "false", (f"envassure_status={env_ref.validation_status}",)


def write_synthetic_frozen_bundle(
    path: Path | str,
    *,
    compiler_commit: str = "deadbeefcafebabe0123456789abcdef01234567",
    validation_status: EnvAssureStatus = "determinate",
    extra: dict[str, Any] | None = None,
) -> tuple[Path, EnvironmentAssuranceRef, str]:
    """Write a synthetic EnvAssure-style frozen evidence bundle (fixture OK)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    ir = digest_of({"ir": "synthetic-envassure-ir", "v": 1})
    assumptions = digest_of({"assumptions": ["fixture_environment"], "v": 1})
    body: dict[str, Any] = {
        "schema_version": "1",
        "compiler_schema": EXPECTED_COMPILER_SCHEMA,
        "compiler_commit": compiler_commit,
        "ir_runtime_digest": ir,
        "assumption_set_digest": assumptions,
        "validation_status": validation_status,
        "eac_r15_registration_refs": ("EAC-R15-FIX-001",),
        "eac_r15_evidence_refs": ("eac:evidence:fixture-1",),
        "claim_boundary": "environment_only",
        "metadata": {"synthetic": True, "non_live": True},
    }
    if extra:
        body.update(extra)
    content_digest = digest_of(body)
    body["content_digest"] = content_digest
    ref = EnvironmentAssuranceRef(
        bundle_digest=content_digest,
        compiler_commit=compiler_commit,
        compiler_schema=EXPECTED_COMPILER_SCHEMA,
        ir_runtime_digest=ir,
        assumption_set_digest=assumptions,
        validation_status=validation_status,
        eac_r15_registration_refs=("EAC-R15-FIX-001",),
        eac_r15_evidence_refs=("eac:evidence:fixture-1",),
        claim_boundary="environment_only",
        metadata={"synthetic": True, "non_live": True},
    )
    path.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path, ref, content_digest


__all__ = [
    "ENVAASSURE_SCHEMA_VERSION",
    "EXPECTED_COMPILER_SCHEMA",
    "SUPPORTED_BUNDLE_SCHEMA_VERSIONS",
    "AssuranceChainManifest",
    "ClaimBoundary",
    "EnvAssureBundleError",
    "EnvAssureStatus",
    "EnvironmentAssuranceRef",
    "build_assurance_chain",
    "load_environment_assurance_ref",
    "propagate_envassure_into_qualification",
    "verify_frozen_envassure_bundle",
    "write_synthetic_frozen_bundle",
]
