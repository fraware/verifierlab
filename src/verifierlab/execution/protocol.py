"""Secure execution protocols, capability negotiation, and probe reports."""

from __future__ import annotations

from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from verifierlab.artifacts.canonical import digest_of

ExecutionBackendKind = Literal[
    "docker_rootless",
    "docker_rootful",
    "microvm",
    "separate_host",
    "local_dev",
]

LauncherMode = Literal["local_dev", "security_grade"]


class IsolationProbeOutcome(BaseModel):
    """One malicious-probe attempt and whether isolation denied it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    probe_id: str = Field(min_length=1)
    attempted: bool
    denied_or_absent: bool
    evidence_digest: str = Field(min_length=1)
    detail: str | None = None


class IsolationProbeReport(BaseModel):
    """Catalogue outcomes for probes run inside the real executor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    backend_kind: ExecutionBackendKind
    ran_inside_executor: bool
    structural_only: bool
    secret_sentinels_absent: bool
    randomized_gt_paths_absent: bool
    outcomes: tuple[IsolationProbeOutcome, ...]
    all_required_denied: bool
    security_grade_eligible: bool

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class CapabilityNegotiation(BaseModel):
    """Host capability surface for selecting a secure backend — fail closed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    requested_mode: LauncherMode
    docker_available: bool
    daemon_rootless: bool
    image_digest_pinned: bool
    supports_network_none: bool
    supports_read_only_root: bool
    supports_cap_drop: bool
    supports_no_new_privileges: bool
    supports_seccomp: bool
    supports_private_ipc: bool
    supports_private_cgroupns: bool
    supports_tmpfs_only: bool
    supports_resource_limits: bool
    microvm_available: bool = False
    separate_host_available: bool = False
    selected_backend: ExecutionBackendKind | None
    refused: bool
    refusal_reasons: tuple[str, ...] = ()
    may_degrade_to_local: Literal[False] = False

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class ExecutionPolicy(BaseModel):
    """Campaign-selected execution plane. Local is development-only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    mode: LauncherMode = "local_dev"
    backend: ExecutionBackendKind | None = None
    worker_image: str | None = None
    require_rootless: bool = True
    run_isolation_probes: bool = True
    # Hard maturity ceiling when using local threads/processes.
    local_dev_maturity_cap: Literal["development_only"] = "development_only"

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


@runtime_checkable
class WorkUnitExecutor(Protocol):
    def execute(self, work_unit: dict[str, Any]) -> dict[str, Any]: ...


@runtime_checkable
class SecureLauncher(Protocol):
    """Campaign-facing security-grade executor protocol."""

    @property
    def backend_kind(self) -> ExecutionBackendKind: ...

    @property
    def security_grade(self) -> bool: ...

    def negotiate(self) -> CapabilityNegotiation: ...

    def execute(self, work_unit: dict[str, Any]) -> dict[str, Any]: ...


@runtime_checkable
class SecureExecutionBackend(Protocol):
    """Pluggable trust-domain backend (Docker-rootless, microVM, separate host)."""

    backend_kind: ExecutionBackendKind

    def available(self) -> bool: ...

    def negotiate(self, policy: ExecutionPolicy) -> CapabilityNegotiation: ...

    def execute(self, work_unit: dict[str, Any], *, policy: ExecutionPolicy) -> dict[str, Any]: ...


__all__ = [
    "CapabilityNegotiation",
    "ExecutionBackendKind",
    "ExecutionPolicy",
    "IsolationProbeOutcome",
    "IsolationProbeReport",
    "LauncherMode",
    "SecureExecutionBackend",
    "SecureLauncher",
    "WorkUnitExecutor",
]
