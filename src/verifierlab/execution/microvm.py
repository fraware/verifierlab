"""MicroVM / separate-host execution backend interface (WP-02).

Docker-rootless is the production-ready backend on this tree. Stronger trust
domains are recognized by the capability negotiator without changing campaign
semantics; this module defines the interface even when unavailable locally.
"""

from __future__ import annotations

from typing import Any

from verifierlab.execution.protocol import (
    CapabilityNegotiation,
    ExecutionBackendKind,
    ExecutionPolicy,
)


class MicroVMExecutionBackend:
    """Placeholder microVM backend — refuse until a concrete hypervisor is wired."""

    backend_kind: ExecutionBackendKind = "microvm"

    def available(self) -> bool:
        return False

    def negotiate(self, policy: ExecutionPolicy) -> CapabilityNegotiation:
        return CapabilityNegotiation(
            requested_mode=policy.mode,
            docker_available=False,
            daemon_rootless=False,
            image_digest_pinned=bool(
                policy.worker_image and "@sha256:" in (policy.worker_image or "")
            ),
            supports_network_none=False,
            supports_read_only_root=False,
            supports_cap_drop=False,
            supports_no_new_privileges=False,
            supports_seccomp=False,
            supports_private_ipc=False,
            supports_private_cgroupns=False,
            supports_tmpfs_only=False,
            supports_resource_limits=False,
            microvm_available=False,
            separate_host_available=False,
            selected_backend=None,
            refused=True,
            refusal_reasons=("microvm_backend_unavailable",),
        )

    def execute(self, work_unit: dict[str, Any], *, policy: ExecutionPolicy) -> dict[str, Any]:
        del work_unit, policy
        raise RuntimeError("microvm backend is not available on this host")


class SeparateHostExecutionBackend:
    """Placeholder separate-host backend interface."""

    backend_kind: ExecutionBackendKind = "separate_host"

    def available(self) -> bool:
        return False

    def negotiate(self, policy: ExecutionPolicy) -> CapabilityNegotiation:
        return CapabilityNegotiation(
            requested_mode=policy.mode,
            docker_available=False,
            daemon_rootless=False,
            image_digest_pinned=bool(
                policy.worker_image and "@sha256:" in (policy.worker_image or "")
            ),
            supports_network_none=False,
            supports_read_only_root=False,
            supports_cap_drop=False,
            supports_no_new_privileges=False,
            supports_seccomp=False,
            supports_private_ipc=False,
            supports_private_cgroupns=False,
            supports_tmpfs_only=False,
            supports_resource_limits=False,
            microvm_available=False,
            separate_host_available=False,
            selected_backend=None,
            refused=True,
            refusal_reasons=("separate_host_backend_unavailable",),
        )

    def execute(self, work_unit: dict[str, Any], *, policy: ExecutionPolicy) -> dict[str, Any]:
        del work_unit, policy
        raise RuntimeError("separate_host backend is not available on this host")


__all__ = [
    "MicroVMExecutionBackend",
    "SeparateHostExecutionBackend",
]
