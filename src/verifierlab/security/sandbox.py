"""Sandbox profiles and trust-boundary documentation (VAL-R17 partial).

**Trust boundary (default local path):**
Attack plugins, verifier callables, and environment workers run as ordinary
Python in the campaign process / process-pool workers. Declarative
``SandboxProfile`` tags record *intent* (no network, RO mounts) but do **not**
enforce OS isolation by themselves.

**Optional container path:** install ``verifierlab[sandbox]`` and use
``verifierlab.security.docker_runner`` when a Docker engine is available.
Missing Docker degrades honestly to ``status=unavailable`` — never a silent
pass claiming isolation.
"""

from __future__ import annotations

from enum import Enum
from typing import Any


class SandboxProfile(str, Enum):
    """Declared isolation expectations for a campaign / work unit."""

    NONE = "none"
    LOCAL_NO_NETWORK = "local_no_network"
    READONLY_VERIFIER = "readonly_verifier"
    CONTAINER = "container"


LOCAL_TRUST_BOUNDARY = (
    "Default local execution trusts the host Python process. Attack/env plugins "
    "and verifier callables are not OS-isolated unless the optional Docker "
    "sandbox runner is enabled and healthy."
)


def default_reference_profile() -> dict[str, Any]:
    """Policy tags applied to offline planted packs."""
    return {
        "schema_version": "2",
        "profile": SandboxProfile.LOCAL_NO_NETWORK.value,
        "network": False,
        "verifier_mount": "read_only",
        "label_mount": "read_only",
        "worker_credentials_eq_vault": False,
        "integration_status": "declarative",
        "trust_boundary": LOCAL_TRUST_BOUNDARY,
        "notes": (
            "Declarative profile for reference campaigns; not a container runtime. "
            "Workers must not receive vault credentials. Use "
            "verifierlab[sandbox] + docker_runner for optional Docker isolation."
        ),
    }


def container_sandbox_profile(
    *,
    docker_available: bool | None = None,
) -> dict[str, Any]:
    """Profile for optional Docker-backed plugin isolation."""
    from verifierlab.security.docker_runner import docker_engine_status

    status = (
        docker_engine_status()
        if docker_available is None
        else {
            "available": bool(docker_available),
            "reason": "caller_override",
        }
    )
    available = bool(status.get("available"))
    return {
        "schema_version": "2",
        "profile": SandboxProfile.CONTAINER.value,
        "network": False,
        "verifier_mount": "read_only",
        "label_mount": "none",
        "worker_credentials_eq_vault": False,
        "integration_status": "enforced" if available else "unavailable",
        "docker": status,
        "trust_boundary": (
            "Container sandbox: no network, read-only mounts, resource limits "
            "when Docker is available."
            if available
            else "Docker unavailable — container isolation not enforced; "
            "falling back to local trust boundary."
        ),
        "notes": (
            "Requires verifierlab[sandbox] and a working Docker engine. "
            "Degrades honestly when Docker is missing."
        ),
    }
