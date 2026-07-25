"""Sandbox profile declarations for reference campaigns.

**Non-claim:** profiles are declarative policy tags for planted packs and
docs — not a full OS/container sandbox runtime. Secret scanning and
worker/vault credential separation remain the enforced integrity controls.
"""

from __future__ import annotationsfrom enum import Enumfrom typing import Anyclass SandboxProfile(str, Enum):
    """Declared isolation expectations for a campaign / work unit."""

    NONE = "none"
    LOCAL_NO_NETWORK = "local_no_network"
    READONLY_VERIFIER = "readonly_verifier"


def default_reference_profile() -> dict[str, Any]:
    """Policy tags applied to offline planted packs."""
    return {
        "schema_version": "1",
        "profile": SandboxProfile.LOCAL_NO_NETWORK.value,
        "network": False,
        "verifier_mount": "read_only",
        "label_mount": "read_only",
        "worker_credentials_eq_vault": False,
        "integration_status": "declarative",
        "notes": (
            "Declarative profile for reference campaigns; not a container runtime. "
            "Workers must not receive vault credentials."
        ),
    }
