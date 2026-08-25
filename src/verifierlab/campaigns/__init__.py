"""Campaign orchestration with lazy role-specific imports."""

from __future__ import annotations

from importlib import import_module
from typing import Any

_ENGINE_EXPORTS = frozenset(
    {
        "CampaignRunResult",
        "adjudicate_campaign",
        "default_workspace",
        "freeze_run",
        "init_workspace",
        "release_labels",
        "run_campaign",
    }
)
_LIFECYCLE_EXPORTS = frozenset({"LifecycleState", "assert_transition", "can_transition"})

__all__ = [
    "CampaignRunResult",
    "LifecycleState",
    "adjudicate_campaign",
    "assert_transition",
    "can_transition",
    "default_workspace",
    "freeze_run",
    "init_workspace",
    "release_labels",
    "run_campaign",
]


def __getattr__(name: str) -> Any:
    """Load coordinator modules only when their public attributes are requested.

    Importing ``verifierlab.campaigns.worker`` must not transitively import the
    campaign engine, lifecycle coordinator, vault, or adjudication service.
    """
    if name in _ENGINE_EXPORTS:
        return getattr(import_module("verifierlab.campaigns.engine"), name)
    if name in _LIFECYCLE_EXPORTS:
        return getattr(import_module("verifierlab.campaigns.lifecycle"), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
