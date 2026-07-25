"""Campaign orchestration."""

from __future__ import annotations

from verifierlab.campaigns.engine import (
    CampaignRunResult,
    adjudicate_campaign,
    default_workspace,
    freeze_run,
    init_workspace,
    release_labels,
    run_campaign,
)
from verifierlab.campaigns.lifecycle import LifecycleState, assert_transition, can_transition

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
