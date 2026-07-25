"""Configuration loading."""

from __future__ import annotations

from verifierlab.config.campaign import (
    BaselineSpec,
    CampaignSpec,
    CampaignSpecError,
    GroundTruthSpec,
    SplitSpec,
    StatsPlan,
    TargetRef,
    load_campaign,
    load_campaign_dict,
    validate_campaign_semantics,
)

__all__ = [
    "BaselineSpec",
    "CampaignSpec",
    "CampaignSpecError",
    "GroundTruthSpec",
    "SplitSpec",
    "StatsPlan",
    "TargetRef",
    "load_campaign",
    "load_campaign_dict",
    "validate_campaign_semantics",
]
