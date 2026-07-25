"""Execution launchers."""

from __future__ import annotations

from verifierlab.api.protocols import CampaignLauncher
from verifierlab.execution.local import LocalLauncher

__all__ = ["CampaignLauncher", "LocalLauncher"]
