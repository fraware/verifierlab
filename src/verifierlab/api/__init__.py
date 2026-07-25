"""Public API surface: decorator, protocols, decisions."""

from __future__ import annotations

from verifierlab.api.decision import Decision, DecisionKind
from verifierlab.api.protocols import (
    AttackStrategy,
    CampaignLauncher,
    EnvironmentTarget,
    GroundTruthProvider,
)
from verifierlab.api.verifier import (
    get_verifier_spec,
    list_registered_verifiers,
    normalize_decision,
    verifier,
)
from verifierlab.artifacts.records import DecisionSpace, VerifierSpec

__all__ = [
    "AttackStrategy",
    "CampaignLauncher",
    "Decision",
    "DecisionKind",
    "DecisionSpace",
    "EnvironmentTarget",
    "GroundTruthProvider",
    "VerifierSpec",
    "get_verifier_spec",
    "list_registered_verifiers",
    "normalize_decision",
    "verifier",
]
