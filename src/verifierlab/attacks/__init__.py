"""Attack package exports."""

from __future__ import annotations

from verifierlab.attacks.identity import (
    AttackBudgetContract,
    AttackIdentity,
    build_attack_identity,
)
from verifierlab.attacks.portfolio import (
    PORTFOLIO_DEPTH_LIMITATIONS,
    AttackPortfolioManifest,
    build_default_portfolio,
    record_candidate_eval,
)
from verifierlab.attacks.registry import create_strategy, list_strategies, register
from verifierlab.attacks.runtime import (
    LEARNING_STRATEGIES,
    PersistentAttacker,
    attacker_store_path,
    is_learning_strategy,
)

__all__ = [
    "LEARNING_STRATEGIES",
    "PORTFOLIO_DEPTH_LIMITATIONS",
    "AttackBudgetContract",
    "AttackIdentity",
    "AttackPortfolioManifest",
    "PersistentAttacker",
    "attacker_store_path",
    "build_attack_identity",
    "build_default_portfolio",
    "create_strategy",
    "is_learning_strategy",
    "list_strategies",
    "record_candidate_eval",
    "register",
]
