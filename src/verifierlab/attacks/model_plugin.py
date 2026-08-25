"""Model-capable attacker plugin interface (WP-09).

Provider extras are optional. The core package only defines the protocol and a
deterministic fixture plugin. Real LLM/provider bindings live behind extras and
must still emit an :class:`~verifierlab.attacks.identity.AttackIdentity`.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import AccessModel
from verifierlab.attacks.identity import (
    AttackBudgetContract,
    AttackIdentity,
    build_attack_identity,
)


@runtime_checkable
class ModelCapableAttacker(Protocol):
    """Provider-agnostic model-assisted attacker."""

    def identity(self) -> AttackIdentity:
        """Return the immutable AttackIdentity for this instance."""

    def propose(self, *, context: dict[str, Any]) -> dict[str, Any]:
        """Propose the next action given public context only."""

    def observe(self, feedback: dict[str, Any]) -> None:
        """Ingest public feedback (never hidden labels)."""

    def meter(self) -> dict[str, int]:
        """Return candidate-eval / query meters for budget enforcement."""


class DeterministicFixtureAttacker:
    """In-tree fixture implementing :class:`ModelCapableAttacker` without providers."""

    def __init__(
        self,
        *,
        seed: int = 0,
        access_model: AccessModel | str = AccessModel.BLACK_BOX,
        max_queries: int = 8,
        model_id: str = "fixture-model",
        model_version: str = "0",
    ) -> None:
        self._seed = seed
        self._access = AccessModel(access_model) if isinstance(access_model, str) else access_model
        self._max_queries = max_queries
        self._model_id = model_id
        self._model_version = model_version
        self._queries = 0
        self._candidate_evals = 0
        self._history: list[str] = []
        self._identity = build_attack_identity(
            strategy_name="model_fixture",
            strategy_version="1",
            source_digest=digest_of(
                "verifierlab.attacks.model_plugin:DeterministicFixtureAttacker"
            ),
            configuration={"seed": seed, "max_queries": max_queries},
            seed=seed,
            access_model=self._access,
            budget=AttackBudgetContract(max_queries=max_queries, max_candidate_evals=max_queries),
            depth="model_assisted",
            model_id=model_id,
            model_version=model_version,
            supports_unknown_robustness_claim=False,
            metadata={"provider": "fixture", "provider_extra_required": False},
        )

    def identity(self) -> AttackIdentity:
        return self._identity

    def propose(self, *, context: dict[str, Any]) -> dict[str, Any]:
        self._queries += 1
        self._candidate_evals += 1
        amount = 50 + (self._seed + self._queries) % 80
        action = {
            "op": "refund",
            "amount": amount,
            "user_id": "eve",
            "_cohort": "optimized",
            "_strategy": "model_fixture",
            "_context_digest": digest_of(context),
        }
        return action

    def observe(self, feedback: dict[str, Any]) -> None:
        self._history.append(digest_of(feedback))

    def meter(self) -> dict[str, int]:
        return {
            "queries": self._queries,
            "candidate_evals": self._candidate_evals,
            "budget_queries": self._max_queries,
        }


def load_model_attacker_plugin(
    ref: str, *, config: dict[str, Any] | None = None
) -> ModelCapableAttacker:
    """Load a model-capable attacker from a dotted ref or the built-in fixture.

    Optional provider extras may register entry points; missing providers fail
    closed rather than silently degrading to local search.
    """
    cfg = dict(config or {})
    if ref in {
        "fixture",
        "deterministic_fixture",
        "verifierlab.attacks.model_plugin:DeterministicFixtureAttacker",
    }:
        return DeterministicFixtureAttacker(
            seed=int(cfg.get("seed", 0)),
            access_model=cfg.get("access_model", AccessModel.BLACK_BOX),
            max_queries=int(cfg.get("max_queries", 8)),
            model_id=str(cfg.get("model_id", "fixture-model")),
            model_version=str(cfg.get("model_version", "0")),
        )
    from verifierlab.plugins.loader import load_object

    obj = load_object(ref)
    if callable(obj) and not isinstance(obj, ModelCapableAttacker):
        instance = obj(**cfg) if cfg else obj()
    else:
        instance = obj
    if not isinstance(instance, ModelCapableAttacker):
        raise TypeError(f"plugin {ref!r} does not implement ModelCapableAttacker")
    return instance


__all__ = [
    "DeterministicFixtureAttacker",
    "ModelCapableAttacker",
    "load_model_attacker_plugin",
]
