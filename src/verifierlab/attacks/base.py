"""Shared attack strategy helpers and registry."""

from __future__ import annotations

import random
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from verifierlab.artifacts.canonical import digest_of


class BaseAttack(ABC):
    """Minimal attack strategy base implementing the protocol."""

    name: str = "base"
    cohort: str = "unspecified"

    def __init__(self) -> None:
        self._config: dict[str, Any] = {}
        self._rng = random.Random(0)
        self._history: list[dict[str, Any]] = []

    def initialize(self, config: dict[str, Any]) -> None:
        self._config = dict(config)
        seed = int(config.get("seed", 0))
        self._rng = random.Random(seed)
        self._history = []
        if "cohort" in config:
            self.cohort = str(config["cohort"])

    @abstractmethod
    def propose(self) -> dict[str, Any]:
        """Propose the next action (or action sequence descriptor)."""

    def observe(self, feedback: dict[str, Any]) -> None:
        self._history.append(dict(feedback))

    def checkpoint(self) -> dict[str, Any]:
        return {
            "schema_version": "1",
            "name": self.name,
            "cohort": self.cohort,
            "config": self._config,
            "history_len": len(self._history),
            "rng_state_digest": digest_of(str(self._rng.getstate())),
        }


AttackFactory = Callable[[], BaseAttack]

_REGISTRY: dict[str, AttackFactory] = {}


def register_attack(name: str, factory: AttackFactory) -> None:
    _REGISTRY[name] = factory


def get_attack(name: str) -> BaseAttack:
    if name not in _REGISTRY:
        raise KeyError(f"unknown attack strategy: {name!r}")
    return _REGISTRY[name]()


def list_attacks() -> list[str]:
    return sorted(_REGISTRY)


def intended_policy_actions() -> list[dict[str, Any]]:
    """Canonical intended (ordinary) refund policy actions."""
    return [
        {"op": "noop"},
        {"op": "refund", "amount": 10},
        {"op": "refund", "amount": 25},
        {"op": "refund", "amount": 50},
        {"op": "refund", "amount": 100},
        {"op": "check_balance"},
    ]
