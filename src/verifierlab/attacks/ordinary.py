"""Ordinary baseline attack — samples intended policy (mandatory cohort)."""

from __future__ import annotations

import random
from typing import Any

from verifierlab.attacks.registry import register


@register("ordinary")
class OrdinaryBaseline:
    """Sample actions from an intended benign policy.

    Cohort tag is always ``ordinary`` so metrics never pool with optimized attacks.
    """

    COHORT = "ordinary"

    def __init__(self) -> None:
        self._rng = random.Random(0)
        self._seed = 0
        self._policy: list[dict[str, Any]] = []
        self._step = 0
        self._max_steps = 3

    def initialize(self, config: dict[str, Any]) -> None:
        self._seed = int(config.get("seed", 0))
        self._rng = random.Random(self._seed)
        self._max_steps = int(config.get("max_steps", 3))
        self._step = 0
        # Allow campaign specs to place ordinary-policy sampling in an optimized
        # cohort (deterministic planted recovery) without rewriting the strategy.
        self._cohort_tag = str(config.get("cohort") or self.COHORT)
        self._policy = list(
            config.get(
                "actions",
                [
                    {"op": "noop"},
                    {"op": "refund", "amount": 25},
                    {"op": "refund", "amount": 50},
                    {"op": "refund", "amount": 75},
                ],
            )
        )

    def propose(self) -> dict[str, Any]:
        action = dict(self._policy[self._rng.randrange(len(self._policy))])
        action["_cohort"] = self._cohort_tag
        action["_strategy"] = "ordinary"
        self._step += 1
        return action

    def observe(self, feedback: dict[str, Any]) -> None:
        _ = feedback

    def checkpoint(self) -> dict[str, Any]:
        return {
            "strategy": "ordinary",
            "cohort": self.COHORT,
            "seed": self._seed,
            "step": self._step,
        }
