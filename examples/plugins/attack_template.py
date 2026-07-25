"""Plugin template: attack strategy."""

from __future__ import annotations

import random
from typing import Any

from verifierlab.attacks.registry import register


@register("example_attack")
class ExampleAttack:
    def __init__(self) -> None:
        self._rng = random.Random(0)

    def initialize(self, config: dict[str, Any]) -> None:
        self._rng = random.Random(int(config.get("seed", 0)))

    def propose(self) -> dict[str, Any]:
        return {"op": "noop", "_cohort": "optimized", "_strategy": "example_attack"}

    def observe(self, feedback: dict[str, Any]) -> None:
        _ = feedback

    def checkpoint(self) -> dict[str, Any]:
        return {"strategy": "example_attack"}
