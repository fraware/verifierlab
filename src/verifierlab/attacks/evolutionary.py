"""Evolutionary multi-objective search (reward, novelty, cost)."""

from __future__ import annotations

import copy
import random
from typing import Any

from verifierlab.attacks.fuzzing import DEFAULT_SCHEMA, mutate_action
from verifierlab.attacks.registry import register


def _dominates(a: tuple[float, float, float], b: tuple[float, float, float]) -> bool:
    """Maximize reward & novelty, minimize cost (negated as third obj)."""
    return all(x >= y for x, y in zip(a, b, strict=True)) and any(
        x > y for x, y in zip(a, b, strict=True)
    )


@register("evolutionary")
class EvolutionarySearch:
    """Population-based search with mutation/crossover and Pareto archive."""

    COHORT = "optimized"

    def __init__(self) -> None:
        self._rng = random.Random(0)
        self._schema = dict(DEFAULT_SCHEMA)
        self._population: list[dict[str, Any]] = []
        self._fitness: list[tuple[float, float, float]] = []
        self._seed = 0
        self._pop_size = 16
        self._idx = 0

    def initialize(self, config: dict[str, Any]) -> None:
        self._seed = int(config.get("seed", 0))
        self._rng = random.Random(self._seed)
        self._pop_size = int(config.get("population", 16))
        if "schema" in config:
            self._schema = dict(config["schema"])
        seeds = list(
            config.get(
                "seeds",
                [
                    {"op": "refund", "amount": 50},
                    {"op": "refund", "amount": 120},
                    {"op": "duplicate", "amount": 100},
                    {"op": "approve", "approval_id": "REUSED", "amount": 200},
                ],
            )
        )
        self._population = [dict(s) for s in seeds]
        while len(self._population) < self._pop_size:
            base = self._rng.choice(seeds)
            self._population.append(mutate_action(self._rng, base, self._schema))
        self._fitness = [(0.0, 0.0, 0.0)] * len(self._population)
        self._idx = 0

    def propose(self) -> dict[str, Any]:
        if self._rng.random() < 0.2 and len(self._population) >= 2:
            # Crossover: splice fields from two parents.
            a, b = self._rng.sample(self._population, 2)
            child = dict(a)
            for key in b:
                if self._rng.random() < 0.5:
                    child[key] = copy.deepcopy(b[key])
            action = mutate_action(self._rng, child, self._schema)
        else:
            parent = self._population[self._idx % len(self._population)]
            action = mutate_action(self._rng, parent, self._schema)
            self._idx += 1
        action["_cohort"] = self.COHORT
        action["_strategy"] = "evolutionary"
        self._last_proposed = {k: v for k, v in action.items() if not str(k).startswith("_")}
        return action

    def observe(self, feedback: dict[str, Any]) -> None:
        # Public-channel fitness only — never read gt_valid / labels.
        reward = float(feedback.get("reward", 0.0))
        novelty = 1.0 if feedback.get("novel") else 0.0
        if feedback.get("verifier_accepted"):
            # Attacker objective proxy: public accept + reward is interesting.
            novelty = max(novelty, 1.0)
            reward = max(reward, 1.0)
        cost = float(feedback.get("cost", 1.0))
        fit = (reward, novelty, -cost)
        # Insert into population if non-dominated or replaces worst.
        if len(self._population) < self._pop_size:
            self._population.append(dict(getattr(self, "_last_proposed", {"op": "noop"})))
            self._fitness.append(fit)
            return
        # Replace a dominated or lowest-fitness individual.
        for i, existing in enumerate(self._fitness):
            if _dominates(fit, existing):
                self._population[i] = dict(getattr(self, "_last_proposed", {"op": "noop"}))
                self._fitness[i] = fit
                return
        worst = min(range(len(self._fitness)), key=lambda i: sum(self._fitness[i]))
        if sum(fit) > sum(self._fitness[worst]):
            self._population[worst] = dict(getattr(self, "_last_proposed", {"op": "noop"}))
            self._fitness[worst] = fit

    def checkpoint(self) -> dict[str, Any]:
        return {
            "strategy": "evolutionary",
            "cohort": self.COHORT,
            "seed": self._seed,
            "population": len(self._population),
        }
