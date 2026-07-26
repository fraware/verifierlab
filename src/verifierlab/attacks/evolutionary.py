"""Evolutionary multi-objective search with persistent population + broker fitness."""

from __future__ import annotations

import copy
import random
from typing import Any

from verifierlab.attacks.fuzzing import DEFAULT_SCHEMA, mutate_action
from verifierlab.attacks.registry import register
from verifierlab.attacks.runtime import evaluate_candidate_trajectory


def _dominates(a: tuple[float, float, float], b: tuple[float, float, float]) -> bool:
    """Maximize reward & novelty, minimize cost (negated as third obj)."""
    return all(x >= y for x, y in zip(a, b, strict=True)) and any(
        x > y for x, y in zip(a, b, strict=True)
    )


@register("evolutionary")
class EvolutionarySearch:
    """Population-based search; fitness from broker queries, not one post-episode observe."""

    COHORT = "optimized"

    def __init__(self) -> None:
        self._rng = random.Random(0)
        self._schema = dict(DEFAULT_SCHEMA)
        self._population: list[dict[str, Any]] = []
        self._fitness: list[tuple[float, float, float]] = []
        self._seed = 0
        self._pop_size = 16
        self._idx = 0
        self._queries = 0
        self._episodes = 0
        self._broker: Any | None = None
        self._env: Any | None = None
        self._learning = True
        self._eval_batch = 4

    def initialize(self, config: dict[str, Any]) -> None:
        self._seed = int(config.get("seed", 0))
        self._rng = random.Random(self._seed)
        self._pop_size = int(config.get("population", 16))
        self._eval_batch = int(config.get("eval_batch", 4))
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
        self._queries = 0
        self._episodes = 0

    def bind_runtime(
        self,
        *,
        broker: Any | None = None,
        env: Any | None = None,
        learning: bool = True,
    ) -> None:
        self._broker = broker
        self._env = env
        self._learning = learning

    def propose(self) -> dict[str, Any]:
        if self._broker is not None and self._env is not None and self._learning:
            self._evaluate_batch_via_broker()
        if self._rng.random() < 0.2 and len(self._population) >= 2:
            a, b = self._rng.sample(self._population, 2)
            child = dict(a)
            for key in b:
                if self._rng.random() < 0.5:
                    child[key] = copy.deepcopy(b[key])
            action = mutate_action(self._rng, child, self._schema)
        else:
            # Prefer higher-fitness parents when available.
            if self._fitness and any(sum(f) != 0 for f in self._fitness):
                ranked = sorted(
                    range(len(self._population)),
                    key=lambda i: sum(self._fitness[i]),
                    reverse=True,
                )
                parent = self._population[ranked[self._idx % min(4, len(ranked))]]
            else:
                parent = self._population[self._idx % len(self._population)]
            action = mutate_action(self._rng, parent, self._schema)
            self._idx += 1
        action["_cohort"] = self.COHORT
        action["_strategy"] = "evolutionary"
        self._last_proposed = {k: v for k, v in action.items() if not str(k).startswith("_")}
        return action

    def _evaluate_batch_via_broker(self) -> None:
        assert self._broker is not None and self._env is not None
        batch = max(1, min(self._eval_batch, len(self._population)))
        for _ in range(batch):
            i = self._rng.randrange(len(self._population))
            cand = self._population[i]
            score, decision = evaluate_candidate_trajectory(
                self._env,
                cand,
                self._broker,
                caller="evolutionary:fitness",
            )
            self._queries += 1
            accepted = getattr(decision, "accepted", None)
            reward = score
            novelty = 1.0 if accepted is True else 0.0
            cost = 1.0
            fit = (reward, novelty, -cost)
            if self._learning:
                self._fitness[i] = fit

    def observe(self, feedback: dict[str, Any]) -> None:
        self._episodes += 1
        if not self._learning:
            return
        reward = float(feedback.get("reward", 0.0))
        novelty = 1.0 if feedback.get("novel") else 0.0
        if feedback.get("verifier_accepted"):
            novelty = max(novelty, 1.0)
            reward = max(reward, 1.0)
        cost = float(feedback.get("cost", 1.0))
        fit = (reward, novelty, -cost)
        individual = dict(getattr(self, "_last_proposed", {"op": "noop"}))
        if len(self._population) < self._pop_size:
            self._population.append(individual)
            self._fitness.append(fit)
            return
        for i, existing in enumerate(self._fitness):
            if _dominates(fit, existing):
                self._population[i] = individual
                self._fitness[i] = fit
                return
        worst = min(range(len(self._fitness)), key=lambda i: sum(self._fitness[i]))
        if sum(fit) > sum(self._fitness[worst]):
            self._population[worst] = individual
            self._fitness[worst] = fit

    def checkpoint(self) -> dict[str, Any]:
        return {
            "schema_version": "1",
            "strategy": "evolutionary",
            "cohort": self.COHORT,
            "seed": self._seed,
            "population": [dict(p) for p in self._population],
            "fitness": [list(f) for f in self._fitness],
            "pop_size": self._pop_size,
            "idx": self._idx,
            "queries": self._queries,
            "episodes": self._episodes,
            "eval_batch": self._eval_batch,
            "rng_state": self._rng.getstate(),
            "schema": self._schema,
        }

    def restore(self, state: dict[str, Any]) -> None:
        self._seed = int(state.get("seed", self._seed))
        self._pop_size = int(state.get("pop_size", self._pop_size))
        self._population = [dict(p) for p in (state.get("population") or [])]
        self._fitness = [
            (float(f[0]), float(f[1]), float(f[2])) for f in (state.get("fitness") or [])
        ]
        while len(self._fitness) < len(self._population):
            self._fitness.append((0.0, 0.0, 0.0))
        self._idx = int(state.get("idx", 0))
        self._queries = int(state.get("queries", 0))
        self._episodes = int(state.get("episodes", 0))
        self._eval_batch = int(state.get("eval_batch", self._eval_batch))
        if "schema" in state:
            self._schema = dict(state["schema"])
        if state.get("rng_state") is not None:
            self._rng.setstate(state["rng_state"])
