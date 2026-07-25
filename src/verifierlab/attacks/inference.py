"""Inference-time search: best-of-N and beam search with query accounting."""

from __future__ import annotations

import heapq
import random
from typing import Any

from verifierlab.attacks.fuzzing import DEFAULT_SCHEMA, mutate_action
from verifierlab.attacks.registry import register


@register("best_of_n")
class BestOfNSearch:
    """Propose N candidates; retain the best by public verifier score."""

    COHORT = "optimized"

    def __init__(self) -> None:
        self._rng = random.Random(0)
        self._schema = dict(DEFAULT_SCHEMA)
        self._n = 8
        self._seed = 0
        self._queue: list[dict[str, Any]] = []
        self._best: dict[str, Any] | None = None
        self._best_score = float("-inf")
        self._queries = 0

    def initialize(self, config: dict[str, Any]) -> None:
        self._seed = int(config.get("seed", 0))
        self._rng = random.Random(self._seed)
        self._n = int(config.get("n", 8))
        if "schema" in config:
            self._schema = dict(config["schema"])
        seed_actions = list(
            config.get("seeds", [{"op": "refund", "amount": 50}, {"op": "refund", "amount": 120}])
        )
        self._queue = []
        for _ in range(self._n):
            base = self._rng.choice(seed_actions)
            self._queue.append(mutate_action(self._rng, base, self._schema))
        self._best = None
        self._best_score = float("-inf")
        self._queries = 0

    def propose(self) -> dict[str, Any]:
        if not self._queue:
            base = self._best or {"op": "refund", "amount": 100}
            self._queue.append(mutate_action(self._rng, base, self._schema))
        action = self._queue.pop(0)
        action = dict(action)
        action["_cohort"] = self.COHORT
        action["_strategy"] = "best_of_n"
        self._queries += 1
        self._last = {k: v for k, v in action.items() if not str(k).startswith("_")}
        return action

    def observe(self, feedback: dict[str, Any]) -> None:
        score = float(feedback.get("score", 0.0))
        if feedback.get("verifier_accepted"):
            score += 1.0
        score += float(feedback.get("reward", 0.0)) * 0.01
        if score > self._best_score:
            self._best_score = score
            self._best = dict(getattr(self, "_last", {"op": "noop"}))
            # Expand around best.
            for _ in range(max(1, self._n // 2)):
                self._queue.append(mutate_action(self._rng, self._best, self._schema))

    def checkpoint(self) -> dict[str, Any]:
        return {
            "strategy": "best_of_n",
            "cohort": self.COHORT,
            "seed": self._seed,
            "queries": self._queries,
            "best_score": self._best_score,
        }


@register("beam")
class BeamSearch:
    """Keep a beam of high-scoring partial action sequences."""

    COHORT = "optimized"

    def __init__(self) -> None:
        self._rng = random.Random(0)
        self._schema = dict(DEFAULT_SCHEMA)
        self._beam_width = 4
        self._seed = 0
        # heap of (-score, counter, action)
        self._beam: list[tuple[float, int, dict[str, Any]]] = []
        self._counter = 0
        self._queries = 0

    def initialize(self, config: dict[str, Any]) -> None:
        self._seed = int(config.get("seed", 0))
        self._rng = random.Random(self._seed)
        self._beam_width = int(config.get("beam_width", 4))
        if "schema" in config:
            self._schema = dict(config["schema"])
        seeds = list(config.get("seeds", [{"op": "refund", "amount": 80}]))
        self._beam = []
        self._counter = 0
        for s in seeds:
            heapq.heappush(self._beam, (0.0, self._counter, dict(s)))
            self._counter += 1
        self._queries = 0

    def propose(self) -> dict[str, Any]:
        if not self._beam:
            action = mutate_action(self._rng, {"op": "refund", "amount": 100}, self._schema)
        else:
            _score, _c, parent = self._rng.choice(self._beam)
            action = mutate_action(self._rng, parent, self._schema)
        action["_cohort"] = self.COHORT
        action["_strategy"] = "beam"
        self._queries += 1
        self._last = {k: v for k, v in action.items() if not str(k).startswith("_")}
        return action

    def observe(self, feedback: dict[str, Any]) -> None:
        score = float(feedback.get("score", 0.0))
        if feedback.get("verifier_accepted"):
            score += 1.0 + float(feedback.get("reward", 0.0)) * 0.01
        action = dict(getattr(self, "_last", {"op": "noop"}))
        heapq.heappush(self._beam, (-score, self._counter, action))
        self._counter += 1
        while len(self._beam) > self._beam_width:
            heapq.heappop(self._beam)

    def checkpoint(self) -> dict[str, Any]:
        return {
            "strategy": "beam",
            "cohort": self.COHORT,
            "seed": self._seed,
            "beam_width": self._beam_width,
            "queries": self._queries,
        }
