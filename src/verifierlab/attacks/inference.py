"""Inference-time search: best-of-N and beam with real broker candidate queries."""

from __future__ import annotations

import heapq
import random
from typing import Any

from verifierlab.attacks.fuzzing import DEFAULT_SCHEMA, mutate_action
from verifierlab.attacks.registry import register
from verifierlab.attacks.runtime import evaluate_candidate_trajectory


@register("best_of_n")
class BestOfNSearch:
    """Evaluate N candidates via broker.query; retain the best by public score."""

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
        self._episodes = 0
        self._broker: Any | None = None
        self._env: Any | None = None
        self._learning = True
        self._seed_actions: list[dict[str, Any]] = []

    def initialize(self, config: dict[str, Any]) -> None:
        self._seed = int(config.get("seed", 0))
        self._rng = random.Random(self._seed)
        self._n = int(config.get("n", 8))
        if "schema" in config:
            self._schema = dict(config["schema"])
        self._seed_actions = list(
            config.get("seeds", [{"op": "refund", "amount": 50}, {"op": "refund", "amount": 120}])
        )
        self._queue = []
        for _ in range(self._n):
            base = self._rng.choice(self._seed_actions)
            self._queue.append(mutate_action(self._rng, base, self._schema))
        self._best = None
        self._best_score = float("-inf")
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
        # Candidate-level broker search when runtime is bound.
        if self._broker is not None and self._env is not None:
            return self._propose_with_broker()
        # Brokerless path is for unit tests only — does NOT count verifier queries.
        if not self._queue:
            base = self._best or {"op": "refund", "amount": 100}
            self._queue.append(mutate_action(self._rng, base, self._schema))
        action = self._queue.pop(0)
        action = dict(action)
        action["_cohort"] = self.COHORT
        action["_strategy"] = "best_of_n"
        self._last = {k: v for k, v in action.items() if not str(k).startswith("_")}
        return action

    def _propose_with_broker(self) -> dict[str, Any]:
        assert self._broker is not None and self._env is not None
        candidates: list[dict[str, Any]] = []
        for _ in range(self._n):
            base = self._best or self._rng.choice(self._seed_actions)
            candidates.append(mutate_action(self._rng, base, self._schema))
        best_action = candidates[0]
        best_score = float("-inf")
        for cand in candidates:
            score, _decision = evaluate_candidate_trajectory(
                self._env,
                cand,
                self._broker,
                caller="best_of_n:candidate",
            )
            self._queries += 1
            if score > best_score:
                best_score = score
                best_action = cand
        if self._learning and best_score > self._best_score:
            self._best_score = best_score
            self._best = {k: v for k, v in best_action.items() if not str(k).startswith("_")}
        action = dict(best_action)
        action["_cohort"] = self.COHORT
        action["_strategy"] = "best_of_n"
        self._last = {k: v for k, v in action.items() if not str(k).startswith("_")}
        return action

    def observe(self, feedback: dict[str, Any]) -> None:
        self._episodes += 1
        if not self._learning:
            return
        score = float(feedback.get("score", 0.0))
        if feedback.get("verifier_accepted"):
            score += 1.0
        score += float(feedback.get("reward", 0.0)) * 0.01
        if score > self._best_score:
            self._best_score = score
            self._best = dict(getattr(self, "_last", {"op": "noop"}))
            for _ in range(max(1, self._n // 2)):
                self._queue.append(mutate_action(self._rng, self._best, self._schema))

    def checkpoint(self) -> dict[str, Any]:
        return {
            "schema_version": "1",
            "strategy": "best_of_n",
            "cohort": self.COHORT,
            "seed": self._seed,
            "n": self._n,
            "queries": self._queries,
            "best_score": self._best_score,
            "best": self._best,
            "queue": list(self._queue),
            "episodes": self._episodes,
            "rng_state": self._rng.getstate(),
            "schema": self._schema,
            "seed_actions": self._seed_actions,
        }

    def restore(self, state: dict[str, Any]) -> None:
        self._seed = int(state.get("seed", self._seed))
        self._n = int(state.get("n", self._n))
        self._queries = int(state.get("queries", 0))
        self._best_score = float(state.get("best_score", float("-inf")))
        self._best = dict(state["best"]) if state.get("best") else None
        self._queue = [dict(a) for a in (state.get("queue") or [])]
        self._episodes = int(state.get("episodes", 0))
        if "schema" in state:
            self._schema = dict(state["schema"])
        if state.get("seed_actions"):
            self._seed_actions = [dict(a) for a in state["seed_actions"]]
        if state.get("rng_state") is not None:
            self._rng.setstate(state["rng_state"])


@register("beam")
class BeamSearch:
    """Keep a beam of high-scoring actions; expand via broker candidate queries."""

    COHORT = "optimized"

    def __init__(self) -> None:
        self._rng = random.Random(0)
        self._schema = dict(DEFAULT_SCHEMA)
        self._beam_width = 4
        self._seed = 0
        self._beam: list[tuple[float, int, dict[str, Any]]] = []
        self._counter = 0
        self._queries = 0
        self._episodes = 0
        self._broker: Any | None = None
        self._env: Any | None = None
        self._learning = True

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
        if self._broker is not None and self._env is not None:
            return self._propose_with_broker()
        # Brokerless path does not meter verifier queries.
        if not self._beam:
            action = mutate_action(self._rng, {"op": "refund", "amount": 100}, self._schema)
        else:
            _score, _c, parent = self._rng.choice(self._beam)
            action = mutate_action(self._rng, parent, self._schema)
        action["_cohort"] = self.COHORT
        action["_strategy"] = "beam"
        self._last = {k: v for k, v in action.items() if not str(k).startswith("_")}
        return action

    def _propose_with_broker(self) -> dict[str, Any]:
        assert self._broker is not None and self._env is not None
        width = max(1, self._beam_width)
        parents = (
            [item[2] for item in self._beam] if self._beam else [{"op": "refund", "amount": 100}]
        )
        candidates: list[dict[str, Any]] = []
        for _ in range(width):
            parent = self._rng.choice(parents)
            candidates.append(mutate_action(self._rng, parent, self._schema))
        best_action = candidates[0]
        best_score = float("-inf")
        for cand in candidates:
            score, _decision = evaluate_candidate_trajectory(
                self._env,
                cand,
                self._broker,
                caller="beam:candidate",
            )
            self._queries += 1
            if self._learning:
                heapq.heappush(self._beam, (-score, self._counter, dict(cand)))
                self._counter += 1
            if score > best_score:
                best_score = score
                best_action = cand
        while self._learning and len(self._beam) > self._beam_width:
            heapq.heappop(self._beam)
        action = dict(best_action)
        action["_cohort"] = self.COHORT
        action["_strategy"] = "beam"
        self._last = {k: v for k, v in action.items() if not str(k).startswith("_")}
        return action

    def observe(self, feedback: dict[str, Any]) -> None:
        self._episodes += 1
        if not self._learning:
            return
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
            "schema_version": "1",
            "strategy": "beam",
            "cohort": self.COHORT,
            "seed": self._seed,
            "beam_width": self._beam_width,
            "queries": self._queries,
            "episodes": self._episodes,
            "counter": self._counter,
            "beam": [(s, c, a) for s, c, a in self._beam],
            "rng_state": self._rng.getstate(),
            "schema": self._schema,
        }

    def restore(self, state: dict[str, Any]) -> None:
        self._seed = int(state.get("seed", self._seed))
        self._beam_width = int(state.get("beam_width", self._beam_width))
        self._queries = int(state.get("queries", 0))
        self._episodes = int(state.get("episodes", 0))
        self._counter = int(state.get("counter", 0))
        self._beam = []
        for item in state.get("beam") or []:
            score, counter, action = item
            heapq.heappush(self._beam, (float(score), int(counter), dict(action)))
        if "schema" in state:
            self._schema = dict(state["schema"])
        if state.get("rng_state") is not None:
            self._rng.setstate(state["rng_state"])
