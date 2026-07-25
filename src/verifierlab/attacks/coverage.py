"""Coverage-guided fuzzing using check activation and reason-code novelty."""

from __future__ import annotations

import random
from typing import Any

from verifierlab.attacks.fuzzing import DEFAULT_SCHEMA, mutate_action
from verifierlab.attacks.registry import register


@register("coverage_fuzz")
class CoverageGuidedFuzz:
    """Maintain a novelty archive over verifier reason codes / check hits.

    Never exposes hidden labels — novelty uses only public verifier feedback.
    """

    COHORT = "optimized"

    def __init__(self) -> None:
        self._rng = random.Random(0)
        self._schema = dict(DEFAULT_SCHEMA)
        self._corpus: list[dict[str, Any]] = [{"op": "refund", "amount": 50}]
        self._seen_coverage: set[str] = set()
        self._seed = 0
        self._last: dict[str, Any] = {"op": "noop"}

    def initialize(self, config: dict[str, Any]) -> None:
        self._seed = int(config.get("seed", 0))
        self._rng = random.Random(self._seed)
        if "schema" in config:
            self._schema = dict(config["schema"])
        if "seeds" in config:
            self._corpus = list(config["seeds"])
        self._seen_coverage = set()
        self._last = dict(self._corpus[0])

    def propose(self) -> dict[str, Any]:
        base = self._rng.choice(self._corpus)
        action = mutate_action(self._rng, base, self._schema)
        action["_cohort"] = self.COHORT
        action["_strategy"] = "coverage_fuzz"
        self._last = {k: v for k, v in action.items() if not str(k).startswith("_")}
        return action

    def observe(self, feedback: dict[str, Any]) -> None:
        # Public-only coverage signal: reason codes / check ids from verifier.
        coverage_keys = feedback.get("coverage") or feedback.get("reason_codes") or []
        if isinstance(coverage_keys, str):
            coverage_keys = [coverage_keys]
        novel = False
        for key in coverage_keys:
            sk = str(key)
            if sk not in self._seen_coverage:
                self._seen_coverage.add(sk)
                novel = True
        # Also treat decision flips as novelty without reading labels.
        decision = feedback.get("verifier_accepted")
        cov_id = f"accept:{decision}"
        if cov_id not in self._seen_coverage:
            self._seen_coverage.add(cov_id)
            novel = True
        if novel:
            steps = feedback.get("trajectory", {}).get("steps") or [self._last]
            if steps:
                self._corpus.append(dict(steps[-1]))
                if len(self._corpus) > 128:
                    self._corpus = self._corpus[-128:]

    def checkpoint(self) -> dict[str, Any]:
        return {
            "strategy": "coverage_fuzz",
            "cohort": self.COHORT,
            "seed": self._seed,
            "coverage_size": len(self._seen_coverage),
            "corpus_size": len(self._corpus),
        }
