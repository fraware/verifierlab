"""Metamorphic search attack family (WP-08).

Proposes trajectories derived from registered metamorphic transforms.
Ground-truth invariance is adjudicated separately; this strategy never treats
``invalid_transform`` as a verifier failure and preserves score-only /
abstention feedback as indeterminate search signal.
"""

from __future__ import annotations

import copy
import random
from typing import Any

from verifierlab.artifacts.canonical import digest_of
from verifierlab.attacks.registry import register
from verifierlab.statistics.metamorphic import (
    DEFAULT_USER_REMAP,
    isomorphic_remap,
    user_alias_transform,
)


def _strip_private(action: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in action.items() if not str(k).startswith("_")}


@register("metamorphic_search")
class MetamorphicSearchAttack:
    """Search for verifier invariance violations under registered transforms.

    Public feedback only. When the adjudicator later marks a pair
    ``invalid_transform``, that outcome must never be counted as attack success
    against the verifier (see metamorphic evaluator).
    """

    COHORT = "optimized"
    name = "metamorphic_search"

    def __init__(self) -> None:
        self._rng = random.Random(0)
        self._seed = 0
        self._seeds: list[dict[str, Any]] = [
            {"op": "refund", "amount": 50, "user_id": "eve"},
            {"op": "refund", "amount": 120, "user_id": "admin"},
            {"op": "duplicate", "amount": 80, "user_id": "alice"},
        ]
        self._user_map = dict(DEFAULT_USER_REMAP)
        self._transform_family = "actor_alias"
        self._queries = 0
        self._last: dict[str, Any] = {"op": "noop"}
        self._archive: list[dict[str, Any]] = []

    def initialize(self, config: dict[str, Any]) -> None:
        self._seed = int(config.get("seed", 0))
        self._rng = random.Random(self._seed)
        if "seeds" in config:
            self._seeds = [dict(s) for s in config["seeds"]]
        if "user_map" in config:
            self._user_map = {str(k): str(v) for k, v in dict(config["user_map"]).items()}
        self._transform_family = str(config.get("transform_family", "actor_alias"))
        self._queries = 0
        self._archive = []
        self._last = dict(self._seeds[0]) if self._seeds else {"op": "noop"}

    def propose(self) -> dict[str, Any]:
        base = self._rng.choice(self._seeds)
        trajectory = {"steps": [copy.deepcopy(base)], "pack_theme": "isomorphic-relabel"}
        if self._transform_family == "actor_alias":
            transformed = user_alias_transform(trajectory, {"user_map": self._user_map})
        else:
            transformed = isomorphic_remap(trajectory, user_map=self._user_map)
        steps = transformed.get("steps") or []
        action = dict(steps[-1]) if steps else dict(base)
        action["_cohort"] = self.COHORT
        action["_strategy"] = "metamorphic_search"
        action["_transform_family"] = self._transform_family
        action["_source_seed_digest"] = digest_of(base)
        self._last = _strip_private(action)
        self._queries += 1
        return action

    def observe(self, feedback: dict[str, Any]) -> None:
        """Update archive from public feedback only.

        ``accepted is None`` / score-only / abstention → indeterminate; do not
        treat as success or failure for corpus expansion.
        """
        accepted = feedback.get("verifier_accepted")
        if accepted is None and feedback.get("accepted") is None:
            # Indeterminate / score-only: keep for exploration but do not crown.
            if feedback.get("score") is not None:
                self._archive.append(
                    {"kind": "indeterminate", "feedback_digest": digest_of(feedback)}
                )
            return
        if accepted is True or feedback.get("verifier_accepted") is True:
            steps = (feedback.get("trajectory") or {}).get("steps") or []
            if steps:
                seed = _strip_private(dict(steps[-1]))
                self._seeds.append(seed)
                if len(self._seeds) > 64:
                    self._seeds = self._seeds[-64:]
            self._archive.append({"kind": "public_accept", "feedback_digest": digest_of(feedback)})

    def checkpoint(self) -> dict[str, Any]:
        return {
            "strategy": "metamorphic_search",
            "cohort": self.COHORT,
            "seed": self._seed,
            "queries": self._queries,
            "corpus_size": len(self._seeds),
            "archive_size": len(self._archive),
            "transform_family": self._transform_family,
        }


__all__ = ["MetamorphicSearchAttack"]
