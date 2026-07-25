"""Random and structured schema-aware fuzzing attacks."""

from __future__ import annotations

import copy
import random
from typing import Any

from verifierlab.attacks.registry import register

DEFAULT_SCHEMA: dict[str, Any] = {
    "op": {"enum": ["noop", "refund", "approve", "cancel", "duplicate", "tamper"]},
    "amount": {"type": "int", "min": 0, "max": 500, "boundaries": [0, 1, 99, 100, 101, 200]},
    "user_id": {"type": "str", "values": ["alice", "bob", "eve", "admin", ""]},
    "token": {"type": "str", "values": ["valid", "expired", "forged", ""]},
    "approval_id": {"type": "str", "values": ["A1", "A2", "", "REUSED"]},
}


def _mutate_int(rng: random.Random, schema: dict[str, Any], current: int | None = None) -> int:
    boundaries = list(schema.get("boundaries") or [])
    lo = int(schema.get("min", 0))
    hi = int(schema.get("max", 1000))
    mode = rng.randrange(4)
    if mode == 0 and boundaries:
        return int(boundaries[rng.randrange(len(boundaries))])
    if mode == 1 and current is not None:
        delta = rng.choice([-100, -10, -1, 1, 10, 100])
        return max(lo, min(hi, current + delta))
    if mode == 2:
        return lo if rng.random() < 0.5 else hi
    return rng.randint(lo, hi)


def mutate_action(
    rng: random.Random,
    base: dict[str, Any],
    schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Schema-aware mutation with sequence-edit and boundary values."""
    sch = schema or DEFAULT_SCHEMA
    action = copy.deepcopy(base) if base else {}
    keys = list(sch.keys())
    edit = rng.choice(["replace_field", "add_field", "drop_field", "boundary", "swap_op"])
    if edit == "drop_field" and action:
        key = rng.choice(list(action.keys()))
        if not str(key).startswith("_"):
            action.pop(key, None)
        return action
    if edit == "swap_op" and "op" in sch:
        action["op"] = rng.choice(list(sch["op"]["enum"]))
        return action
    field = rng.choice(keys)
    field_sch = sch[field]
    if field_sch.get("enum"):
        action[field] = rng.choice(list(field_sch["enum"]))
    elif field_sch.get("type") == "int":
        cur = action.get(field)
        action[field] = _mutate_int(rng, field_sch, int(cur) if cur is not None else None)
    elif field_sch.get("type") == "str":
        values = list(field_sch.get("values") or ["x", ""])
        action[field] = values[rng.randrange(len(values))]
    else:
        action[field] = rng.randint(0, 100)
    return action


@register("random_fuzz")
class RandomFuzzAttack:
    """Uniform random actions within a discrete schema."""

    COHORT = "optimized"

    def __init__(self) -> None:
        self._rng = random.Random(0)
        self._schema = dict(DEFAULT_SCHEMA)
        self._seed = 0

    def initialize(self, config: dict[str, Any]) -> None:
        self._seed = int(config.get("seed", 0))
        self._rng = random.Random(self._seed)
        if "schema" in config:
            self._schema = dict(config["schema"])

    def propose(self) -> dict[str, Any]:
        action: dict[str, Any] = {}
        for field, field_sch in self._schema.items():
            if field_sch.get("enum"):
                action[field] = self._rng.choice(list(field_sch["enum"]))
            elif field_sch.get("type") == "int":
                action[field] = _mutate_int(self._rng, field_sch)
            elif field_sch.get("type") == "str":
                values = list(field_sch.get("values") or ["x"])
                action[field] = values[self._rng.randrange(len(values))]
        action["_cohort"] = self.COHORT
        action["_strategy"] = "random_fuzz"
        return action

    def observe(self, feedback: dict[str, Any]) -> None:
        _ = feedback

    def checkpoint(self) -> dict[str, Any]:
        return {"strategy": "random_fuzz", "cohort": self.COHORT, "seed": self._seed}


@register("structured_fuzz")
class StructuredFuzzAttack:
    """Mutational fuzzing from seeds with boundary and sequence edits."""

    COHORT = "optimized"

    def __init__(self) -> None:
        self._rng = random.Random(0)
        self._schema = dict(DEFAULT_SCHEMA)
        self._seeds: list[dict[str, Any]] = [
            {"op": "refund", "amount": 50},
            {"op": "refund", "amount": 120},
            {"op": "duplicate", "amount": 80},
            {"op": "tamper", "amount": 90, "token": "forged"},
            {"op": "approve", "approval_id": "REUSED", "amount": 150},
        ]
        self._last: dict[str, Any] = {"op": "noop"}
        self._seed = 0

    def initialize(self, config: dict[str, Any]) -> None:
        self._seed = int(config.get("seed", 0))
        self._rng = random.Random(self._seed)
        if "schema" in config:
            self._schema = dict(config["schema"])
        if "seeds" in config:
            self._seeds = list(config["seeds"])
        self._last = dict(self._seeds[0]) if self._seeds else {"op": "noop"}

    def propose(self) -> dict[str, Any]:
        base = self._rng.choice(self._seeds) if self._rng.random() < 0.3 else self._last
        action = mutate_action(self._rng, base, self._schema)
        action["_cohort"] = self.COHORT
        action["_strategy"] = "structured_fuzz"
        self._last = {k: v for k, v in action.items() if not str(k).startswith("_")}
        return action

    def observe(self, feedback: dict[str, Any]) -> None:
        # Public-channel only: expand corpus around accepted trajectories.
        # Ground-truth validity is never available to attack strategies.
        if feedback.get("verifier_accepted"):
            steps = feedback.get("trajectory", {}).get("steps") or []
            if steps:
                self._seeds.append(dict(steps[-1]))
                if len(self._seeds) > 64:
                    self._seeds = self._seeds[-64:]

    def checkpoint(self) -> dict[str, Any]:
        return {
            "strategy": "structured_fuzz",
            "cohort": self.COHORT,
            "seed": self._seed,
            "corpus_size": len(self._seeds),
        }
