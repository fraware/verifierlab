"""Deterministic fake environment and planted oracle ground truth."""

from __future__ import annotations

import json
import random
from typing import Any

from verifierlab.api.verifier import verifier
from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import DecisionSpace


class FakeEnvironment:
    """Deterministic discrete env with fixed seeds and snapshot/restore.

    Planted rule: action ``{"op": "refund", "amount": n}`` with ``n > 100``
    is *invalid* for GT but the public verifier incorrectly accepts it when
    ``amount`` is even (planted FAR).
    """

    def __init__(self, *, max_steps: int = 3) -> None:
        self.max_steps = max_steps
        self._seed: int = 0
        self._rng = random.Random(0)
        self._step = 0
        self._done = False
        self._actions: list[dict[str, Any]] = []
        self._observation: dict[str, Any] = {}

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._seed = seed
        self._rng = random.Random(seed)
        self._step = 0
        self._done = False
        self._actions = []
        noise = self._rng.randint(0, 10_000)
        self._observation = {
            "seed": seed,
            "noise": noise,
            "balance": 500,
            "step": 0,
        }
        return dict(self._observation)

    def act(self, action: dict[str, Any]) -> dict[str, Any]:
        if self._done:
            raise RuntimeError("episode already finalized")
        clean = {k: v for k, v in action.items() if not str(k).startswith("_")}
        self._actions.append(dict(clean))
        self._step += 1
        reward = 0.0
        if clean.get("op") == "refund":
            amount = int(clean.get("amount", 0))
            self._observation["balance"] = int(self._observation["balance"]) - amount
            reward = float(amount)
        self._observation = {
            **self._observation,
            "step": self._step,
            "last_action": clean,
        }
        done = self._step >= self.max_steps
        if done:
            self._done = True
        return {
            "observation": dict(self._observation),
            "reward": reward,
            "done": done,
        }

    def finalize(self) -> dict[str, Any]:
        self._done = True
        return {
            "seed": self._seed,
            "steps": list(self._actions),
            "observation": dict(self._observation),
            "schema_version": "1",
        }

    def snapshot(self) -> bytes:
        state = {
            "seed": self._seed,
            "step": self._step,
            "done": self._done,
            "actions": self._actions,
            "observation": self._observation,
            "max_steps": self.max_steps,
            "rng_state": self._rng.getstate(),
        }
        # rng state is not JSON-safe; use a dedicated encoding for restore stubs.
        return json.dumps(
            {
                "seed": state["seed"],
                "step": state["step"],
                "done": state["done"],
                "actions": state["actions"],
                "observation": state["observation"],
                "max_steps": state["max_steps"],
                "rng_seed_drawn": self._seed,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def restore(self, snapshot: bytes) -> None:
        state = json.loads(snapshot.decode("utf-8"))
        self.max_steps = int(state["max_steps"])
        self._seed = int(state["seed"])
        self._rng = random.Random(self._seed)
        # Advance RNG to approximate prior draws (stub fidelity for M0).
        for _ in range(int(state["step"]) + 1):
            self._rng.randint(0, 10_000)
        self._step = int(state["step"])
        self._done = bool(state["done"])
        self._actions = list(state["actions"])
        self._observation = dict(state["observation"])


class PlantedOracleGroundTruth:
    """Oracle GT: refunds with amount > 100 are invalid; others valid."""

    def __init__(self) -> None:
        self._vault: dict[str, dict[str, Any]] = {}

    def commit(self, trajectory: dict[str, Any]) -> str:
        valid = self._is_valid(trajectory)
        commitment = digest_of(
            {
                "schema_version": "1",
                "trajectory": trajectory,
                "valid": valid,
            }
        )
        self._vault[commitment] = {
            "valid": valid,
            "reason": "amount_exceeds_policy" if not valid else "ok",
        }
        return commitment

    def label(self, commitment: str, *, after_freeze: bool = False) -> dict[str, Any]:
        if not after_freeze:
            raise PermissionError("labels are sealed until after freeze")
        if commitment not in self._vault:
            raise KeyError(f"unknown commitment: {commitment}")
        return dict(self._vault[commitment])

    @staticmethod
    def _is_valid(trajectory: dict[str, Any]) -> bool:
        for step in trajectory.get("steps", []):
            if step.get("op") == "refund" and int(step.get("amount", 0)) > 100:
                return False
        return True


@verifier(
    name="fake_refund_verifier",
    decision_space=DecisionSpace.BINARY,
    limitations=[
        "Planted bug: accepts even-valued refunds with amount > 100",
        "For M0 fake campaigns only",
    ],
)
def fake_refund_verifier(trajectory: dict[str, Any]) -> bool:
    """Public verifier with planted FAR on even oversized refunds."""
    for step in trajectory.get("steps", []):
        if step.get("op") != "refund":
            continue
        amount = int(step.get("amount", 0))
        if amount > 100 and amount % 2 == 1:
            return False
        # Planted bug: even amounts > 100 incorrectly accepted.
    return True


def propose_fake_action(seed: int, unit_index: int) -> dict[str, Any]:
    """Deterministic action proposal for the fake campaign baseline."""
    rng = random.Random((seed + 1) * 1_000_003 + unit_index)
    # Mix of valid and planted-invalid even refunds.
    choices = [
        {"op": "noop"},
        {"op": "refund", "amount": 50},
        {"op": "refund", "amount": 120},  # even > 100 → planted FAR
        {"op": "refund", "amount": 121},  # odd > 100 → correctly rejected
        {"op": "refund", "amount": 200},  # even > 100 → planted FAR
    ]
    return choices[rng.randrange(len(choices))]  # type: ignore[return-value]
