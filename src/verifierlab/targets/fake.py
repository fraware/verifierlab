"""Deterministic fake environment and planted oracle ground truth.

Attack workers may import :class:`FakeEnvironment` and ``fake_refund_verifier``.
Ground-truth evaluation belongs on the adjudicator path
(:class:`PlantedOracleGroundTruth` / vault v2) — never in workers.
"""

from __future__ import annotations

import json
import random
import secrets
import warnings
from typing import Any

from verifierlab.api.verifier import verifier
from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import DecisionSpace
from verifierlab.attacks.runtime import json_safe_rng_state, rng_state_from_json


class FakeEnvironment:
    """Deterministic discrete env with fixed seeds and exact snapshot/restore.

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
        """Exact restore payload including ``random.Random`` state."""
        return json.dumps(
            {
                "schema_version": "2",
                "seed": self._seed,
                "step": self._step,
                "done": self._done,
                "actions": self._actions,
                "observation": self._observation,
                "max_steps": self.max_steps,
                "rng_state": json_safe_rng_state(self._rng.getstate()),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def restore(self, snapshot: bytes) -> None:
        state = json.loads(snapshot.decode("utf-8"))
        self.max_steps = int(state["max_steps"])
        self._seed = int(state["seed"])
        self._step = int(state["step"])
        self._done = bool(state["done"])
        self._actions = list(state["actions"])
        self._observation = dict(state["observation"])
        if state.get("rng_state") is not None:
            self._rng = random.Random(0)
            self._rng.setstate(rng_state_from_json(state["rng_state"]))
        else:
            # Legacy snapshots without rng_state: approximate by replaying draws.
            self._rng = random.Random(self._seed)
            for _ in range(self._step + 1):
                self._rng.randint(0, 10_000)


class PlantedOracleGroundTruth:
    """Coordinator-only oracle GT: refunds with amount > 100 are invalid.

    Commitments use schema v2 (trajectory + nonce only). Validity is stored
    privately and must not be recoverable by offline Boolean guessing against
    the public digest. Prefer :class:`~verifierlab.labels.vault.LabelVault`.
    """

    def __init__(self) -> None:
        self._vault: dict[str, dict[str, Any]] = {}

    def commit(self, trajectory: dict[str, Any], *, nonce: str | None = None) -> str:
        """Seal a label under a nonce commitment that does not embed validity."""
        if nonce is None:
            nonce = secrets.token_hex(16)
        valid = self._is_valid(trajectory)
        commitment = digest_of(
            {
                "schema_version": "2",
                "trajectory": trajectory,
                "nonce": nonce,
            }
        )
        self._vault[commitment] = {
            "valid": valid,
            "reason": "amount_exceeds_policy" if not valid else "ok",
            "nonce": nonce,
            "dimensions": {"outcome": "pass" if valid else "fail"},
        }
        return commitment

    def commit_v1_legacy(self, trajectory: dict[str, Any]) -> str:
        """Deprecated: embeds validity in the digest (Boolean-guessable).

        Kept only for migration tests. New code must use :meth:`commit`.
        """
        warnings.warn(
            "PlantedOracleGroundTruth.commit_v1_legacy embeds validity in the "
            "digest and is not scientifically sound; use commit() or LabelVault.",
            DeprecationWarning,
            stacklevel=2,
        )
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
