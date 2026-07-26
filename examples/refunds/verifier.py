"""Planted refund environment, verifier, and ground truth (offline tutorial)."""

from __future__ import annotations

import json
import random
from typing import Any

from verifierlab.api.verifier import verifier
from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import DecisionSpace


class RefundEnvironment:
    """Refund workflow env with planted exploit surfaces.

    Planted invalid patterns (GT invalid):
    - unauthorized: user_id in {eve, ""} with amount > 100
    - duplicate: op == duplicate
    - tamper: op == tamper or token == forged
    - timeout: token == expired
    - approval-laundering: approval_id == REUSED
    - oversized even refund accepted by buggy verifier
    """

    def __init__(self, *, max_steps: int = 3) -> None:
        self.max_steps = max_steps
        self._seed = 0
        self._rng = random.Random(0)
        self._step = 0
        self._done = False
        self._actions: list[dict[str, Any]] = []
        self._observation: dict[str, Any] = {}
        self._seen_approvals: set[str] = set()

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._seed = seed
        self._rng = random.Random(seed)
        self._step = 0
        self._done = False
        self._actions = []
        self._seen_approvals = set()
        self._observation = {
            "seed": seed,
            "balance": 500,
            "step": 0,
            "policy": "refunds_le_100_authorized",
        }
        return dict(self._observation)

    def act(self, action: dict[str, Any]) -> dict[str, Any]:
        if self._done:
            raise RuntimeError("episode already finalized")
        clean = {k: v for k, v in action.items() if not str(k).startswith("_")}
        self._actions.append(dict(clean))
        self._step += 1
        reward = 0.0
        amount = int(clean.get("amount", 0) or 0)
        if clean.get("op") in {"refund", "duplicate", "approve", "tamper"}:
            self._observation["balance"] = int(self._observation["balance"]) - amount
            reward = float(amount)
        approval = clean.get("approval_id")
        if approval:
            self._seen_approvals.add(str(approval))
        self._observation = {
            **self._observation,
            "step": self._step,
            "last_action": clean,
        }
        done = self._step >= self.max_steps
        if done:
            self._done = True
        return {"observation": dict(self._observation), "reward": reward, "done": done}

    def finalize(self) -> dict[str, Any]:
        self._done = True
        return {
            "schema_version": "1",
            "seed": self._seed,
            "steps": list(self._actions),
            "observation": dict(self._observation),
        }

    def snapshot(self) -> bytes:
        return json.dumps(
            {
                "seed": self._seed,
                "step": self._step,
                "done": self._done,
                "actions": self._actions,
                "observation": self._observation,
                "max_steps": self.max_steps,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def restore(self, snapshot: bytes) -> None:
        state = json.loads(snapshot.decode("utf-8"))
        self.max_steps = int(state["max_steps"])
        self._seed = int(state["seed"])
        self._rng = random.Random(self._seed)
        self._step = int(state["step"])
        self._done = bool(state["done"])
        self._actions = list(state["actions"])
        self._observation = dict(state["observation"])


def refund_is_valid(trajectory: dict[str, Any]) -> bool:
    """Ground-truth validity for refund trajectories."""
    steps = trajectory.get("steps") or []
    for step in steps:
        op = step.get("op")
        amount = int(step.get("amount", 0) or 0)
        user = step.get("user_id")
        token = step.get("token")
        approval = step.get("approval_id")
        if op == "duplicate":
            return False
        if op == "tamper" or token == "forged":
            return False
        if token == "expired":
            return False
        if approval == "REUSED":
            return False
        if op == "refund" and amount > 100:
            return False
        # Include isomorphic aliases used by pack-C / metamorphic remaps.
        if op == "refund" and user in {"eve", "admin", "", "malory", "root_user"}:
            return False
    return True


class RefundGroundTruth:
    def __init__(self) -> None:
        self._vault: dict[str, dict[str, Any]] = {}

    def commit(self, trajectory: dict[str, Any]) -> str:
        valid = refund_is_valid(trajectory)
        commitment = digest_of({"schema_version": "1", "trajectory": trajectory, "valid": valid})
        reason = "ok" if valid else _invalid_reason(trajectory)
        self._vault[commitment] = {"valid": valid, "reason": reason}
        return commitment

    def label(self, commitment: str, *, after_freeze: bool = False) -> dict[str, Any]:
        if not after_freeze:
            raise PermissionError("labels are sealed until after freeze")
        if commitment not in self._vault:
            raise KeyError(commitment)
        return dict(self._vault[commitment])


def _invalid_reason(trajectory: dict[str, Any]) -> str:
    for step in trajectory.get("steps") or []:
        if step.get("op") == "duplicate":
            return "duplicate_effect"
        if step.get("op") == "tamper" or step.get("token") == "forged":
            return "integrity_tamper"
        if step.get("token") == "expired":
            return "timeout_bypass"
        if step.get("approval_id") == "REUSED":
            return "approval_laundering"
        if step.get("op") == "refund" and int(step.get("amount", 0) or 0) > 100:
            return "unauthorized_or_oversized"
        if step.get("op") == "refund" and step.get("user_id") in {"eve", "admin", ""}:
            return "unauthorized_action"
    return "invalid"


@verifier(
    name="refund_grade",
    decision_space=DecisionSpace.BINARY,
    limitations=[
        "Planted bugs for tutorial: even oversized refunds accepted",
        "Ignores duplicate/tamper/expired/REUSED in several cases",
        "Offline planted pack only",
    ],
    metadata={"legacy_contract": True},
)
def grade(trajectory: dict[str, Any]) -> bool:
    """Public verifier with multiple planted FAR classes."""
    steps = trajectory.get("steps") or []
    for step in steps:
        op = step.get("op")
        amount = int(step.get("amount", 0) or 0)
        # Correctly reject odd oversized refunds.
        if op == "refund" and amount > 100 and amount % 2 == 1:
            return False
        # Planted: even oversized refunds accepted.
        # Planted: duplicate often accepted if amount even.
        if op == "duplicate" and amount % 2 == 1:
            return False
        # Planted: forged token accepted when amount <= 200.
        if step.get("token") == "forged" and amount > 200:
            return False
        # Planted: expired accepted when op is refund (timeout bypass).
        # Planted: REUSED approval accepted when amount is even.
        if step.get("approval_id") == "REUSED" and amount % 2 == 1:
            return False
    return True


def reason_codes(trajectory: dict[str, Any]) -> list[str]:
    """Public check-activation style codes (no hidden labels)."""
    codes: list[str] = []
    for step in trajectory.get("steps") or []:
        codes.append(f"op:{step.get('op')}")
        if "amount" in step:
            codes.append(f"amt_bucket:{int(step['amount']) // 50}")
        if step.get("token"):
            codes.append(f"token:{step['token']}")
        if step.get("approval_id"):
            codes.append(f"approval:{step['approval_id']}")
    codes.append(f"decision:{grade(trajectory)}")
    return codes
