"""Tiny native environment for Example V1."""

from __future__ import annotations

import json
from typing import Any


class TinyNativeEnv:
    def __init__(self, *, max_steps: int = 3) -> None:
        self.max_steps = max_steps
        self._seed = 0
        self._step = 0
        self._done = False
        self._actions: list[dict[str, Any]] = []
        self._observation: dict[str, Any] = {}

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._seed = seed
        self._step = 0
        self._done = False
        self._actions = []
        self._observation = {"seed": seed, "balance": 500, "step": 0}
        return dict(self._observation)

    def act(self, action: dict[str, Any]) -> dict[str, Any]:
        if self._done:
            raise RuntimeError("episode already finished")
        clean = {k: v for k, v in action.items() if not str(k).startswith("_")}
        self._actions.append(dict(clean))
        self._step += 1
        amount = int(clean.get("amount", 0) or 0)
        if clean.get("op") == "refund":
            self._observation["balance"] = int(self._observation["balance"]) - amount
        self._observation = {**self._observation, "step": self._step, "last_action": clean}
        self._done = self._step >= self.max_steps
        return {"observation": dict(self._observation), "reward": float(amount), "done": self._done}

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
        self._seed = int(state["seed"])
        self._step = int(state["step"])
        self._done = bool(state["done"])
        self._actions = list(state["actions"])
        self._observation = dict(state["observation"])
        self.max_steps = int(state["max_steps"])
