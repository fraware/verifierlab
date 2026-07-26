"""External trainer adapter (VALAB-09): broker-only feedback for trainer loops.

Wraps a callback / trainer step loop that may only observe
:class:`~verifierlab.verifiers.broker.VerifierBroker` feedback — never ground
truth, vault labels, or verifier source unless the access model grants it.

Install optional heavy trainers via ``pip install 'verifierlab[rl]'`` (or
``[trainer]``); this module itself is base-install and uses only broker APIs.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from verifierlab.api.decision import Decision
from verifierlab.artifacts.canonical import digest_of
from verifierlab.verifiers.broker import VerifierBroker


@dataclass
class TrainerStepResult:
    """One trainer step outcome under broker metering."""

    step: int
    action: dict[str, Any]
    decision: Decision
    score: float | None
    query_id: str | None = None


@dataclass
class TrainerAdapter:
    """Thin trainer loop that only sees broker feedback (VALAB-09 #6).

    ``propose`` returns an action dict; ``on_feedback`` may update trainer state
    from the public Decision (capability-filtered by the broker).
    """

    name: str = "trainer"
    broker: VerifierBroker | None = None
    propose: Callable[[int, dict[str, Any]], dict[str, Any]] | None = None
    on_feedback: Callable[[int, Decision, dict[str, Any]], None] | None = None
    build_trajectory: Callable[[Sequence[dict[str, Any]]], dict[str, Any]] | None = None
    history: list[TrainerStepResult] = field(default_factory=list)
    _state: dict[str, Any] = field(default_factory=dict)

    def capture_config(self) -> dict[str, Any]:
        access = self.broker.access_model if self.broker else "unbound"
        return {
            "framework": "trainer",
            "version": "1",
            "adapter": self.name,
            "access_model": access,
            "profile_digest": self.broker.profile_digest if self.broker else None,
            "capabilities": (
                self.broker.capabilities.as_dict()
                if self.broker and self.broker.capabilities
                else {}
            ),
        }

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._state = {"seed": seed, "steps": []}
        self.history.clear()
        if self.broker is not None:
            self.broker.clear_episode_state()
        return dict(self._state)

    def step(self, action: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run one trainer step: propose (optional) → broker.query → feedback."""
        if self.broker is None:
            raise RuntimeError("TrainerAdapter requires a bound VerifierBroker")
        step_i = len(self.history)
        if action is None:
            if self.propose is None:
                raise RuntimeError("no action provided and propose callback unset")
            action = self.propose(step_i, dict(self._state))
        clean = {k: v for k, v in action.items() if not str(k).startswith("_")}
        steps = list(self._state.get("steps") or [])
        steps.append(clean)
        self._state["steps"] = steps
        if self.build_trajectory is not None:
            traj = self.build_trajectory(steps)
        else:
            traj = {"schema_version": "1", "steps": list(steps), "seed": self._state.get("seed")}
        decision = self.broker.query(traj, caller=f"trainer:{self.name}")
        if self.on_feedback is not None:
            self.on_feedback(step_i, decision, dict(self._state))
        query_id = self.broker.events[-1].query_id if self.broker.events else None
        result = TrainerStepResult(
            step=step_i,
            action=clean,
            decision=decision,
            score=decision.score,
            query_id=query_id,
        )
        self.history.append(result)
        return {
            "step": step_i,
            "action": clean,
            "accepted": decision.accepted,
            "score": decision.score,
            "status": decision.status,
            "reason_codes": list(decision.reason_codes),
            "query_id": query_id,
            "reward": float(decision.score or 0.0),
            "resources": {"broker_queries": 1},
        }

    def finalize(self) -> dict[str, Any]:
        steps = list(self._state.get("steps") or [])
        traj = (
            self.build_trajectory(steps)
            if self.build_trajectory is not None
            else {"schema_version": "1", "steps": steps, "seed": self._state.get("seed")}
        )
        if "steps" not in traj:
            traj = {**traj, "steps": steps}
        return {
            "schema_version": "1",
            "framework": "trainer",
            "steps": list(traj.get("steps") or steps),
            "trajectory": traj,
            "trajectory_digest": digest_of(traj),
            "n_steps": len(self.history),
            "query_count": len(self.broker.events) if self.broker else 0,
            "history": [
                {
                    "step": h.step,
                    "action": h.action,
                    "accepted": h.decision.accepted,
                    "score": h.score,
                    "status": h.decision.status,
                    "query_id": h.query_id,
                }
                for h in self.history
            ],
        }

    def map_timeout(self, exc: Exception) -> dict[str, Any]:
        return {"status": "timeout", "error": str(exc), "framework": "trainer"}


def run_trainer_loop(
    broker: VerifierBroker,
    *,
    steps: int,
    seed: int = 0,
    propose: Callable[[int, dict[str, Any]], dict[str, Any]] | None = None,
    on_feedback: Callable[[int, Decision, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Convenience: bind broker and run ``steps`` trainer iterations."""

    def _default_propose(i: int, state: dict[str, Any]) -> dict[str, Any]:
        return {"op": "refund", "amount": 50 + (i * 10) + int(state.get("seed") or 0) % 7}

    adapter = TrainerAdapter(
        broker=broker,
        propose=propose or _default_propose,
        on_feedback=on_feedback,
    )
    adapter.reset(seed=seed)
    for _ in range(steps):
        adapter.step()
    return adapter.finalize()
