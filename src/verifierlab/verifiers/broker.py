"""Metered verifier invocation broker (VAL-R02 / VAL-R10 / VAL-R09 / VALAB-03)."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from verifierlab.api.decision import Decision, DecisionKind
from verifierlab.api.verifier import normalize_decision
from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import AccessModel
from verifierlab.budgets.ledger import ProvenanceLedger
from verifierlab.verifiers.capabilities import AccessCapabilities, AccessDenied, capabilities_for
from verifierlab.verifiers.profile import VerifierProfile

_KNOWN_ACCESS = frozenset(m.value for m in AccessModel)

# Keys / markers that must never enter stateful episode retention (VALAB-03).
_GT_EPISODE_DENY = frozenset(
    {
        "gt_valid",
        "label",
        "hidden_label",
        "gt_label",
        "commitment_label",
        "ground_truth",
        "vault_secret",
        "private_holdout",
    }
)


def _reject_gt_episode_payload(key: str, value: Any) -> None:
    """Raise when stateful retention tries to store ground-truth material."""
    lowered = str(key).lower()
    if lowered in _GT_EPISODE_DENY or lowered.startswith("gt_") or lowered.startswith("label"):
        raise AccessDenied(f"stateful episode state cannot retain GT key {key!r}")
    if isinstance(value, dict):
        for nested_key in value:
            nested = str(nested_key).lower()
            if (
                nested in _GT_EPISODE_DENY
                or nested.startswith("gt_")
                or nested.startswith("hidden_")
            ):
                raise AccessDenied(
                    f"stateful episode state cannot retain GT field {nested_key!r} under {key!r}"
                )


@dataclass
class QueryEvent:
    """One broker-metered verifier query."""

    query_id: str
    input_digest: str
    output_digest: str
    latency_ms: float
    caller: str
    access_model: str
    profile_digest: str
    status: str
    accepted: bool | None


@dataclass
class VerifierBroker:
    """Sole public path for verifier calls during attack / evaluation.

    Enforces access-model **capability objects**, atomically reserves budget
    (when a ledger is attached), records query provenance, and returns typed
    decisions. Verifier invocations are metered as ``ledger.add_queries`` —
    equivalent to the ``max_queries`` budget dimension (VALAB-04).
    """

    profile: VerifierProfile
    verifier: Callable[[dict[str, Any]], Any]
    access_model: str = AccessModel.BLACK_BOX.value
    caller: str = "worker"
    ledger: ProvenanceLedger | None = None
    events: list[QueryEvent] = field(default_factory=list)
    capabilities: AccessCapabilities | None = None
    _episode_state: dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if self.access_model not in _KNOWN_ACCESS:
            raise ValueError(f"unknown access model: {self.access_model!r}")
        if self.capabilities is None:
            self.capabilities = capabilities_for(self.access_model)

    @property
    def profile_digest(self) -> str:
        return self.profile.content_digest()

    def _default_capability(self) -> str:
        """Pick the primary feedback channel for this access model."""
        assert self.capabilities is not None
        if self.capabilities.may_read_decision:
            return "decision"
        if self.capabilities.may_read_score:
            return "score"
        return "decision"

    def query(
        self,
        trajectory: dict[str, Any],
        *,
        caller: str | None = None,
        capability: str | None = None,
    ) -> Decision:
        """Invoke the verifier under metering and access control."""
        assert self.capabilities is not None
        cap = capability or self._default_capability()
        self.capabilities.require(cap)
        caller_id = caller or self.caller
        input_digest = digest_of(trajectory)

        if self.ledger is not None:
            # Atomic reserve: budget check happens before the call.
            # Verifier invocations ≡ queries (VALAB-04).
            self.ledger.add_queries(1)
            self.ledger.sync_wall_time()

        started = time.perf_counter()
        try:
            raw = self.verifier(trajectory)
            decision = normalize_decision(raw)
        except Exception as exc:
            decision = Decision.from_raw(
                {
                    "status": "error",
                    "reason_codes": ["broker_invocation_error", type(exc).__name__],
                    "raw": str(exc),
                }
            )
        latency_ms = (time.perf_counter() - started) * 1000.0
        decision = decision.model_copy(update={"profile_ref": self.profile_digest})

        # Capability-gated feedback channels (VALAB-03).
        caps = self.capabilities
        filtered_reasons = caps.filter_reason_codes(list(decision.reason_codes))
        updates: dict[str, Any] = {"reason_codes": filtered_reasons}
        if not caps.may_read_score:
            updates["score"] = None
        if not caps.may_read_decision:
            # score_only: strip accept/reject hard labels; keep / synthesize score.
            if decision.score is None and decision.accepted is not None:
                updates["score"] = 1.0 if decision.accepted else 0.0
            updates["accepted"] = None
            updates["kind"] = DecisionKind.SCORE
            updates["label"] = None
        if self.access_model == AccessModel.BLACK_BOX.value or not caps.may_read_reason_codes:
            updates["components"] = {}
            updates["raw"] = None
        if not caps.may_read_source:
            updates.setdefault("components", {})
            if self.access_model != AccessModel.WHITE_BOX.value:
                updates["components"] = {}
                updates["raw"] = None
        decision = decision.model_copy(update=updates)

        # Event accepted field mirrors what the caller may observe.
        event_accepted = decision.accepted if caps.may_read_decision else None
        output_digest = digest_of(
            {
                "status": decision.status,
                "accepted": event_accepted,
                "score": decision.score,
                "reason_codes": list(decision.reason_codes),
            }
        )
        event = QueryEvent(
            query_id=f"q-{uuid.uuid4().hex[:16]}",
            input_digest=input_digest,
            output_digest=output_digest,
            latency_ms=latency_ms,
            caller=caller_id,
            access_model=self.access_model,
            profile_digest=self.profile_digest,
            status=decision.status,
            accepted=event_accepted,
        )
        self.events.append(event)
        if self.ledger is not None:
            self.ledger.record_event(
                "verifier_query",
                query_id=event.query_id,
                input_digest=event.input_digest,
                output_digest=event.output_digest,
                latency_ms=event.latency_ms,
                caller=event.caller,
                access_model=event.access_model,
                profile_digest=event.profile_digest,
                status=event.status,
            )
        return decision

    def retain_episode_state(self, key: str, value: Any) -> None:
        """Stateful access: retain attacker-visible episode state (no GT)."""
        assert self.capabilities is not None
        self.capabilities.require("episode_state")
        _reject_gt_episode_payload(key, value)
        self._episode_state[key] = value

    def read_episode_state(self, key: str, default: Any = None) -> Any:
        """Stateful access: read previously retained episode state."""
        assert self.capabilities is not None
        self.capabilities.require("episode_state")
        _reject_gt_episode_payload(key, None)
        return self._episode_state.get(key, default)

    def clear_episode_state(self) -> None:
        """Clear episode state (end of episode)."""
        self._episode_state.clear()

    def profile_mount(self) -> VerifierProfile:
        """Return the immutable profile (white-box / gray-box only)."""
        assert self.capabilities is not None
        self.capabilities.require("profile")
        return self.profile

    def read_source(self) -> dict[str, Any]:
        """White-box only: expose profile implementation digests (not live source)."""
        assert self.capabilities is not None
        self.capabilities.require("source")
        return {
            "name": self.profile.name,
            "implementation_digest": self.profile.implementation_digest,
            "config_digest": self.profile.config_digest,
            "rubric_digest": self.profile.rubric_digest,
            "limitations": list(self.profile.limitations),
        }

    def adaptive_round(self, artifact: dict[str, Any]) -> dict[str, Any]:
        """Adaptive access: accept an explicit prior-round artifact reference."""
        assert self.capabilities is not None
        self.capabilities.require("adaptive")
        return {"accepted": True, "artifact_digest": digest_of(artifact)}

    def transfer_artifact(self, artifact: dict[str, Any]) -> dict[str, Any]:
        """Transfer access: accept an explicit source-campaign artifact."""
        assert self.capabilities is not None
        self.capabilities.require("transfer")
        return {"accepted": True, "artifact_digest": digest_of(artifact)}

    def event_dicts(self) -> list[dict[str, Any]]:
        return [
            {
                "query_id": e.query_id,
                "input_digest": e.input_digest,
                "output_digest": e.output_digest,
                "latency_ms": e.latency_ms,
                "caller": e.caller,
                "access_model": e.access_model,
                "profile_digest": e.profile_digest,
                "status": e.status,
                "accepted": e.accepted,
            }
            for e in self.events
        ]
