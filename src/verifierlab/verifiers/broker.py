"""Metered verifier invocation broker (VAL-R02 / VAL-R10 / VAL-R09)."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from verifierlab.api.decision import Decision
from verifierlab.api.verifier import normalize_decision
from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import AccessModel
from verifierlab.budgets.ledger import ProvenanceLedger
from verifierlab.verifiers.capabilities import AccessCapabilities, capabilities_for
from verifierlab.verifiers.profile import VerifierProfile

_KNOWN_ACCESS = frozenset(m.value for m in AccessModel)


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
    decisions.
    """

    profile: VerifierProfile
    verifier: Callable[[dict[str, Any]], Any]
    access_model: str = AccessModel.BLACK_BOX.value
    caller: str = "worker"
    ledger: ProvenanceLedger | None = None
    events: list[QueryEvent] = field(default_factory=list)
    capabilities: AccessCapabilities | None = None

    def __post_init__(self) -> None:
        if self.access_model not in _KNOWN_ACCESS:
            raise ValueError(f"unknown access model: {self.access_model!r}")
        if self.capabilities is None:
            self.capabilities = capabilities_for(self.access_model)

    @property
    def profile_digest(self) -> str:
        return self.profile.content_digest()

    def query(
        self,
        trajectory: dict[str, Any],
        *,
        caller: str | None = None,
        capability: str = "decision",
    ) -> Decision:
        """Invoke the verifier under metering and access control."""
        assert self.capabilities is not None
        self.capabilities.require(capability)
        caller_id = caller or self.caller
        input_digest = digest_of(trajectory)

        if self.ledger is not None:
            # Atomic reserve: budget check happens before the call.
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

        # Capability-gated feedback channels.
        caps = self.capabilities
        filtered_reasons = caps.filter_reason_codes(list(decision.reason_codes))
        updates: dict[str, Any] = {"reason_codes": filtered_reasons}
        if not caps.may_read_score:
            updates["score"] = None
        if self.access_model == AccessModel.BLACK_BOX.value or not caps.may_read_reason_codes:
            updates["components"] = {}
            updates["raw"] = None
        if not caps.may_read_source:
            # Never expose raw source / component dumps under black/gray.
            updates.setdefault("components", {})
            if self.access_model != AccessModel.WHITE_BOX.value:
                updates["components"] = {}
                updates["raw"] = None
        decision = decision.model_copy(update=updates)

        output_digest = digest_of(
            {
                "status": decision.status,
                "accepted": decision.accepted,
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
            accepted=decision.accepted,
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
