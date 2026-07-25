"""Public decision types for verifier outputs."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DecisionKind(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    ABSTAIN = "abstain"
    SCORE = "score"


class Decision(BaseModel):
    """Normalized verifier decision."""

    model_config = ConfigDict(extra="forbid")

    kind: DecisionKind
    accepted: bool | None = None
    score: float | None = None
    label: str | None = None
    reason_codes: list[str] = Field(default_factory=list)
    raw: Any = None

    @classmethod
    def from_bool(cls, accepted: bool, *, reason_codes: list[str] | None = None) -> Decision:
        return cls(
            kind=DecisionKind.ACCEPT if accepted else DecisionKind.REJECT,
            accepted=accepted,
            reason_codes=reason_codes or [],
        )

    @classmethod
    def from_raw(cls, value: Any) -> Decision:
        if isinstance(value, Decision):
            return value
        if isinstance(value, bool):
            return cls.from_bool(value)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return cls(kind=DecisionKind.SCORE, score=float(value), accepted=float(value) >= 0.5)
        if isinstance(value, dict):
            accepted = value.get("accepted")
            if accepted is None and "decision" in value:
                accepted = bool(value["decision"])
            kind_raw = value.get("kind")
            kind = DecisionKind(kind_raw) if kind_raw else (
                DecisionKind.ACCEPT if accepted else DecisionKind.REJECT
            )
            return cls(
                kind=kind,
                accepted=accepted if isinstance(accepted, bool) else None,
                score=value.get("score"),
                label=value.get("label"),
                reason_codes=list(value.get("reason_codes") or []),
                raw=value,
            )
        return cls(kind=DecisionKind.SCORE, raw=value)
