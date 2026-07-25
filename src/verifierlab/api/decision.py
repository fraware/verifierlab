"""Public decision types for verifier outputs.

Fail-closed normalization: nonempty strings such as ``\"reject\"`` must never
become acceptance via Python truthiness (``bool(\"reject\") is True``).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field

DecisionStatus = Literal["accept", "reject", "abstain", "indeterminate", "error"]

_ACCEPT_TOKENS = frozenset({"accept", "accepted", "pass", "passed", "true", "yes", "1"})
_REJECT_TOKENS = frozenset({"reject", "rejected", "fail", "failed", "false", "no", "0"})
_ABSTAIN_TOKENS = frozenset({"abstain", "abstention"})
_INDETERMINATE_TOKENS = frozenset({"indeterminate", "undecided", "unknown"})
_ERROR_TOKENS = frozenset({"error", "timeout", "exception"})


class DecisionKind(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    ABSTAIN = "abstain"
    INDETERMINATE = "indeterminate"
    ERROR = "error"
    # Legacy numeric channel; :attr:`Decision.status` maps via ``accepted``.
    SCORE = "score"


def kind_to_accepted(kind: DecisionKind) -> bool | None:
    """Map a closed decision kind to ``True`` / ``False`` / ``None`` (abstain-like)."""
    if kind is DecisionKind.ACCEPT:
        return True
    if kind is DecisionKind.REJECT:
        return False
    return None


def parse_decision_token(value: str) -> DecisionKind | None:
    """Map a string token to a :class:`DecisionKind`, or ``None`` if unknown."""
    token = value.strip().lower()
    if token in _ACCEPT_TOKENS:
        return DecisionKind.ACCEPT
    if token in _REJECT_TOKENS:
        return DecisionKind.REJECT
    if token in _ABSTAIN_TOKENS:
        return DecisionKind.ABSTAIN
    if token in _INDETERMINATE_TOKENS:
        return DecisionKind.INDETERMINATE
    if token in _ERROR_TOKENS:
        return DecisionKind.ERROR
    try:
        return DecisionKind(token)
    except ValueError:
        return None


class Decision(BaseModel):
    """Normalized verifier decision (typed, fail-closed)."""

    model_config = ConfigDict(extra="forbid")

    kind: DecisionKind
    accepted: bool | None = None
    score: float | None = None
    label: str | None = None
    reason_codes: list[str] = Field(default_factory=list)
    components: dict[str, Any] = Field(default_factory=dict)
    raw_output_ref: str | None = None
    profile_ref: str | None = None
    raw: Any = None

    @property
    def status(self) -> DecisionStatus:
        """Closed status set used by the verifier protocol and metrics."""
        if self.kind is DecisionKind.SCORE:
            if self.accepted is True:
                return "accept"
            if self.accepted is False:
                return "reject"
            return "indeterminate"
        return cast(DecisionStatus, self.kind.value)

    @classmethod
    def from_bool(cls, accepted: bool, *, reason_codes: list[str] | None = None) -> Decision:
        return cls(
            kind=DecisionKind.ACCEPT if accepted else DecisionKind.REJECT,
            accepted=accepted,
            reason_codes=reason_codes or [],
        )

    @classmethod
    def from_raw(cls, value: Any) -> Decision:
        """Normalize arbitrary verifier output without truthiness coercion.

        Strings like ``\"reject\"`` / ``\"false\"`` never become accept.
        Unrecognized values become ``error`` / ``indeterminate`` with
        ``accepted=None`` (fail closed).
        """
        if isinstance(value, Decision):
            return value
        if isinstance(value, bool):
            return cls.from_bool(value)
        if isinstance(value, DecisionKind):
            return cls(kind=value, accepted=kind_to_accepted(value), raw=value)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            score = float(value)
            return cls(kind=DecisionKind.SCORE, score=score, accepted=score >= 0.5)
        if isinstance(value, str):
            kind = parse_decision_token(value)
            if kind is None:
                return cls(
                    kind=DecisionKind.ERROR,
                    accepted=None,
                    reason_codes=["unrecognized_decision"],
                    raw=value,
                )
            return cls(kind=kind, accepted=kind_to_accepted(kind), raw=value)
        if isinstance(value, dict):
            return cls._from_mapping(value)
        return cls(
            kind=DecisionKind.ERROR,
            accepted=None,
            reason_codes=["unrecognized_decision_type"],
            raw=value,
        )

    @classmethod
    def _from_mapping(cls, value: dict[str, Any]) -> Decision:
        reason_codes = list(value.get("reason_codes") or [])
        components = (
            dict(value.get("components") or {}) if isinstance(value.get("components"), dict) else {}
        )
        score_raw = value.get("score")
        score = (
            float(score_raw)
            if isinstance(score_raw, (int, float)) and not isinstance(score_raw, bool)
            else None
        )
        label = value.get("label") if isinstance(value.get("label"), str) else None
        raw_output_ref = (
            value.get("raw_output_ref") if isinstance(value.get("raw_output_ref"), str) else None
        )
        profile_ref = (
            value.get("profile_ref") if isinstance(value.get("profile_ref"), str) else None
        )

        def _error(*extra_codes: str) -> Decision:
            return cls(
                kind=DecisionKind.ERROR,
                accepted=None,
                score=score,
                label=label,
                reason_codes=[*reason_codes, *extra_codes],
                components=components,
                raw_output_ref=raw_output_ref,
                profile_ref=profile_ref,
                raw=value,
            )

        kind = _parse_kind_field(value.get("status"), value.get("kind"))
        if kind is False:
            return _error("unrecognized_status" if "status" in value else "unrecognized_kind")

        accepted, accepted_err = _parse_accepted_field(value.get("accepted"))
        if accepted_err:
            return _error(accepted_err)

        if kind is None and "decision" in value:
            kind, accepted, dec_err = _parse_decision_field(value["decision"], accepted)
            if dec_err:
                return _error(dec_err)

        if kind is None:
            if accepted is True:
                kind = DecisionKind.ACCEPT
            elif accepted is False:
                kind = DecisionKind.REJECT
            elif score is not None:
                return cls(
                    kind=DecisionKind.SCORE,
                    accepted=score >= 0.5,
                    score=score,
                    label=label,
                    reason_codes=reason_codes,
                    components=components,
                    raw_output_ref=raw_output_ref,
                    profile_ref=profile_ref,
                    raw=value,
                )
            else:
                kind = DecisionKind.INDETERMINATE
                accepted = None

        if accepted is None:
            accepted = kind_to_accepted(kind)
        else:
            # Accept/reject kinds are authoritative — never keep a conflicting True.
            synced = kind_to_accepted(kind)
            if synced is not None:
                accepted = synced

        return cls(
            kind=kind,
            accepted=accepted,
            score=score,
            label=label,
            reason_codes=reason_codes,
            components=components,
            raw_output_ref=raw_output_ref,
            profile_ref=profile_ref,
            raw=value,
        )


def _parse_kind_field(status_raw: Any, kind_raw: Any) -> DecisionKind | Literal[False] | None:
    """Return a kind, ``None`` if absent, or ``False`` if present but invalid."""
    if status_raw is not None:
        if isinstance(status_raw, DecisionKind):
            return status_raw
        if isinstance(status_raw, str):
            parsed = parse_decision_token(status_raw)
            return parsed if parsed is not None else False
        return False
    if kind_raw is not None:
        if isinstance(kind_raw, DecisionKind):
            return kind_raw
        if isinstance(kind_raw, str):
            try:
                return DecisionKind(kind_raw)
            except ValueError:
                parsed = parse_decision_token(kind_raw)
                return parsed if parsed is not None else False
        return False
    return None


def _parse_accepted_field(accepted_raw: Any) -> tuple[bool | None, str | None]:
    """Parse ``accepted`` without ``bool(str)`` coercion. Error code on failure."""
    if accepted_raw is None:
        return None, None
    if isinstance(accepted_raw, bool):
        return accepted_raw, None
    if isinstance(accepted_raw, str):
        parsed = parse_decision_token(accepted_raw)
        if parsed is DecisionKind.ACCEPT:
            return True, None
        if parsed is DecisionKind.REJECT:
            return False, None
        if parsed in {
            DecisionKind.ABSTAIN,
            DecisionKind.INDETERMINATE,
            DecisionKind.ERROR,
        }:
            return None, None
        return None, "invalid_accepted"
    return None, "invalid_accepted"


def _parse_decision_field(
    decision_field: Any,
    accepted: bool | None,
) -> tuple[DecisionKind | None, bool | None, str | None]:
    """Parse legacy ``decision`` key. Never uses ``bool(str)``."""
    if isinstance(decision_field, bool):
        kind = DecisionKind.ACCEPT if decision_field else DecisionKind.REJECT
        return kind, decision_field if accepted is None else accepted, None
    if isinstance(decision_field, str):
        parsed = parse_decision_token(decision_field)
        if parsed is None:
            # Fail closed: ``bool("reject")`` must not become accept.
            return None, None, "unrecognized_decision"
        if accepted is None:
            accepted = kind_to_accepted(parsed)
        return parsed, accepted, None
    if isinstance(decision_field, (int, float)) and not isinstance(decision_field, bool):
        score = float(decision_field)
        return DecisionKind.SCORE, score >= 0.5, None
    return None, None, "unrecognized_decision"
