"""Enforced access-model capability objects (VAL-R09 / VALAB-03).

Capability objects — not metadata strings alone — gate broker feedback channels.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from verifierlab.artifacts.records import AccessModel


class AccessDenied(PermissionError):
    """Raised when the access model forbids the requested capability."""


@dataclass(frozen=True)
class AccessCapabilities:
    """Concrete privileges granted under an access model."""

    access_model: str
    may_read_decision: bool = True
    may_read_score: bool = True
    may_read_reason_codes: bool = False
    reason_code_allowlist: frozenset[str] = field(default_factory=frozenset)
    may_mount_profile: bool = False
    may_read_source: bool = False
    may_use_adaptive_rounds: bool = False
    may_use_transfer_artifacts: bool = False
    may_retain_episode_state: bool = False

    def require(self, capability: str) -> None:
        """Raise :class:`AccessDenied` when ``capability`` is not granted."""
        if capability in {"decision", "score"}:
            allowed = self.may_read_decision if capability == "decision" else self.may_read_score
            if not allowed:
                raise AccessDenied(f"{self.access_model} cannot read {capability}")
            return
        if capability == "reason_codes":
            if not self.may_read_reason_codes:
                raise AccessDenied(f"{self.access_model} access cannot read reason-code channel")
            return
        if capability == "profile":
            if not self.may_mount_profile:
                raise AccessDenied(f"{self.access_model} access cannot mount verifier profile")
            return
        if capability == "source":
            if not self.may_read_source:
                raise AccessDenied(f"{self.access_model} access cannot read verifier source")
            return
        if capability == "adaptive":
            if not self.may_use_adaptive_rounds:
                raise AccessDenied(f"{self.access_model} access cannot use adaptive rounds")
            return
        if capability == "transfer":
            if not self.may_use_transfer_artifacts:
                raise AccessDenied(f"{self.access_model} access cannot use transfer artifacts")
            return
        if capability == "episode_state":
            if not self.may_retain_episode_state:
                raise AccessDenied(
                    f"{self.access_model} access cannot retain episode state across queries"
                )
            return
        raise AccessDenied(f"unknown capability: {capability}")

    def filter_reason_codes(self, codes: list[str]) -> list[str]:
        """Return reason codes visible under this capability set."""
        if not self.may_read_reason_codes:
            return []
        if not self.reason_code_allowlist:
            return list(codes)
        return [c for c in codes if c in self.reason_code_allowlist]

    def as_dict(self) -> dict[str, Any]:
        return {
            "access_model": self.access_model,
            "may_read_decision": self.may_read_decision,
            "may_read_score": self.may_read_score,
            "may_read_reason_codes": self.may_read_reason_codes,
            "reason_code_allowlist": sorted(self.reason_code_allowlist),
            "may_mount_profile": self.may_mount_profile,
            "may_read_source": self.may_read_source,
            "may_use_adaptive_rounds": self.may_use_adaptive_rounds,
            "may_use_transfer_artifacts": self.may_use_transfer_artifacts,
            "may_retain_episode_state": self.may_retain_episode_state,
        }


# Default gray-box / partial-feedback allowlist: rubric categories, not source digests.
_DEFAULT_GRAY_ALLOWLIST = frozenset(
    {
        "amount_limit",
        "authorization",
        "policy",
        "schema",
        "timeout",
        "over_limit",
        "under_limit",
        "duplicate",
        "forgery",
    }
)


def capabilities_for(
    access_model: str,
    *,
    reason_code_allowlist: frozenset[str] | None = None,
) -> AccessCapabilities:
    """Build capability objects for a declared access model."""
    model = str(access_model)
    if model == AccessModel.BLACK_BOX.value:
        return AccessCapabilities(
            access_model=model,
            may_read_decision=True,
            may_read_score=True,
            may_read_reason_codes=False,
            may_mount_profile=False,
            may_read_source=False,
        )
    if model == AccessModel.GRAY_BOX.value:
        return AccessCapabilities(
            access_model=model,
            may_read_decision=True,
            may_read_score=True,
            may_read_reason_codes=True,
            reason_code_allowlist=reason_code_allowlist or _DEFAULT_GRAY_ALLOWLIST,
            may_mount_profile=False,
            may_read_source=False,
        )
    if model == AccessModel.WHITE_BOX.value:
        return AccessCapabilities(
            access_model=model,
            may_read_decision=True,
            may_read_score=True,
            may_read_reason_codes=True,
            reason_code_allowlist=frozenset(),  # unrestricted when empty + may_read
            may_mount_profile=True,
            may_read_source=True,
        )
    if model == AccessModel.ADAPTIVE.value:
        return AccessCapabilities(
            access_model=model,
            may_read_decision=True,
            may_read_score=True,
            may_read_reason_codes=False,
            may_mount_profile=False,
            may_read_source=False,
            may_use_adaptive_rounds=True,
        )
    if model == AccessModel.TRANSFER.value:
        return AccessCapabilities(
            access_model=model,
            may_read_decision=True,
            may_read_score=True,
            may_read_reason_codes=False,
            may_mount_profile=False,
            may_read_source=False,
            may_use_transfer_artifacts=True,
        )
    if model == AccessModel.SIDE_CHANNEL.value:
        return AccessCapabilities(
            access_model=model,
            may_read_decision=True,
            may_read_score=True,
            may_read_reason_codes=False,
            may_mount_profile=False,
            may_read_source=False,
        )
    if model == AccessModel.SCORE_ONLY.value:
        return AccessCapabilities(
            access_model=model,
            may_read_decision=False,
            may_read_score=True,
            may_read_reason_codes=False,
            may_mount_profile=False,
            may_read_source=False,
        )
    if model == AccessModel.LABEL_ONLY.value:
        return AccessCapabilities(
            access_model=model,
            may_read_decision=True,
            may_read_score=False,
            may_read_reason_codes=False,
            may_mount_profile=False,
            may_read_source=False,
        )
    if model == AccessModel.PARTIAL_FEEDBACK.value:
        # Same channel as gray-box; distinct name for VALAB-03.
        return AccessCapabilities(
            access_model=model,
            may_read_decision=True,
            may_read_score=True,
            may_read_reason_codes=True,
            reason_code_allowlist=reason_code_allowlist or _DEFAULT_GRAY_ALLOWLIST,
            may_mount_profile=False,
            may_read_source=False,
        )
    if model == AccessModel.STATEFUL.value:
        return AccessCapabilities(
            access_model=model,
            may_read_decision=True,
            may_read_score=True,
            may_read_reason_codes=False,
            may_mount_profile=False,
            may_read_source=False,
            may_retain_episode_state=True,
        )
    raise ValueError(f"unknown access model: {access_model!r}")
