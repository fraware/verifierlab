"""Core protocols for environments, ground truth, attacks, and launchers."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class EnvironmentTarget(Protocol):
    """Environment that produces trajectories for verification."""

    def reset(self, *, seed: int) -> dict[str, Any]:
        """Reset environment; return initial observation."""

    def act(self, action: dict[str, Any]) -> dict[str, Any]:
        """Apply an action; return step result with observation / reward / done."""

    def finalize(self) -> dict[str, Any]:
        """Finalize episode; return trajectory payload."""

    def snapshot(self) -> bytes:
        """Serialize environment state for restore."""

    def restore(self, snapshot: bytes) -> None:
        """Restore environment from ``snapshot``."""


@runtime_checkable
class GroundTruthProvider(Protocol):
    """Hidden reference labels; coordinator/adjudicator only (never attack workers).

    Attack workers must not import implementations of this protocol. Commitments
    on the attack plane are ``digest(trajectory || coordinator_nonce)`` without
    a validity bit; sealing happens in the label vault after freeze.
    """

    def commit(self, trajectory: dict[str, Any]) -> str:
        """Commit a label commitment digest for ``trajectory`` (adjudicator use)."""

    def label(self, commitment: str, *, after_freeze: bool = False) -> dict[str, Any]:
        """Reveal label for ``commitment`` only when ``after_freeze`` is True."""


@runtime_checkable
class AttackStrategy(Protocol):
    """Attack / search strategy over an environment + verifier."""

    def initialize(self, config: dict[str, Any]) -> None: ...

    def propose(self) -> dict[str, Any]: ...

    def observe(self, feedback: dict[str, Any]) -> None: ...

    def checkpoint(self) -> dict[str, Any]: ...


@runtime_checkable
class CampaignLauncher(Protocol):
    """Submit and collect campaign work units."""

    def submit(self, work_unit: dict[str, Any]) -> str: ...

    def status(self, handle: str) -> str: ...

    def collect(self, handle: str) -> dict[str, Any]: ...

    def cancel(self, handle: str) -> None: ...
