"""Coordinator/adjudicator-only planted ground truth for fake campaigns.

This module is intentionally placed under :mod:`verifierlab.labels` so worker
images can remove the entire labels package and cannot import the oracle used to
adjudicate the planted fake target.
"""

from __future__ import annotations

import secrets
import warnings
from typing import Any

from verifierlab.artifacts.canonical import digest_of


class PlantedOracleGroundTruth:
    """Oracle GT: refunds with amount greater than 100 are invalid.

    Commitments use schema v2 (trajectory + nonce only). Validity is stored
    privately and must not be recoverable by offline Boolean guessing against
    the public digest. Prefer :class:`~verifierlab.labels.vault.LabelVault` for
    campaign adjudication.
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
        """Deprecated legacy commitment that embeds validity in the digest."""
        warnings.warn(
            "legacy planted commitment embeds validity in the digest; use commit() or LabelVault",
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


__all__ = ["PlantedOracleGroundTruth"]
