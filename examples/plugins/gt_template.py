"""Plugin template: ground-truth provider."""

from __future__ import annotations

from typing import Any

from verifierlab.artifacts.canonical import digest_of


class ExampleGroundTruth:
    def __init__(self) -> None:
        self._vault: dict[str, dict[str, Any]] = {}

    def commit(self, trajectory: dict[str, Any]) -> str:
        valid = True
        commitment = digest_of({"trajectory": trajectory, "valid": valid})
        self._vault[commitment] = {"valid": valid}
        return commitment

    def label(self, commitment: str, *, after_freeze: bool = False) -> dict[str, Any]:
        if not after_freeze:
            raise PermissionError("sealed")
        return dict(self._vault[commitment])
