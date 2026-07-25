"""Minimal example verifier for docs (not required for M0 smoke)."""

from __future__ import annotations

from typing import Any

from verifierlab import api


@api.verifier(
    name="example_always_accept",
    limitations=["Example only — accepts everything"],
)
def grade(trajectory: dict[str, Any]) -> bool:
    return True
