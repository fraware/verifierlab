"""Multi-dimensional adjudication with role recording."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from verifierlab.artifacts.records import ArtifactBase


class Adjudication(ArtifactBase):
    """Human/automated adjudication across correctness dimensions."""

    adjudication_id: str
    exploit_id: str | None = None
    unit_id: str
    role: str
    dimensions: dict[str, Any] = Field(default_factory=dict)
    decision: str
    notes: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


def adjudicate(
    *,
    adjudication_id: str,
    unit_id: str,
    role: str,
    decision: str,
    dimensions: dict[str, Any] | None = None,
    exploit_id: str | None = None,
    notes: str | None = None,
) -> Adjudication:
    return Adjudication(
        adjudication_id=adjudication_id,
        unit_id=unit_id,
        role=role,
        decision=decision,
        dimensions=dict(dimensions or {}),
        exploit_id=exploit_id,
        notes=notes,
    )
