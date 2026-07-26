from __future__ import annotations

from typing import Any

from verifierlab.api.verifier import verifier
from verifierlab.artifacts.records import DecisionSpace


@verifier(
    name="v3_inspect_grade",
    decision_space=DecisionSpace.BINARY,
    version="1.0.0",
    input_schema={"type": "object"},
    output_schema={"type": "boolean"},
    limitations=["Example V3 — inspect samples"],
)
def grade(trajectory: dict[str, Any]) -> bool:
    steps = trajectory.get('steps') or []
    return any(s.get('op') == 'inspect_sample' for s in steps) or bool(steps)
