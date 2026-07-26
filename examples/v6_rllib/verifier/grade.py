from __future__ import annotations

from typing import Any

from verifierlab.api.verifier import verifier
from verifierlab.artifacts.records import DecisionSpace


@verifier(
    name="v6_rllib_grade",
    decision_space=DecisionSpace.BINARY,
    version="1.0.0",
    input_schema={"type": "object"},
    output_schema={"type": "boolean"},
    limitations=["Example V6 — broker reward channel"],
)
def grade(trajectory: dict[str, Any]) -> bool:
    return bool(trajectory.get('steps'))
