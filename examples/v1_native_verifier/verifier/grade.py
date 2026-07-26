"""Native example verifier with full VerifierSpec contract."""

from __future__ import annotations

from typing import Any

from verifierlab.api.verifier import verifier
from verifierlab.artifacts.records import DecisionSpace


@verifier(
    name="v1_native_grade",
    decision_space=DecisionSpace.BINARY,
    version="1.0.0",
    input_schema={
        "type": "object",
        "properties": {
            "schema_version": {"type": "string"},
            "steps": {"type": "array"},
        },
        "required": ["steps"],
    },
    output_schema={"type": "boolean"},
    limitations=["Example verifier — planted FAR for even amounts > 100"],
)
def grade(trajectory: dict[str, Any]) -> bool:
    for step in trajectory.get("steps") or []:
        if step.get("op") == "refund":
            amount = int(step.get("amount", 0) or 0)
            if amount > 100 and amount % 2 == 1:
                return False
    return True
