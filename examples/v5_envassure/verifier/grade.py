from __future__ import annotations

from typing import Any

from verifierlab.api.verifier import verifier
from verifierlab.artifacts.records import DecisionSpace


@verifier(
    name="v5_envassure_grade",
    decision_space=DecisionSpace.BINARY,
    version="1.0.0",
    input_schema={"type": "object"},
    output_schema={"type": "boolean"},
    limitations=["Example V5 — public feedback only"],
)
def grade(trajectory: dict[str, Any]) -> bool:
    blob = str(trajectory)
    assert 'evaluator_state' not in blob
    assert 'planted_label' not in blob
    return bool(trajectory.get('steps'))
