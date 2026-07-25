"""Plugin template: transcript detector."""

from __future__ import annotations

from typing import Any

from verifierlab.transcripts.audit import AuditFinding


def example_detector(payload: dict[str, Any]) -> list[AuditFinding]:
    if "DEBUG_LEAK" in str(payload):
        return [
            AuditFinding(
                rule_id="EXAMPLE.DEBUG_LEAK",
                severity="warning",
                message="debug leak token present",
            )
        ]
    return []
