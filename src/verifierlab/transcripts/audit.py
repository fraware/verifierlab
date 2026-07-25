"""Transcript audit: deterministic rules first, calibration hooks second."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AuditFinding:
    rule_id: str
    severity: str
    message: str
    path: str | None = None


@dataclass
class AuditReport:
    findings: list[AuditFinding] = field(default_factory=list)
    reference_metadata_isolated: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1",
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "message": f.message,
                    "path": f.path,
                }
                for f in self.findings
            ],
            "reference_metadata_isolated": self.reference_metadata_isolated,
        }


def _rule_hidden_label_leak(payload: dict[str, Any]) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    forbidden = ("gt_label", "ground_truth_label", "hidden_label", "vault_secret")
    blob = str(payload)

    def walk(obj: Any, path: str) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                key = str(k).lower()
                if key in forbidden or key.startswith("hidden_"):
                    findings.append(
                        AuditFinding(
                            rule_id="TRANSCRIPT.HIDDEN_LABEL",
                            severity="error",
                            message=f"forbidden key {k!r} in worker-visible payload",
                            path=f"{path}.{k}" if path else str(k),
                        )
                    )
                walk(v, f"{path}.{k}" if path else str(k))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, f"{path}[{i}]")

    walk(payload, "")
    for token in ("VAULT_SECRET", "LABEL_PRE_FREEZE"):
        if token in blob:
            findings.append(
                AuditFinding(
                    rule_id="TRANSCRIPT.SECRET_TOKEN",
                    severity="error",
                    message=f"secret token {token} found in transcript",
                )
            )
    return findings


def _rule_query_accounting(payload: dict[str, Any]) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    invocations = payload.get("verifier_invocations")
    if invocations is not None and not isinstance(invocations, list):
        findings.append(
            AuditFinding(
                rule_id="TRANSCRIPT.QUERY_ACCOUNTING",
                severity="warning",
                message="verifier_invocations should be a list",
            )
        )
    return findings


DETERMINISTIC_RULES: list[Callable[[dict[str, Any]], list[AuditFinding]]] = [
    _rule_hidden_label_leak,
    _rule_query_accounting,
]


class CalibrationHook:
    """Optional non-deterministic detector; disabled by default in CI."""

    def __init__(self, name: str, fn: Callable[[dict[str, Any]], list[AuditFinding]]) -> None:
        self.name = name
        self.fn = fn

    def run(self, payload: dict[str, Any]) -> list[AuditFinding]:
        return self.fn(payload)


def audit_transcript(
    payload: dict[str, Any],
    *,
    calibration_hooks: list[CalibrationHook] | None = None,
    allow_reference_metadata: bool = False,
) -> AuditReport:
    """Audit a worker transcript. Reference metadata must stay isolated."""
    findings: list[AuditFinding] = []
    for rule in DETERMINISTIC_RULES:
        findings.extend(rule(payload))
    isolated = True
    if "reference_metadata" in payload and not allow_reference_metadata:
        isolated = False
        findings.append(
            AuditFinding(
                rule_id="TRANSCRIPT.REF_META",
                severity="error",
                message="reference_metadata must not appear in worker transcripts",
                path="reference_metadata",
            )
        )
    for hook in calibration_hooks or []:
        findings.extend(hook.run(payload))
    return AuditReport(findings=findings, reference_metadata_isolated=isolated)
