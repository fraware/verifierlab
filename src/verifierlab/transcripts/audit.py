"""Transcript audit: deterministic rules first, plugins second (VAL-R16).

**Non-claim:** automated transcript audit findings are *not* ground truth.
They are structural / heuristic signals for human review. Disagreement records
and optional external plugins must never be presented as labels.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import Any

AUDIT_DISCLAIMER = (
    "Automated transcript audit is not ground truth. Findings are structural "
    "or plugin-heuristic signals for human review only."
)

# Entry-point group for external transcript auditors.
TRANSCRIPT_PLUGIN_GROUP = "verifierlab.transcript_auditors"


@dataclass
class AuditFinding:
    rule_id: str
    severity: str
    message: str
    path: str | None = None
    source: str = "builtin"  # builtin | calibration | plugin


@dataclass
class AuditReport:
    findings: list[AuditFinding] = field(default_factory=list)
    reference_metadata_isolated: bool = True
    is_ground_truth: bool = False
    disclaimer: str = AUDIT_DISCLAIMER
    plugins_run: list[str] = field(default_factory=list)
    disagreement_records: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "2",
            "is_ground_truth": False,
            "disclaimer": self.disclaimer,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "message": f.message,
                    "path": f.path,
                    "source": f.source,
                }
                for f in self.findings
            ],
            "reference_metadata_isolated": self.reference_metadata_isolated,
            "plugins_run": list(self.plugins_run),
            "disagreement_records": list(self.disagreement_records),
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


def _rule_evaluator_tamper(payload: dict[str, Any]) -> list[AuditFinding]:
    """Detect obvious evaluator-state tampering markers in transcripts."""
    findings: list[AuditFinding] = []
    markers = (
        "evaluator_state_patch",
        "__evaluator_mutate__",
        "tamper_gt_fn",
        "monkeypatch_is_valid",
    )
    blob = str(payload).lower()
    for marker in markers:
        if marker in blob:
            findings.append(
                AuditFinding(
                    rule_id="TRANSCRIPT.EVALUATOR_TAMPER",
                    severity="error",
                    message=f"evaluator tampering marker {marker!r} present",
                )
            )
    return findings


DETERMINISTIC_RULES: list[Callable[[dict[str, Any]], list[AuditFinding]]] = [
    _rule_hidden_label_leak,
    _rule_query_accounting,
    _rule_evaluator_tamper,
]


class CalibrationHook:
    """Optional non-deterministic detector; disabled by default in CI."""

    def __init__(self, name: str, fn: Callable[[dict[str, Any]], list[AuditFinding]]) -> None:
        self.name = name
        self.fn = fn

    def run(self, payload: dict[str, Any]) -> list[AuditFinding]:
        return self.fn(payload)


class TranscriptAuditPlugin:
    """External transcript-analysis plugin contract."""

    def __init__(
        self,
        name: str,
        fn: Callable[[dict[str, Any]], list[AuditFinding] | list[dict[str, Any]]],
    ) -> None:
        self.name = name
        self.fn = fn

    def run(self, payload: dict[str, Any]) -> list[AuditFinding]:
        raw = self.fn(payload)
        out: list[AuditFinding] = []
        for item in raw or []:
            if isinstance(item, AuditFinding):
                item.source = "plugin"
                out.append(item)
            elif isinstance(item, dict):
                out.append(
                    AuditFinding(
                        rule_id=str(item.get("rule_id") or f"PLUGIN.{self.name}"),
                        severity=str(item.get("severity") or "info"),
                        message=str(item.get("message") or "plugin finding"),
                        path=item.get("path"),
                        source="plugin",
                    )
                )
        return out


def discover_transcript_plugins(
    group: str = TRANSCRIPT_PLUGIN_GROUP,
) -> dict[str, TranscriptAuditPlugin | BaseException]:
    """Load external auditors registered under ``verifierlab.transcript_auditors``."""
    found: dict[str, TranscriptAuditPlugin | BaseException] = {}
    eps = entry_points()
    select = getattr(eps, "select", None)
    if callable(select):
        selected = list(select(group=group))
    else:
        get = getattr(eps, "get", None)
        selected = list(get(group, ())) if callable(get) else []
    for ep in selected:
        try:
            loaded = ep.load()
            if isinstance(loaded, TranscriptAuditPlugin):
                found[ep.name] = loaded
            elif callable(loaded):
                found[ep.name] = TranscriptAuditPlugin(ep.name, loaded)
            else:
                found[ep.name] = TypeError(
                    f"plugin {ep.name!r} must be callable or TranscriptAuditPlugin"
                )
        except Exception as exc:
            found[ep.name] = exc
    return found


def audit_transcript(
    payload: dict[str, Any],
    *,
    calibration_hooks: list[CalibrationHook] | None = None,
    plugins: list[TranscriptAuditPlugin] | None = None,
    load_entry_point_plugins: bool = False,
    allow_reference_metadata: bool = False,
    human_sample: dict[str, Any] | None = None,
) -> AuditReport:
    """Audit a worker transcript.

    Results are **never** ground truth (``is_ground_truth`` is always False).
    """
    findings: list[AuditFinding] = []
    plugins_run: list[str] = []
    disagreements: list[dict[str, Any]] = []

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
        for f in hook.run(payload):
            f.source = "calibration"
            findings.append(f)
        plugins_run.append(f"calibration:{hook.name}")

    active_plugins = list(plugins or [])
    if load_entry_point_plugins:
        for name, plugin in discover_transcript_plugins().items():
            if isinstance(plugin, BaseException):
                findings.append(
                    AuditFinding(
                        rule_id="TRANSCRIPT.PLUGIN_LOAD",
                        severity="warning",
                        message=f"failed to load plugin {name!r}: {plugin}",
                        source="plugin",
                    )
                )
                continue
            active_plugins.append(plugin)

    for plugin in active_plugins:
        plugin_findings = plugin.run(payload)
        findings.extend(plugin_findings)
        plugins_run.append(plugin.name)

    if human_sample is not None:
        # Optional random human audit sample: record disagreements vs automation.
        human_labels = human_sample.get("labels") or human_sample.get("findings") or []
        auto_ids = {f.rule_id for f in findings}
        human_ids = {str(h.get("rule_id") if isinstance(h, dict) else h) for h in human_labels}
        only_auto = sorted(auto_ids - human_ids)
        only_human = sorted(human_ids - auto_ids)
        if only_auto or only_human:
            disagreements.append(
                {
                    "sample_id": human_sample.get("sample_id"),
                    "only_automated": only_auto,
                    "only_human": only_human,
                    "note": "Disagreement is expected; neither side is automatic GT.",
                }
            )

    return AuditReport(
        findings=findings,
        reference_metadata_isolated=isolated,
        is_ground_truth=False,
        disclaimer=AUDIT_DISCLAIMER,
        plugins_run=plugins_run,
        disagreement_records=disagreements,
    )
