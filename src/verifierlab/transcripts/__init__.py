"""Transcript detectors."""

from __future__ import annotations

from verifierlab.transcripts.audit import (
    AUDIT_DISCLAIMER,
    TRANSCRIPT_PLUGIN_GROUP,
    AuditFinding,
    AuditReport,
    CalibrationHook,
    TranscriptAuditPlugin,
    audit_transcript,
    discover_transcript_plugins,
)

__all__ = [
    "AUDIT_DISCLAIMER",
    "TRANSCRIPT_PLUGIN_GROUP",
    "AuditFinding",
    "AuditReport",
    "CalibrationHook",
    "TranscriptAuditPlugin",
    "audit_transcript",
    "discover_transcript_plugins",
]
