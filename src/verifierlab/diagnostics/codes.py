"""Diagnostic codes for CLI and validation."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict


class DiagnosticSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class Diagnostic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    severity: DiagnosticSeverity
    message: str
    path: str | None = None
