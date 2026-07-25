"""Shared artifact record types with schema_version fields."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ArtifactBase(BaseModel):
    """Base for content-addressable records."""

    model_config = ConfigDict(extra="forbid", frozen=False)

    schema_version: str = Field(default="1", description="Artifact schema version")


class AccessModel(str, Enum):
    BLACK_BOX = "black-box"
    GRAY_BOX = "gray-box"
    WHITE_BOX = "white-box"
    ADAPTIVE = "adaptive"
    TRANSFER = "transfer"
    SIDE_CHANNEL = "side-channel"


class DisclosureClass(str, Enum):
    PUBLIC = "public"
    EMBARGO = "embargo"
    PRIVATE = "private"
    INTERNAL = "internal"


class DecisionSpace(str, Enum):
    BINARY = "binary"
    MULTICLASS = "multiclass"
    CONTINUOUS = "continuous"
    STRUCTURED = "structured"


class SourceLocation(ArtifactBase):
    """Source location of a decorated verifier callable."""

    module: str
    qualname: str
    filename: str
    lineno: int | None = None
    source_digest: str | None = None


class VerifierSpec(ArtifactBase):
    """Immutable description of a wrapped verifier."""

    name: str
    source: SourceLocation
    callable_digest: str
    decision_space: DecisionSpace = DecisionSpace.BINARY
    input_schema: dict[str, Any] | None = None
    output_schema: dict[str, Any] | None = None
    limitations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TrajectoryRecord(ArtifactBase):
    """Minimal trajectory artifact for M0 fake campaigns."""

    trajectory_id: str
    seed: int
    steps: list[dict[str, Any]] = Field(default_factory=list)
    observation: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class VerifierInvocation(ArtifactBase):
    """Record of one public verifier call."""

    invocation_id: str
    trajectory_digest: str
    decision: Any
    accepted: bool | None = None
    raw_output: Any = None
    latency_ms: float | None = None


class RunManifest(ArtifactBase):
    """Top-level run bundle manifest."""

    run_id: str
    campaign_digest: str
    status: str
    work_unit_digests: list[str] = Field(default_factory=list)
    ledger_digest: str | None = None
    overrun: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssuranceReport(ArtifactBase):
    """Offline-rebuildable assurance report sidecar (JSON form)."""

    report_version: str = "1"
    run_id: str
    run_digest: str
    access_model: str = AccessModel.BLACK_BOX.value
    metrics: dict[str, Any] = Field(default_factory=dict)
    exploit_count: int = 0
    exploit_unit_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
