"""Shared artifact record types with schema_version fields."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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
    # VALAB-03 extensions
    SCORE_ONLY = "score_only"
    LABEL_ONLY = "label_only"
    PARTIAL_FEEDBACK = "partial_feedback"
    STATEFUL = "stateful"


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


class AbstentionBehavior(str, Enum):
    """How the verifier treats abstention (VALAB-02)."""

    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    MAPPED_TO_REJECT = "mapped_to_reject"


class SideEffects(str, Enum):
    """Declared side-effect class for a verifier (VALAB-02)."""

    NONE = "none"
    LOGGED = "logged"
    EXTERNAL = "external"


class LabelTier(str, Enum):
    """Label protection tier (VALAB-06)."""

    DEVELOPMENT = "development"
    REGRESSION = "regression"
    RELEASE = "release"
    PRIVATE_HOLDOUT = "private_holdout"


class SourceLocation(ArtifactBase):
    """Source location of a decorated verifier callable."""

    module: str
    qualname: str
    filename: str
    lineno: int | None = None
    source_digest: str | None = None


class VerifierSpec(ArtifactBase):
    """Immutable description of a wrapped verifier (VALAB-02 contract)."""

    schema_version: str = "2"
    name: str
    source: SourceLocation
    callable_digest: str
    decision_space: DecisionSpace = DecisionSpace.BINARY
    input_schema: dict[str, Any] | None = None
    output_schema: dict[str, Any] | None = None
    stochastic: bool = False
    allowed_exceptions: list[str] = Field(default_factory=list)
    score_range: tuple[float, float] | None = None
    abstention: AbstentionBehavior = AbstentionBehavior.UNSUPPORTED
    timeout_s: float | None = None
    side_effects: SideEffects = SideEffects.NONE
    external_resources: list[str] = Field(default_factory=list)
    version: str = "0.0.0"
    access_model: AccessModel = AccessModel.BLACK_BOX
    limitations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("score_range", mode="before")
    @classmethod
    def _coerce_score_range(cls, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, (list, tuple)) and len(value) == 2:
            return (float(value[0]), float(value[1]))
        return value

    @model_validator(mode="after")
    def _score_range_order(self) -> VerifierSpec:
        if self.score_range is not None and self.score_range[0] > self.score_range[1]:
            raise ValueError("score_range min must be <= max")
        return self

    def legacy_contract(self) -> bool:
        """True when metadata opts into one-release incomplete-contract escape."""
        return bool(self.metadata.get("legacy_contract"))

    def contract_complete(self) -> bool:
        """Return True when required VALAB-02 contract fields are present."""
        if self.legacy_contract():
            return True
        return self.input_schema is not None and self.output_schema is not None

    def contract_gaps(self) -> list[str]:
        """Human-readable missing contract fields (empty when complete / legacy)."""
        if self.legacy_contract():
            return []
        gaps: list[str] = []
        if self.input_schema is None:
            gaps.append("input_schema")
        if self.output_schema is None:
            gaps.append("output_schema")
        return gaps


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

    report_version: str = "2"
    run_id: str
    run_digest: str
    access_model: str = AccessModel.BLACK_BOX.value
    metrics: dict[str, Any] = Field(default_factory=dict)
    exploit_count: int = 0
    exploit_unit_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
