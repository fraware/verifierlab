"""CampaignSpec models, YAML/JSON loading, and validation diagnostics."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from verifierlab.artifacts.records import AccessModel, DisclosureClass
from verifierlab.budgets.budget import Budget, OverrunPolicy
from verifierlab.diagnostics.codes import Diagnostic, DiagnosticSeverity


class CampaignSpecError(ValueError):
    """Raised when a campaign fails validation."""

    def __init__(self, message: str, diagnostics: list[Diagnostic]) -> None:
        self.diagnostics = diagnostics
        super().__init__(message)


class TargetRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str
    ref: str
    version: str | None = None
    config: dict[str, Any] = Field(default_factory=dict)


class GroundTruthSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    version: str | None = None
    config: dict[str, Any] = Field(default_factory=dict)


class BaselineSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    strategy: str = "ordinary"
    config: dict[str, Any] = Field(default_factory=dict)


class AttackSpec(BaseModel):
    """Named attack cohort within a campaign."""

    model_config = ConfigDict(extra="forbid")

    name: str
    strategy: str
    cohort: str = "optimized"
    units: int = Field(default=1, ge=1)
    config: dict[str, Any] = Field(default_factory=dict)


class SplitSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    fraction: float | None = Field(default=None, ge=0.0, le=1.0)
    count: int | None = Field(default=None, ge=0)
    seed: int | None = None

    @model_validator(mode="after")
    def _fraction_or_count(self) -> SplitSpec:
        if self.fraction is None and self.count is None:
            raise ValueError(f"split {self.name!r} requires fraction or count")
        return self


class StatsPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    methods: list[str] = Field(default_factory=lambda: ["wilson"])
    alpha: float = Field(default=0.05, gt=0.0, lt=1.0)
    bootstrap_samples: int = Field(default=1000, ge=0)


class CampaignSpec(BaseModel):
    """Pinned campaign plan C = (E, V, G, P, A, B, X, S) binding."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1"
    name: str
    description: str | None = None
    pinned_versions: dict[str, str] = Field(default_factory=dict)
    access_model: AccessModel
    budget: Budget
    environment: TargetRef
    verifier: TargetRef
    ground_truth: GroundTruthSpec
    baseline: BaselineSpec = Field(default_factory=BaselineSpec)
    attacks: list[AttackSpec] = Field(default_factory=list)
    splits: list[SplitSpec] = Field(default_factory=list)
    stats_plan: StatsPlan = Field(default_factory=StatsPlan)
    disclosure_class: DisclosureClass = DisclosureClass.INTERNAL
    seed: int = 0
    work_units: int = Field(default=1, ge=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _nonempty_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("name must be non-empty")
        return value

    @model_validator(mode="after")
    def _require_pinned_core(self) -> CampaignSpec:
        # Soft requirement enforced via diagnostics; keep model flexible.
        return self


def _diagnostic_from_validation_error(exc: ValidationError) -> list[Diagnostic]:
    out: list[Diagnostic] = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err.get("loc", ()))
        out.append(
            Diagnostic(
                code="VALAB.CAMPAIGN.SCHEMA",
                severity=DiagnosticSeverity.ERROR,
                message=err.get("msg", "validation error"),
                path=loc or None,
            )
        )
    return out


def validate_campaign_semantics(spec: CampaignSpec) -> list[Diagnostic]:
    """Return semantic diagnostics (errors and warnings) for a loaded spec."""
    diags: list[Diagnostic] = []
    required_pins = ("verifierlab", "campaign")
    for key in required_pins:
        if key not in spec.pinned_versions:
            diags.append(
                Diagnostic(
                    code="VALAB.CAMPAIGN.PINNED_VERSION",
                    severity=DiagnosticSeverity.ERROR,
                    message=f"pinned_versions missing required key {key!r}",
                    path="pinned_versions",
                )
            )
    if spec.environment.kind not in {"fake", "python", "adapter"}:
        diags.append(
            Diagnostic(
                code="VALAB.CAMPAIGN.ENV_KIND",
                severity=DiagnosticSeverity.WARNING,
                message=f"unrecognized environment.kind {spec.environment.kind!r}",
                path="environment.kind",
            )
        )
    if not spec.ground_truth.provider:
        diags.append(
            Diagnostic(
                code="VALAB.CAMPAIGN.GT",
                severity=DiagnosticSeverity.ERROR,
                message="ground_truth.provider must be non-empty",
                path="ground_truth.provider",
            )
        )
    if spec.budget.overrun_policy not in OverrunPolicy:
        diags.append(
            Diagnostic(
                code="VALAB.CAMPAIGN.BUDGET",
                severity=DiagnosticSeverity.ERROR,
                message="invalid overrun_policy",
                path="budget.overrun_policy",
            )
        )
    if not spec.stats_plan.methods:
        diags.append(
            Diagnostic(
                code="VALAB.CAMPAIGN.STATS",
                severity=DiagnosticSeverity.WARNING,
                message="stats_plan.methods is empty",
                path="stats_plan.methods",
            )
        )
    if not isinstance(spec.access_model, AccessModel):
        diags.append(
            Diagnostic(
                code="VALAB.CAMPAIGN.ACCESS",
                severity=DiagnosticSeverity.ERROR,
                message="access_model is required",
                path="access_model",
            )
        )
    if not isinstance(spec.disclosure_class, DisclosureClass):
        diags.append(
            Diagnostic(
                code="VALAB.CAMPAIGN.DISCLOSURE",
                severity=DiagnosticSeverity.ERROR,
                message="disclosure_class is required",
                path="disclosure_class",
            )
        )
    if not spec.baseline.strategy:
        diags.append(
            Diagnostic(
                code="VALAB.CAMPAIGN.BASELINE",
                severity=DiagnosticSeverity.ERROR,
                message="baseline.strategy must be non-empty",
                path="baseline.strategy",
            )
        )
    return diags


def load_campaign_dict(data: dict[str, Any]) -> tuple[CampaignSpec | None, list[Diagnostic]]:
    try:
        spec = CampaignSpec.model_validate(data)
    except ValidationError as exc:
        return None, _diagnostic_from_validation_error(exc)
    diags = validate_campaign_semantics(spec)
    return spec, diags


def load_campaign(path: Path | str) -> tuple[CampaignSpec, list[Diagnostic]]:
    """Load YAML or JSON campaign file; raise :class:`CampaignSpecError` on errors."""
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        raw = yaml.safe_load(text)
    elif suffix == ".json":
        raw = json.loads(text)
    else:
        # Try YAML first, then JSON.
        try:
            raw = yaml.safe_load(text)
        except yaml.YAMLError:
            raw = json.loads(text)
    if not isinstance(raw, dict):
        raise CampaignSpecError(
            "campaign root must be a mapping",
            [
                Diagnostic(
                    code="VALAB.CAMPAIGN.ROOT",
                    severity=DiagnosticSeverity.ERROR,
                    message="campaign root must be a mapping",
                    path=str(path),
                )
            ],
        )
    spec, diags = load_campaign_dict(raw)
    errors = [d for d in diags if d.severity == DiagnosticSeverity.ERROR]
    if spec is None or errors:
        raise CampaignSpecError(
            f"campaign validation failed for {path}",
            diags,
        )
    return spec, diags


# Re-export enums commonly used with specs.
__all__ = [
    "AccessModel",
    "AttackSpec",
    "BaselineSpec",
    "CampaignSpec",
    "CampaignSpecError",
    "DisclosureClass",
    "GroundTruthSpec",
    "SplitSpec",
    "StatsPlan",
    "TargetRef",
    "load_campaign",
    "load_campaign_dict",
    "validate_campaign_semantics",
]
