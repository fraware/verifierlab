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
from verifierlab.statistics.preregistration import AnalysisPreregistration


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


class StatsPlan(BaseModel):
    """Executable statistical analysis plan (VAL-R12 / VALAB-08).

    A declared option must be implemented by the compiler or rejected
    fail-closed; it must never be copied into a report as if it had run.
    """

    model_config = ConfigDict(extra="forbid")
    methods: list[str] = Field(default_factory=lambda: ["wilson"])
    alpha: float = Field(default=0.05, gt=0.0, lt=1.0)
    bootstrap_samples: int = Field(default=1000, ge=0)
    bootstrap_seed: int = 0
    pairing_key: str | None = Field(
        default=None,
        description="Optional row field identifying ordinary/optimized paired units.",
    )
    stopping_rule: str = Field(
        default="fixed_n",
        description="fixed_n | budget_exhausted | sequential_alpha",
    )
    multiple_comparison_policy: str = Field(
        default="none",
        description="none | bonferroni | pre_registered_primary",
    )
    preregistration: AnalysisPreregistration | None = None

    @field_validator("methods")
    @classmethod
    def _known_methods(cls, values: list[str]) -> list[str]:
        allowed = {"wilson", "exact"}
        unknown = sorted(set(values) - allowed)
        if unknown:
            raise ValueError(f"unsupported interval methods: {unknown}; allowed={sorted(allowed)}")
        return values

    @field_validator("pairing_key")
    @classmethod
    def _pairing_key_nonempty(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("pairing_key must be non-empty when supplied")
        return value

    @field_validator("stopping_rule")
    @classmethod
    def _known_stopping(cls, value: str) -> str:
        allowed = {"fixed_n", "budget_exhausted", "sequential_alpha"}
        if value not in allowed:
            raise ValueError(f"stopping_rule must be one of {sorted(allowed)}")
        return value

    @field_validator("multiple_comparison_policy")
    @classmethod
    def _known_mcp(cls, value: str) -> str:
        allowed = {"none", "bonferroni", "pre_registered_primary"}
        if value not in allowed:
            raise ValueError(f"multiple_comparison_policy must be one of {sorted(allowed)}")
        return value


class SplitSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    fraction: float | None = Field(default=None, ge=0.0, le=1.0)
    count: int | None = Field(default=None, ge=0)
    seed: int | None = None
    label_tier: str | None = Field(
        default=None,
        description="LabelTier: development|regression|release|private_holdout",
    )

    @model_validator(mode="after")
    def _fraction_or_count(self) -> SplitSpec:
        if self.fraction is None and self.count is None:
            raise ValueError(f"split {self.name!r} requires fraction or count")
        return self

    @field_validator("label_tier")
    @classmethod
    def _known_tier(cls, value: str | None) -> str | None:
        if value is None:
            return None
        from verifierlab.artifacts.records import LabelTier

        allowed = {t.value for t in LabelTier}
        if value not in allowed:
            raise ValueError(f"label_tier must be one of {sorted(allowed)}")
        return value


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
    for key in ("verifierlab", "campaign"):
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
    if spec.stats_plan.stopping_rule == "sequential_alpha":
        diags.append(
            Diagnostic(
                code="VALAB.CAMPAIGN.SEQUENTIAL_UNSUPPORTED",
                severity=DiagnosticSeverity.ERROR,
                message=(
                    "stopping_rule='sequential_alpha' is not implemented; use a fixed/budget "
                    "design or add a preregistered sequential alpha-spending procedure"
                ),
                path="stats_plan.stopping_rule",
            )
        )
    if spec.stats_plan.multiple_comparison_policy == "pre_registered_primary":
        diags.append(
            Diagnostic(
                code="VALAB.CAMPAIGN.PRIMARY_FAMILY_UNSUPPORTED",
                severity=DiagnosticSeverity.ERROR,
                message=(
                    "pre_registered_primary requires an explicit estimand family compiler; "
                    "use none/bonferroni until that implementation exists"
                ),
                path="stats_plan.multiple_comparison_policy",
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
    diags.extend(_validate_verifier_contract(spec))
    return diags


def _validate_verifier_contract(spec: CampaignSpec) -> list[Diagnostic]:
    """VALAB-02: reject incomplete verifier contracts unless legacy_contract."""
    diags: list[Diagnostic] = []
    ref = spec.verifier.ref
    if not ref or ":" not in ref:
        return diags
    try:
        from verifierlab.api.verifier import get_verifier_spec
        from verifierlab.plugins.loader import load_object

        fn = load_object(ref)
        try:
            vspec = get_verifier_spec(fn)
        except AttributeError:
            diags.append(
                Diagnostic(
                    code="VALAB.CAMPAIGN.VERIFIER_CONTRACT",
                    severity=DiagnosticSeverity.WARNING,
                    message=f"verifier {ref!r} is not @verifier-decorated; contract not checked",
                    path="verifier.ref",
                )
            )
            return diags
        gaps = vspec.contract_gaps()
        if gaps:
            diags.append(
                Diagnostic(
                    code="VALAB.CAMPAIGN.VERIFIER_CONTRACT",
                    severity=DiagnosticSeverity.ERROR,
                    message=(
                        f"verifier {ref!r} missing required contract fields: {', '.join(gaps)} "
                        "(set metadata.legacy_contract=True for one-release migration)"
                    ),
                    path="verifier.ref",
                )
            )
    except Exception as exc:
        diags.append(
            Diagnostic(
                code="VALAB.CAMPAIGN.VERIFIER_LOAD",
                severity=DiagnosticSeverity.WARNING,
                message=f"could not load verifier for contract check: {exc}",
                path="verifier.ref",
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
        raise CampaignSpecError(f"campaign validation failed for {path}", diags)
    return spec, diags


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
