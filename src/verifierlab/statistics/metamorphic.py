"""Metamorphic and isomorphic verification with explicit transformation contracts.

Legacy helpers remain available for existing pack fixtures. The registered API
adds content-bound transformation implementations, canonical parameters,
declared invariants and assumptions, typed case evidence, and suite summaries.
A transformation that changes declared ground-truth validity is invalid evidence,
not a verifier exploit.
"""

from __future__ import annotations

import inspect
import json
import textwrap
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from verifierlab.artifacts.canonical import canonical_dumps, digest_of, sha256_digest

# Actor aliases that preserve unauthorized / authorized semantics for GT.
DEFAULT_USER_REMAP = {
    "eve": "malory",
    "malory": "eve",
    "admin": "root_user",
    "root_user": "admin",
    "alice": "authorized_user",
    "authorized_user": "alice",
}

TransformationFn = Callable[[dict[str, Any], Mapping[str, Any]], dict[str, Any]]
MetamorphicStatus = Literal[
    "consistent",
    "verifier_violation",
    "indeterminate",
    "invalid_transform",
]
CounterexampleKind = Literal[
    "ground_truth_invariance_violation",
    "verifier_invariance_violation",
    "verifier_decision_indeterminate",
]


def isomorphic_remap(
    trajectory: dict[str, Any],
    *,
    user_map: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Deep-copy a trajectory with isomorphic actor remapping.

    Marks remapped steps with ``relabel=True`` for pack-C taxonomy binding.
    Cosmetic fields (``note``, ``display``) are flipped to stress surface form.
    """
    users = dict(user_map or DEFAULT_USER_REMAP)
    out = deepcopy(trajectory)
    new_steps: list[dict[str, Any]] = []
    for step in out.get("steps") or []:
        if not isinstance(step, dict):
            new_steps.append(step)
            continue
        s = dict(step)
        uid = s.get("user_id")
        if isinstance(uid, str) and uid in users:
            s["user_id"] = users[uid]
            s["relabel"] = True
            s["alias_of"] = uid
        # Surface-only noise that must not affect GT.
        if "note" in s:
            s["note"] = f"remap:{s['note']}"
        else:
            s["note"] = "isomorphic-surface"
        if s.get("op") == "duplicate":
            s["relabel"] = True
        new_steps.append(s)
    out["steps"] = new_steps
    if "pack_theme" in trajectory:
        out["pack_theme"] = trajectory["pack_theme"]
    out["isomorphic_remap"] = True
    return out


def assert_gt_invariance(
    trajectory: dict[str, Any],
    *,
    is_valid: Callable[[dict[str, Any]], bool],
    remap: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assert ground-truth validity is unchanged under isomorphic remap."""
    transformed = (remap or isomorphic_remap)(trajectory)
    before = bool(is_valid(trajectory))
    after = bool(is_valid(transformed))
    if before != after:
        raise AssertionError(f"GT metamorphic invariance violated: before={before} after={after}")
    return {
        "invariant": "gt_validity",
        "before": before,
        "after": after,
        "held": True,
        "transformed": transformed,
    }


def verifier_invariance_report(
    trajectory: dict[str, Any],
    *,
    verifier: Callable[[dict[str, Any]], Any],
    is_valid: Callable[[dict[str, Any]], bool],
    remap: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compare verifier decisions before/after remap against GT invariance."""
    from verifierlab.api.verifier import normalize_decision

    transformed = (remap or isomorphic_remap)(trajectory)
    gt_before = bool(is_valid(trajectory))
    gt_after = bool(is_valid(transformed))
    v_before = normalize_decision(verifier(trajectory)).accepted is True
    v_after = normalize_decision(verifier(transformed)).accepted is True
    return {
        "gt_invariant": gt_before == gt_after,
        "gt_before": gt_before,
        "gt_after": gt_after,
        "verifier_before": v_before,
        "verifier_after": v_after,
        "verifier_invariant": v_before == v_after,
    }


def _callable_implementation_digest(fn: TransformationFn) -> str:
    try:
        source = textwrap.dedent(inspect.getsource(fn))
    except (OSError, TypeError):
        source = f"{fn.__module__}:{fn.__qualname__}"
    return digest_of(
        {
            "module": fn.__module__,
            "qualname": fn.__qualname__,
            "source_digest": sha256_digest(source.encode("utf-8")),
        }
    )


class TransformationSpec(BaseModel):
    """Immutable declaration of one metamorphic transformation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    transformation_id: str = Field(min_length=1)
    family: str = Field(min_length=1)
    version: str = Field(min_length=1)
    invariant: Literal["gt_validity"] = "gt_validity"
    implementation_digest: str = Field(min_length=1)
    parameters_json: str = "{}"
    assumptions: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_canonical_parameters(self) -> TransformationSpec:
        try:
            parsed = json.loads(self.parameters_json)
        except json.JSONDecodeError as exc:
            raise ValueError("parameters_json must be valid JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("parameters_json must encode an object")
        canonical = canonical_dumps(parsed).decode("utf-8")
        if canonical != self.parameters_json:
            raise ValueError("parameters_json must use canonical JSON encoding")
        if any(not assumption.strip() for assumption in self.assumptions):
            raise ValueError("assumptions must contain only non-empty strings")
        return self

    @property
    def parameters(self) -> dict[str, Any]:
        value = json.loads(self.parameters_json)
        if not isinstance(value, dict):
            raise TypeError("canonical transformation parameters must be an object")
        return value

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def transformation_spec_for_callable(
    transform: TransformationFn,
    *,
    transformation_id: str,
    family: str,
    version: str,
    assumptions: Sequence[str],
    parameters: Mapping[str, Any] | None = None,
) -> TransformationSpec:
    """Build a spec that binds the callable source and canonical parameters."""
    return TransformationSpec(
        transformation_id=transformation_id,
        family=family,
        version=version,
        implementation_digest=_callable_implementation_digest(transform),
        parameters_json=canonical_dumps(dict(parameters or {})).decode("utf-8"),
        assumptions=tuple(assumptions),
    )


_TRANSFORMATION_REGISTRY: dict[str, tuple[TransformationSpec, TransformationFn]] = {}


def register_transformation(spec: TransformationSpec, transform: TransformationFn) -> None:
    """Register an exact transformation implementation under its stable id."""
    actual = _callable_implementation_digest(transform)
    if actual != spec.implementation_digest:
        raise ValueError(
            "transformation implementation digest mismatch: "
            f"declared={spec.implementation_digest} actual={actual}"
        )
    if spec.transformation_id in _TRANSFORMATION_REGISTRY:
        raise ValueError(f"transformation_id already registered: {spec.transformation_id}")
    _TRANSFORMATION_REGISTRY[spec.transformation_id] = (spec, transform)


def get_registered_transformation(
    transformation_id: str,
) -> tuple[TransformationSpec, TransformationFn]:
    if transformation_id not in _TRANSFORMATION_REGISTRY:
        raise KeyError(f"unknown transformation_id: {transformation_id}")
    return _TRANSFORMATION_REGISTRY[transformation_id]


def list_registered_transformations() -> dict[str, str]:
    """Return transformation ids mapped to their immutable spec digests."""
    return {key: spec.content_digest for key, (spec, _) in sorted(_TRANSFORMATION_REGISTRY.items())}


def user_alias_transform(
    trajectory: dict[str, Any],
    parameters: Mapping[str, Any],
) -> dict[str, Any]:
    """Canonical parameterized actor-alias transformation."""
    configured = parameters.get("user_map", DEFAULT_USER_REMAP)
    if not isinstance(configured, Mapping):
        raise ValueError("user_map parameter must be an object")
    user_map: dict[str, str] = {}
    for key, value in configured.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("user_map keys and values must be strings")
        user_map[key] = value
    return isomorphic_remap(trajectory, user_map=user_map)


class MetamorphicCounterexample(BaseModel):
    """Typed content-addressed failure witness without embedding raw inputs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: CounterexampleKind
    transformation_digest: str = Field(min_length=1)
    source_unit_digest: str = Field(min_length=1)
    original_digest: str = Field(min_length=1)
    transformed_digest: str = Field(min_length=1)
    gt_before: bool
    gt_after: bool
    verifier_before: bool | None
    verifier_after: bool | None

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class MetamorphicCaseEvidence(BaseModel):
    """Evidence for one source/transformed pair under a registered transform."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    transformation: TransformationSpec
    verifier_profile_digest: str = Field(min_length=1)
    source_unit_digest: str = Field(min_length=1)
    original_digest: str = Field(min_length=1)
    transformed_digest: str = Field(min_length=1)
    gt_before: bool
    gt_after: bool
    gt_invariant: bool
    verifier_before: bool | None
    verifier_after: bool | None
    verifier_invariant: bool | None
    status: MetamorphicStatus
    counterexample: MetamorphicCounterexample | None = None
    qualification_grade: Literal[False] = False
    claim_boundary: Literal[
        "registered_pairwise_invariance_evidence_no_population_robustness_claim"
    ] = "registered_pairwise_invariance_evidence_no_population_robustness_claim"

    @model_validator(mode="after")
    def _status_consistency(self) -> MetamorphicCaseEvidence:
        if not self.gt_invariant and self.status != "invalid_transform":
            raise ValueError("non-invariant ground truth must be invalid_transform")
        if self.status == "consistent" and self.verifier_invariant is not True:
            raise ValueError("consistent status requires verifier_invariant=true")
        if self.status == "verifier_violation" and self.verifier_invariant is not False:
            raise ValueError("verifier_violation requires verifier_invariant=false")
        if self.status == "indeterminate" and self.verifier_invariant is not None:
            raise ValueError("indeterminate status requires verifier_invariant=null")
        if (
            self.status in {"verifier_violation", "invalid_transform", "indeterminate"}
            and self.counterexample is None
        ):
            raise ValueError(f"{self.status} requires typed counterexample evidence")
        if self.status == "consistent" and self.counterexample is not None:
            raise ValueError("consistent evidence cannot carry a counterexample")
        return self

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class InvalidMetamorphicTransformation(ValueError):
    """Raised when a declared invariant is false for a generated pair."""

    def __init__(self, evidence: MetamorphicCaseEvidence) -> None:
        self.evidence = evidence
        super().__init__(
            "registered transformation violated its ground-truth invariant: "
            f"transformation={evidence.transformation.transformation_id} "
            f"source={evidence.source_unit_digest}"
        )


def _counterexample(
    *,
    kind: CounterexampleKind,
    spec: TransformationSpec,
    source_unit_digest: str,
    original_digest: str,
    transformed_digest: str,
    gt_before: bool,
    gt_after: bool,
    verifier_before: bool | None,
    verifier_after: bool | None,
) -> MetamorphicCounterexample:
    return MetamorphicCounterexample(
        kind=kind,
        transformation_digest=spec.content_digest,
        source_unit_digest=source_unit_digest,
        original_digest=original_digest,
        transformed_digest=transformed_digest,
        gt_before=gt_before,
        gt_after=gt_after,
        verifier_before=verifier_before,
        verifier_after=verifier_after,
    )


def evaluate_registered_transformation(
    spec: TransformationSpec,
    transform: TransformationFn,
    trajectory: dict[str, Any],
    *,
    verifier: Callable[[dict[str, Any]], Any],
    is_valid: Callable[[dict[str, Any]], bool],
    verifier_profile_digest: str,
    source_unit_digest: str | None = None,
    fail_on_invalid_transform: bool = True,
) -> MetamorphicCaseEvidence:
    """Evaluate one registered pair while preserving indeterminate decisions.

    The transform implementation must match the digest declared by ``spec``.
    Ground-truth invariance is checked before verifier invariance is interpreted.
    By default a false transformation invariant raises with the typed evidence
    attached, so it cannot be accidentally counted as a verifier failure.
    """
    from verifierlab.api.verifier import normalize_decision

    actual_implementation = _callable_implementation_digest(transform)
    if actual_implementation != spec.implementation_digest:
        raise ValueError(
            "transformation implementation digest mismatch: "
            f"declared={spec.implementation_digest} actual={actual_implementation}"
        )

    original = deepcopy(trajectory)
    transformed = transform(deepcopy(trajectory), spec.parameters)
    original_digest = digest_of(original)
    transformed_digest = digest_of(transformed)
    unit_digest = source_unit_digest or original_digest

    gt_before = bool(is_valid(original))
    gt_after = bool(is_valid(transformed))

    if gt_before != gt_after:
        counterexample = _counterexample(
            kind="ground_truth_invariance_violation",
            spec=spec,
            source_unit_digest=unit_digest,
            original_digest=original_digest,
            transformed_digest=transformed_digest,
            gt_before=gt_before,
            gt_after=gt_after,
            verifier_before=None,
            verifier_after=None,
        )
        evidence = MetamorphicCaseEvidence(
            transformation=spec,
            verifier_profile_digest=verifier_profile_digest,
            source_unit_digest=unit_digest,
            original_digest=original_digest,
            transformed_digest=transformed_digest,
            gt_before=gt_before,
            gt_after=gt_after,
            gt_invariant=False,
            verifier_before=None,
            verifier_after=None,
            verifier_invariant=None,
            status="invalid_transform",
            counterexample=counterexample,
        )
        if fail_on_invalid_transform:
            raise InvalidMetamorphicTransformation(evidence)
        return evidence

    verifier_before = normalize_decision(verifier(original)).accepted
    verifier_after = normalize_decision(verifier(transformed)).accepted

    if verifier_before is None or verifier_after is None:
        counterexample = _counterexample(
            kind="verifier_decision_indeterminate",
            spec=spec,
            source_unit_digest=unit_digest,
            original_digest=original_digest,
            transformed_digest=transformed_digest,
            gt_before=gt_before,
            gt_after=gt_after,
            verifier_before=verifier_before,
            verifier_after=verifier_after,
        )
        return MetamorphicCaseEvidence(
            transformation=spec,
            verifier_profile_digest=verifier_profile_digest,
            source_unit_digest=unit_digest,
            original_digest=original_digest,
            transformed_digest=transformed_digest,
            gt_before=gt_before,
            gt_after=gt_after,
            gt_invariant=True,
            verifier_before=verifier_before,
            verifier_after=verifier_after,
            verifier_invariant=None,
            status="indeterminate",
            counterexample=counterexample,
        )

    verifier_invariant = verifier_before == verifier_after
    if verifier_invariant:
        return MetamorphicCaseEvidence(
            transformation=spec,
            verifier_profile_digest=verifier_profile_digest,
            source_unit_digest=unit_digest,
            original_digest=original_digest,
            transformed_digest=transformed_digest,
            gt_before=gt_before,
            gt_after=gt_after,
            gt_invariant=True,
            verifier_before=verifier_before,
            verifier_after=verifier_after,
            verifier_invariant=True,
            status="consistent",
        )

    counterexample = _counterexample(
        kind="verifier_invariance_violation",
        spec=spec,
        source_unit_digest=unit_digest,
        original_digest=original_digest,
        transformed_digest=transformed_digest,
        gt_before=gt_before,
        gt_after=gt_after,
        verifier_before=verifier_before,
        verifier_after=verifier_after,
    )
    return MetamorphicCaseEvidence(
        transformation=spec,
        verifier_profile_digest=verifier_profile_digest,
        source_unit_digest=unit_digest,
        original_digest=original_digest,
        transformed_digest=transformed_digest,
        gt_before=gt_before,
        gt_after=gt_after,
        gt_invariant=True,
        verifier_before=verifier_before,
        verifier_after=verifier_after,
        verifier_invariant=False,
        status="verifier_violation",
        counterexample=counterexample,
    )


class MetamorphicSuiteArtifact(BaseModel):
    """A group of pairwise results for one exact transform and verifier."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    transformation: TransformationSpec
    verifier_profile_digest: str = Field(min_length=1)
    cases: tuple[MetamorphicCaseEvidence, ...]
    case_count: int = Field(ge=0)
    consistent_count: int = Field(ge=0)
    verifier_violation_count: int = Field(ge=0)
    indeterminate_count: int = Field(ge=0)
    invalid_transform_count: int = Field(ge=0)
    qualification_grade: Literal[False] = False
    claim_boundary: Literal[
        "registered_metamorphic_suite_descriptive_no_population_robustness_claim"
    ] = "registered_metamorphic_suite_descriptive_no_population_robustness_claim"

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def compile_metamorphic_suite(
    spec: TransformationSpec,
    *,
    verifier_profile_digest: str,
    cases: Sequence[MetamorphicCaseEvidence],
) -> MetamorphicSuiteArtifact:
    """Compile exact pair evidence without inventing population-level inference."""
    seen_units: set[str] = set()
    normalized: list[MetamorphicCaseEvidence] = []
    for case in cases:
        if case.transformation.content_digest != spec.content_digest:
            raise ValueError("metamorphic suite contains a different transformation spec")
        if case.verifier_profile_digest != verifier_profile_digest:
            raise ValueError("metamorphic suite contains a different verifier profile")
        if case.source_unit_digest in seen_units:
            raise ValueError(f"duplicate source_unit_digest: {case.source_unit_digest}")
        seen_units.add(case.source_unit_digest)
        normalized.append(case)

    normalized.sort(key=lambda item: item.source_unit_digest)
    return MetamorphicSuiteArtifact(
        transformation=spec,
        verifier_profile_digest=verifier_profile_digest,
        cases=tuple(normalized),
        case_count=len(normalized),
        consistent_count=sum(case.status == "consistent" for case in normalized),
        verifier_violation_count=sum(case.status == "verifier_violation" for case in normalized),
        indeterminate_count=sum(case.status == "indeterminate" for case in normalized),
        invalid_transform_count=sum(case.status == "invalid_transform" for case in normalized),
    )


def cosmetic_field_transform(
    trajectory: dict[str, Any],
    parameters: Mapping[str, Any],
) -> dict[str, Any]:
    """Flip cosmetic note/display fields without changing authorization semantics."""
    prefix = str(parameters.get("prefix", "cosmetic:"))
    out = deepcopy(trajectory)
    new_steps: list[dict[str, Any]] = []
    for step in out.get("steps") or []:
        if not isinstance(step, dict):
            new_steps.append(step)
            continue
        s = dict(step)
        if "note" in s:
            s["note"] = f"{prefix}{s['note']}"
        else:
            s["note"] = f"{prefix}surface"
        if "display" in s:
            s["display"] = f"{prefix}{s['display']}"
        new_steps.append(s)
    out["steps"] = new_steps
    out["cosmetic_transform"] = True
    return out


def amount_boundary_transform(
    trajectory: dict[str, Any],
    parameters: Mapping[str, Any],
) -> dict[str, Any]:
    """Shift refund amounts to declared boundaries while preserving op semantics.

    When ``preserve_validity_class`` is true (default), amounts stay within the
    same declared validity band so GT invariance can hold for planted fixtures.
    """
    boundaries = parameters.get("boundaries", [0, 1, 99, 100, 101])
    if not isinstance(boundaries, Sequence) or isinstance(boundaries, str | bytes):
        raise ValueError("boundaries must be a sequence of integers")
    band_max = int(parameters.get("authorized_max", 100))
    preserve = bool(parameters.get("preserve_validity_class", True))
    out = deepcopy(trajectory)
    new_steps: list[dict[str, Any]] = []
    for step in out.get("steps") or []:
        if not isinstance(step, dict):
            new_steps.append(step)
            continue
        s = dict(step)
        if s.get("op") == "refund" and "amount" in s:
            current = int(s["amount"])
            candidates = [int(b) for b in boundaries]
            if preserve:
                if current <= band_max:
                    candidates = [b for b in candidates if b <= band_max] or [band_max]
                else:
                    candidates = [b for b in candidates if b > band_max] or [band_max + 1]
            # Deterministic pick: nearest boundary in the filtered set.
            s["amount"] = min(candidates, key=lambda b: (abs(b - current), b))
            s["boundary_shift"] = True
        new_steps.append(s)
    out["steps"] = new_steps
    return out


class TransformQualityCalibration(BaseModel):
    """Calibration of transform validity rate — separate from verifier conclusions.

    Suites with high invalid-transform rates cannot support verifier FAR/FRR
    claims. This artifact records that boundary explicitly.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    transformation_digest: str = Field(min_length=1)
    suite_digest: str = Field(min_length=1)
    case_count: int = Field(ge=0)
    invalid_transform_count: int = Field(ge=0)
    invalid_transform_rate: float = Field(ge=0.0, le=1.0)
    maximum_invalid_rate_for_verifier_inference: float = Field(default=0.05, ge=0.0, le=1.0)
    supports_verifier_inference: bool
    reasons: tuple[str, ...] = ()
    claim_boundary: Literal["transform_quality_calibration_not_verifier_robustness"] = (
        "transform_quality_calibration_not_verifier_robustness"
    )

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def calibrate_transform_quality(
    suite: MetamorphicSuiteArtifact,
    *,
    maximum_invalid_rate_for_verifier_inference: float = 0.05,
) -> TransformQualityCalibration:
    """Derive transform-quality calibration from a compiled suite."""
    rate = suite.invalid_transform_count / suite.case_count if suite.case_count else 0.0
    reasons: list[str] = []
    supports = True
    if suite.case_count == 0:
        supports = False
        reasons.append("empty_suite")
    if rate > maximum_invalid_rate_for_verifier_inference:
        supports = False
        reasons.append(
            f"invalid_transform_rate={rate:.4f}>"
            f"maximum={maximum_invalid_rate_for_verifier_inference}"
        )
    if suite.invalid_transform_count > 0 and suite.verifier_violation_count > 0:
        # Mixed: still allow descriptive violation rates but flag inference risk.
        reasons.append("suite_contains_both_invalid_transforms_and_verifier_violations")
    return TransformQualityCalibration(
        transformation_digest=suite.transformation.content_digest,
        suite_digest=suite.content_digest,
        case_count=suite.case_count,
        invalid_transform_count=suite.invalid_transform_count,
        invalid_transform_rate=rate,
        maximum_invalid_rate_for_verifier_inference=maximum_invalid_rate_for_verifier_inference,
        supports_verifier_inference=supports,
        reasons=tuple(reasons),
    )


class MetamorphicEstimandSummary(BaseModel):
    """Preregistered metamorphic violation / indeterminate rates (descriptive)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    estimand_id: str = Field(min_length=1)
    metric: Literal["metamorphic_violation", "metamorphic_indeterminate"]
    transformation_digest: str = Field(min_length=1)
    verifier_profile_digest: str = Field(min_length=1)
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    estimate: float | None = None
    inferential: Literal[False] = False
    excluded_invalid_transforms: int = Field(ge=0)
    status: Literal["estimated", "indeterminate"]
    reasons: tuple[str, ...] = ()

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def summarize_metamorphic_estimands(
    suite: MetamorphicSuiteArtifact,
    *,
    estimand_id: str = "metamorphic_primary",
) -> tuple[MetamorphicEstimandSummary, MetamorphicEstimandSummary]:
    """Compute violation and indeterminate rates excluding invalid transforms.

    ``invalid_transform`` cases never enter the verifier-failure denominator.
    """
    usable = [case for case in suite.cases if case.status != "invalid_transform"]
    excluded = suite.invalid_transform_count
    denom = len(usable)
    violations = sum(case.status == "verifier_violation" for case in usable)
    indeterminates = sum(case.status == "indeterminate" for case in usable)
    reasons: list[str] = []
    if excluded:
        reasons.append(f"excluded_invalid_transforms={excluded}")
    status: Literal["estimated", "indeterminate"] = "estimated" if denom > 0 else "indeterminate"
    if denom == 0:
        reasons.append("no_usable_pairs_after_excluding_invalid_transforms")

    violation = MetamorphicEstimandSummary(
        estimand_id=f"{estimand_id}.violation",
        metric="metamorphic_violation",
        transformation_digest=suite.transformation.content_digest,
        verifier_profile_digest=suite.verifier_profile_digest,
        numerator=violations,
        denominator=denom,
        estimate=(violations / denom) if denom else None,
        excluded_invalid_transforms=excluded,
        status=status,
        reasons=tuple(reasons),
    )
    indeterminate = MetamorphicEstimandSummary(
        estimand_id=f"{estimand_id}.indeterminate",
        metric="metamorphic_indeterminate",
        transformation_digest=suite.transformation.content_digest,
        verifier_profile_digest=suite.verifier_profile_digest,
        numerator=indeterminates,
        denominator=denom,
        estimate=(indeterminates / denom) if denom else None,
        excluded_invalid_transforms=excluded,
        status=status,
        reasons=tuple(reasons),
    )
    return violation, indeterminate


def ensure_builtin_transformations_registered() -> dict[str, str]:
    """Idempotently register the built-in transformation catalogue."""
    catalogue: list[tuple[str, str, str, TransformationFn, dict[str, Any], tuple[str, ...]]] = [
        (
            "builtin.actor_alias.v1",
            "actor_alias",
            "1",
            user_alias_transform,
            {"user_map": dict(DEFAULT_USER_REMAP)},
            (
                "Configured actor aliases preserve authorization semantics for the fixture ontology.",
            ),
        ),
        (
            "builtin.cosmetic_fields.v1",
            "cosmetic_fields",
            "1",
            cosmetic_field_transform,
            {"prefix": "cosmetic:"},
            ("Cosmetic note/display fields are not part of ground-truth validity.",),
        ),
        (
            "builtin.amount_boundary.v1",
            "amount_boundary",
            "1",
            amount_boundary_transform,
            {
                "boundaries": [0, 1, 99, 100, 101],
                "authorized_max": 100,
                "preserve_validity_class": True,
            },
            ("Boundary shifts preserve the authorized/unauthorized amount class when configured.",),
        ),
    ]
    for transformation_id, family, version, fn, params, assumptions in catalogue:
        if transformation_id in _TRANSFORMATION_REGISTRY:
            continue
        spec = transformation_spec_for_callable(
            fn,
            transformation_id=transformation_id,
            family=family,
            version=version,
            assumptions=assumptions,
            parameters=params,
        )
        register_transformation(spec, fn)
    return list_registered_transformations()


__all__ = [
    "DEFAULT_USER_REMAP",
    "InvalidMetamorphicTransformation",
    "MetamorphicCaseEvidence",
    "MetamorphicCounterexample",
    "MetamorphicEstimandSummary",
    "MetamorphicSuiteArtifact",
    "TransformQualityCalibration",
    "TransformationFn",
    "TransformationSpec",
    "amount_boundary_transform",
    "assert_gt_invariance",
    "calibrate_transform_quality",
    "compile_metamorphic_suite",
    "cosmetic_field_transform",
    "ensure_builtin_transformations_registered",
    "evaluate_registered_transformation",
    "get_registered_transformation",
    "isomorphic_remap",
    "list_registered_transformations",
    "register_transformation",
    "summarize_metamorphic_estimands",
    "transformation_spec_for_callable",
    "user_alias_transform",
    "verifier_invariance_report",
]
