"""Exact-coordinate robustness response surfaces for adjudicated attack evidence.

The compiler represents R(V, P, B, A, X) without interpolation or implicit
pooling across verifier, policy, budget, access-model, or attack-family axes.
Only released adjudication summaries are accepted. Chronological
preregistration, trustworthy hidden-label custody, and experiment execution
must be established by external lifecycle artifacts.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import AccessModel
from verifierlab.statistics.intervals import exact_clopper_pearson, wilson_interval

IntervalMethod = Literal["wilson", "exact"]
CellStatus = Literal["estimated", "indeterminate", "missing"]


class RobustnessCoordinate(BaseModel):
    """One exact response-surface coordinate (V, P, B, A, X)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    verifier_profile_digest: str = Field(min_length=1)
    policy_digest: str = Field(min_length=1)
    budget_queries: int = Field(gt=0)
    access_model: AccessModel
    attack_family: str = Field(min_length=1)

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class AdjudicatedAttackBatch(BaseModel):
    """Released hidden-adjudication summary for one exact coordinate/run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    coordinate: RobustnessCoordinate
    run_digest: str = Field(min_length=1)
    attacker_instance_digest: str = Field(min_length=1)
    results_digest: str = Field(min_length=1)
    adjudication_digest: str = Field(min_length=1)
    holdout_commitment_digest: str = Field(min_length=1)
    labels_released: Literal[True] = True
    n_trials: int = Field(gt=0)
    exploit_count: int = Field(ge=0)
    queries_used: int = Field(ge=0)
    qualification_blockers: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _validate_counts_and_budget(self) -> AdjudicatedAttackBatch:
        if self.exploit_count > self.n_trials:
            raise ValueError("exploit_count cannot exceed n_trials")
        if self.queries_used > self.coordinate.budget_queries:
            raise ValueError("queries_used exceeds the coordinate query budget")
        if any(not blocker.strip() for blocker in self.qualification_blockers):
            raise ValueError("qualification_blockers must be non-empty strings")
        return self

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class RobustnessResponseSurfacePlan(BaseModel):
    """Frozen, explicit grid and inferential contract for the response surface."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    surface_id: str = Field(min_length=1)
    design_registration_digest: str = Field(min_length=1)
    required_coordinates: tuple[RobustnessCoordinate, ...] = Field(min_length=1)
    minimum_trials_per_coordinate: int = Field(default=20, gt=0)
    alpha: float = Field(default=0.05, gt=0.0, lt=1.0)
    interval_method: IntervalMethod = "wilson"

    @model_validator(mode="after")
    def _unique_grid(self) -> RobustnessResponseSurfacePlan:
        digests = [coordinate.content_digest for coordinate in self.required_coordinates]
        if len(digests) != len(set(digests)):
            raise ValueError("required_coordinates must be unique")
        return self

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class RobustnessCell(BaseModel):
    """Compiled evidence for one exact registered response-surface coordinate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    coordinate: RobustnessCoordinate
    status: CellStatus
    source_run_digests: tuple[str, ...]
    source_batch_digests: tuple[str, ...]
    n_trials: int = Field(ge=0)
    exploit_count: int = Field(ge=0)
    exploit_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    interval: dict[str, object] | None = None
    total_queries_used: int = Field(ge=0)
    reasons: tuple[str, ...] = ()

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class RobustnessResponseSurfaceArtifact(BaseModel):
    """Compiled grid with no extrapolation beyond the registered coordinates."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    plan: RobustnessResponseSurfacePlan
    cells: tuple[RobustnessCell, ...]
    complete_coordinate_count: int = Field(ge=0)
    missing_coordinate_count: int = Field(ge=0)
    indeterminate_coordinate_count: int = Field(ge=0)
    qualification_grade: Literal[False] = False
    claim_boundary: Literal[
        "released_adjudication_exact_coordinate_surface_no_extrapolation"
    ] = "released_adjudication_exact_coordinate_surface_no_extrapolation"

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def _interval(
    successes: int,
    n: int,
    *,
    method: IntervalMethod,
    alpha: float,
) -> dict[str, object]:
    if method == "wilson":
        value = wilson_interval(successes, n, alpha=alpha)
    else:
        value = exact_clopper_pearson(successes, n, alpha=alpha)
    return value.as_dict()


def _compile_cell(
    coordinate: RobustnessCoordinate,
    batches: list[AdjudicatedAttackBatch],
    *,
    plan: RobustnessResponseSurfacePlan,
) -> RobustnessCell:
    if not batches:
        return RobustnessCell(
            coordinate=coordinate,
            status="missing",
            source_run_digests=(),
            source_batch_digests=(),
            n_trials=0,
            exploit_count=0,
            exploit_rate=None,
            interval=None,
            total_queries_used=0,
            reasons=("registered_coordinate_has_no_adjudicated_batch",),
        )

    n_trials = sum(batch.n_trials for batch in batches)
    exploits = sum(batch.exploit_count for batch in batches)
    total_queries = sum(batch.queries_used for batch in batches)
    rate = exploits / n_trials
    blockers = sorted({item for batch in batches for item in batch.qualification_blockers})
    reasons: list[str] = []
    if blockers:
        reasons.extend(f"source_blocker:{item}" for item in blockers)
    if n_trials < plan.minimum_trials_per_coordinate:
        reasons.append(
            "underpowered_coordinate:"
            f"n={n_trials}<minimum={plan.minimum_trials_per_coordinate}"
        )

    status: CellStatus = "indeterminate" if reasons else "estimated"
    interval = (
        None
        if reasons
        else _interval(
            exploits,
            n_trials,
            method=plan.interval_method,
            alpha=plan.alpha,
        )
    )
    return RobustnessCell(
        coordinate=coordinate,
        status=status,
        source_run_digests=tuple(sorted(batch.run_digest for batch in batches)),
        source_batch_digests=tuple(sorted(batch.content_digest for batch in batches)),
        n_trials=n_trials,
        exploit_count=exploits,
        exploit_rate=rate,
        interval=interval,
        total_queries_used=total_queries,
        reasons=tuple(reasons),
    )


def compile_robustness_response_surface(
    plan: RobustnessResponseSurfacePlan,
    batches: list[AdjudicatedAttackBatch] | tuple[AdjudicatedAttackBatch, ...],
) -> RobustnessResponseSurfaceArtifact:
    """Compile released adjudication evidence onto the exact registered grid.

    Observations outside the registered design are rejected. Replicates are
    pooled only when all five coordinate dimensions are identical. Missing,
    underpowered, or source-blocked cells never receive an inferential interval.
    """
    required = {coordinate.content_digest: coordinate for coordinate in plan.required_coordinates}
    seen_runs: set[str] = set()
    grouped: dict[str, list[AdjudicatedAttackBatch]] = defaultdict(list)

    for batch in batches:
        coordinate_digest = batch.coordinate.content_digest
        if coordinate_digest not in required:
            raise ValueError(
                "adjudicated batch lies outside registered response-surface grid: "
                f"coordinate={coordinate_digest}"
            )
        if batch.run_digest in seen_runs:
            raise ValueError(f"duplicate run_digest in response surface: {batch.run_digest}")
        seen_runs.add(batch.run_digest)
        grouped[coordinate_digest].append(batch)

    cells = tuple(
        _compile_cell(coordinate, grouped.get(coordinate.content_digest, []), plan=plan)
        for coordinate in sorted(
            plan.required_coordinates,
            key=lambda value: (
                value.verifier_profile_digest,
                value.policy_digest,
                value.budget_queries,
                value.access_model.value,
                value.attack_family,
            ),
        )
    )
    return RobustnessResponseSurfaceArtifact(
        plan=plan,
        cells=cells,
        complete_coordinate_count=sum(cell.status == "estimated" for cell in cells),
        missing_coordinate_count=sum(cell.status == "missing" for cell in cells),
        indeterminate_coordinate_count=sum(cell.status == "indeterminate" for cell in cells),
    )


__all__ = [
    "AdjudicatedAttackBatch",
    "RobustnessCell",
    "RobustnessCoordinate",
    "RobustnessResponseSurfaceArtifact",
    "RobustnessResponseSurfacePlan",
    "compile_robustness_response_surface",
]
