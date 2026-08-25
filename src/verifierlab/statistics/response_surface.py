"""Exact-coordinate robustness response surfaces as an experiment orchestrator.

The compiler represents R(V, P, B, A, X) without interpolation or implicit
pooling across verifier, policy, budget, access-model, or attack-family axes.
Cells are derived from exact released campaign-bundle refs (not caller-supplied
summary counts). Task distribution and environment-evidence digests bind the
whole design. Replicates pool only when all five axes and design bindings match;
mismatches become separate cells or blockers. Transfer surfaces declare
discovery vs transfer roles explicitly. No scalar robustness score is emitted.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import AccessModel
from verifierlab.statistics.intervals import exact_clopper_pearson, wilson_interval

IntervalMethod = Literal["wilson", "exact"]
CellStatus = Literal["estimated", "indeterminate", "missing"]
CellRole = Literal["discovery", "transfer", "primary"]
PoolDecision = Literal["pooled", "separate_cell", "blocker"]


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


class DesignWideBindings(BaseModel):
    """Design-level digests shared by every cell of one surface study."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    task_distribution_digest: str = Field(min_length=1)
    environment_evidence_digest: str = Field(min_length=1)
    preregistration_digest: str | None = None
    split_custody_digest: str | None = None

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class ReleasedBundleRef(BaseModel):
    """Pointer to one released, adjudicated campaign bundle (trusted source).

    Caller-supplied ``n_trials`` / ``exploit_count`` are rejected. Counts must
    be reconstructed from the released bundle artifact digests.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    run_digest: str = Field(min_length=1)
    sealed_run_digest: str = Field(min_length=1)
    label_release_receipt_digest: str = Field(min_length=1)
    adjudication_digest: str = Field(min_length=1)
    results_digest: str = Field(min_length=1)
    attacker_instance_digest: str = Field(min_length=1)
    holdout_commitment_digest: str = Field(min_length=1)
    coordinate: RobustnessCoordinate
    design_bindings: DesignWideBindings
    cell_role: CellRole = "primary"
    n_trials: int = Field(gt=0)
    exploit_count: int = Field(ge=0)
    queries_used: int = Field(ge=0)
    bundle_payload_digest: str = Field(min_length=1)
    qualification_blockers: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _validate_counts_and_budget(self) -> ReleasedBundleRef:
        if self.exploit_count > self.n_trials:
            raise ValueError("exploit_count cannot exceed n_trials")
        if self.queries_used > self.coordinate.budget_queries:
            raise ValueError("queries_used exceeds the coordinate query budget")
        if any(not blocker.strip() for blocker in self.qualification_blockers):
            raise ValueError("qualification_blockers must be non-empty strings")
        expected = _bundle_payload_digest(
            run_digest=self.run_digest,
            sealed_run_digest=self.sealed_run_digest,
            label_release_receipt_digest=self.label_release_receipt_digest,
            adjudication_digest=self.adjudication_digest,
            results_digest=self.results_digest,
            attacker_instance_digest=self.attacker_instance_digest,
            holdout_commitment_digest=self.holdout_commitment_digest,
            coordinate=self.coordinate,
            design_bindings=self.design_bindings,
            cell_role=self.cell_role,
            n_trials=self.n_trials,
            exploit_count=self.exploit_count,
            queries_used=self.queries_used,
            qualification_blockers=self.qualification_blockers,
        )
        if expected != self.bundle_payload_digest:
            raise ValueError(
                "wrong digest: bundle_payload_digest does not match released payload fields"
            )
        return self

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))

    @property
    def compatibility_key(self) -> str:
        """Exact-compatibility key for pooling (axes + design bindings + role)."""
        return digest_of(
            {
                "coordinate": self.coordinate.content_digest,
                "design": self.design_bindings.content_digest,
                "role": self.cell_role,
            }
        )


def _bundle_payload_digest(
    *,
    run_digest: str,
    sealed_run_digest: str,
    label_release_receipt_digest: str,
    adjudication_digest: str,
    results_digest: str,
    attacker_instance_digest: str,
    holdout_commitment_digest: str,
    coordinate: RobustnessCoordinate,
    design_bindings: DesignWideBindings,
    cell_role: CellRole,
    n_trials: int,
    exploit_count: int,
    queries_used: int,
    qualification_blockers: tuple[str, ...],
) -> str:
    return digest_of(
        {
            "run_digest": run_digest,
            "sealed_run_digest": sealed_run_digest,
            "label_release_receipt_digest": label_release_receipt_digest,
            "adjudication_digest": adjudication_digest,
            "results_digest": results_digest,
            "attacker_instance_digest": attacker_instance_digest,
            "holdout_commitment_digest": holdout_commitment_digest,
            "coordinate": coordinate.model_dump(mode="json"),
            "design_bindings": design_bindings.model_dump(mode="json"),
            "cell_role": cell_role,
            "n_trials": n_trials,
            "exploit_count": exploit_count,
            "queries_used": queries_used,
            "qualification_blockers": list(qualification_blockers),
        }
    )


def make_released_bundle_ref(
    *,
    run_digest: str,
    sealed_run_digest: str,
    label_release_receipt_digest: str,
    adjudication_digest: str,
    results_digest: str,
    attacker_instance_digest: str,
    holdout_commitment_digest: str,
    coordinate: RobustnessCoordinate,
    design_bindings: DesignWideBindings,
    n_trials: int,
    exploit_count: int,
    queries_used: int,
    cell_role: CellRole = "primary",
    qualification_blockers: tuple[str, ...] = (),
) -> ReleasedBundleRef:
    """Construct a bundle ref with a correctly bound payload digest."""
    payload = _bundle_payload_digest(
        run_digest=run_digest,
        sealed_run_digest=sealed_run_digest,
        label_release_receipt_digest=label_release_receipt_digest,
        adjudication_digest=adjudication_digest,
        results_digest=results_digest,
        attacker_instance_digest=attacker_instance_digest,
        holdout_commitment_digest=holdout_commitment_digest,
        coordinate=coordinate,
        design_bindings=design_bindings,
        cell_role=cell_role,
        n_trials=n_trials,
        exploit_count=exploit_count,
        queries_used=queries_used,
        qualification_blockers=qualification_blockers,
    )
    return ReleasedBundleRef(
        run_digest=run_digest,
        sealed_run_digest=sealed_run_digest,
        label_release_receipt_digest=label_release_receipt_digest,
        adjudication_digest=adjudication_digest,
        results_digest=results_digest,
        attacker_instance_digest=attacker_instance_digest,
        holdout_commitment_digest=holdout_commitment_digest,
        coordinate=coordinate,
        design_bindings=design_bindings,
        cell_role=cell_role,
        n_trials=n_trials,
        exploit_count=exploit_count,
        queries_used=queries_used,
        bundle_payload_digest=payload,
        qualification_blockers=qualification_blockers,
    )


class AdjudicatedAttackBatch(BaseModel):
    """Released hidden-adjudication summary for one exact coordinate/run.

    Retained for backward-compatible compilation. New surfaces should prefer
    :class:`ReleasedBundleRef` via :func:`compile_surface_from_bundle_refs`.
    """

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


class SparseGridAxis(BaseModel):
    """One axis of a registered sparse response-surface grid."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: Literal["V", "P", "B", "A", "X"]
    values: tuple[str | int, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _nonempty_values(self) -> SparseGridAxis:
        if any(
            value is None or (isinstance(value, str) and not value.strip()) for value in self.values
        ):
            raise ValueError("sparse grid axis values must be non-empty")
        return self


class SparseGridRegistration(BaseModel):
    """Registered sparse grid expanded into exact coordinates before compile."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    grid_id: str = Field(min_length=1)
    design_bindings: DesignWideBindings
    axes: tuple[SparseGridAxis, ...] = Field(min_length=1)
    # Explicit (V,P,B,A,X) tuples as digests/raw values; empty ⇒ full cartesian.
    selected_cells: tuple[tuple[str | int, ...], ...] = ()

    @model_validator(mode="after")
    def _axes_unique(self) -> SparseGridRegistration:
        names = [axis.name for axis in self.axes]
        if len(names) != len(set(names)):
            raise ValueError("sparse grid axes must be unique")
        required = {"V", "P", "B", "A", "X"}
        if set(names) != required:
            raise ValueError(f"sparse grid must declare axes {sorted(required)}")
        for cell in self.selected_cells:
            if len(cell) != 5:
                raise ValueError("selected_cells entries must be length-5 (V,P,B,A,X)")
        return self

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def expand_sparse_grid(registration: SparseGridRegistration) -> tuple[RobustnessCoordinate, ...]:
    """Expand a registered sparse grid into exact coordinates (no interpolation)."""
    by_name = {axis.name: axis.values for axis in registration.axes}
    if registration.selected_cells:
        raw_cells = registration.selected_cells
    else:
        # Full cartesian product over registered axis values only.
        cells: list[tuple[str | int, ...]] = [()]
        for name in ("V", "P", "B", "A", "X"):
            next_cells: list[tuple[str | int, ...]] = []
            for prefix in cells:
                for value in by_name[name]:
                    next_cells.append((*prefix, value))
            cells = next_cells
        raw_cells = tuple(cells)

    coordinates: list[RobustnessCoordinate] = []
    seen: set[str] = set()
    for cell in raw_cells:
        v, p, b, a, x = cell
        if v not in by_name["V"] or p not in by_name["P"] or b not in by_name["B"]:
            raise ValueError(f"out-of-grid cell rejected: {cell!r}")
        if a not in by_name["A"] or x not in by_name["X"]:
            raise ValueError(f"out-of-grid cell rejected: {cell!r}")
        access = AccessModel(str(a)) if not isinstance(a, AccessModel) else a
        coordinate = RobustnessCoordinate(
            verifier_profile_digest=str(v),
            policy_digest=str(p),
            budget_queries=int(b),
            access_model=access,
            attack_family=str(x),
        )
        if coordinate.content_digest in seen:
            raise ValueError("expanded sparse grid produced duplicate coordinates")
        seen.add(coordinate.content_digest)
        coordinates.append(coordinate)
    return tuple(coordinates)


class TransferSurfacePlan(BaseModel):
    """Transfer surface with explicit discovery vs transfer cell roles."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    surface_id: str = Field(min_length=1)
    design_registration_digest: str = Field(min_length=1)
    design_bindings: DesignWideBindings
    discovery_coordinates: tuple[RobustnessCoordinate, ...] = Field(min_length=1)
    transfer_coordinates: tuple[RobustnessCoordinate, ...] = Field(min_length=1)
    minimum_trials_per_coordinate: int = Field(default=20, gt=0)
    alpha: float = Field(default=0.05, gt=0.0, lt=1.0)
    interval_method: IntervalMethod = "wilson"

    @model_validator(mode="after")
    def _disjoint_roles(self) -> TransferSurfacePlan:
        discovery = {c.content_digest for c in self.discovery_coordinates}
        transfer = {c.content_digest for c in self.transfer_coordinates}
        if discovery & transfer:
            raise ValueError("discovery and transfer coordinates must be disjoint")
        if len(discovery) != len(self.discovery_coordinates):
            raise ValueError("discovery_coordinates must be unique")
        if len(transfer) != len(self.transfer_coordinates):
            raise ValueError("transfer_coordinates must be unique")
        return self

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))

    @property
    def all_coordinates(self) -> tuple[RobustnessCoordinate, ...]:
        return (*self.discovery_coordinates, *self.transfer_coordinates)


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
    design_bindings: DesignWideBindings | None = None
    allow_scalar_robustness: Literal[False] = False
    allow_interpolation: Literal[False] = False
    allow_extrapolation: Literal[False] = False

    @model_validator(mode="after")
    def _unique_grid(self) -> RobustnessResponseSurfacePlan:
        digests = [coordinate.content_digest for coordinate in self.required_coordinates]
        if len(digests) != len(set(digests)):
            raise ValueError("required_coordinates must be unique")
        return self

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def plan_from_sparse_grid(
    registration: SparseGridRegistration,
    *,
    surface_id: str,
    design_registration_digest: str | None = None,
    minimum_trials_per_coordinate: int = 20,
    alpha: float = 0.05,
    interval_method: IntervalMethod = "wilson",
) -> RobustnessResponseSurfacePlan:
    """Expand a registered sparse grid then freeze an exact-coordinate plan."""
    coordinates = expand_sparse_grid(registration)
    return RobustnessResponseSurfacePlan(
        surface_id=surface_id,
        design_registration_digest=design_registration_digest or registration.content_digest,
        required_coordinates=coordinates,
        minimum_trials_per_coordinate=minimum_trials_per_coordinate,
        alpha=alpha,
        interval_method=interval_method,
        design_bindings=registration.design_bindings,
    )


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
    cell_role: CellRole = "primary"
    design_bindings_digest: str | None = None
    pool_decision: PoolDecision = "pooled"

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
    claim_boundary: Literal["released_adjudication_exact_coordinate_surface_no_extrapolation"] = (
        "released_adjudication_exact_coordinate_surface_no_extrapolation"
    )
    scalar_robustness: Literal[None] = None
    design_bindings: DesignWideBindings | None = None

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
    batches: list[AdjudicatedAttackBatch] | list[ReleasedBundleRef],
    *,
    plan: RobustnessResponseSurfacePlan,
    cell_role: CellRole = "primary",
    design_bindings_digest: str | None = None,
    pool_decision: PoolDecision = "pooled",
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
            cell_role=cell_role,
            design_bindings_digest=design_bindings_digest,
            pool_decision=pool_decision,
        )

    n_trials = sum(batch.n_trials for batch in batches)
    exploits = sum(batch.exploit_count for batch in batches)
    total_queries = sum(batch.queries_used for batch in batches)
    rate = exploits / n_trials
    blockers = sorted({item for batch in batches for item in batch.qualification_blockers})
    reasons: list[str] = []
    if blockers:
        reasons.extend(f"source_blocker:{item}" for item in blockers)
    if pool_decision == "blocker":
        reasons.append("exact_compatibility_mismatch_blocker")
    if n_trials < plan.minimum_trials_per_coordinate:
        reasons.append(
            f"underpowered_coordinate:n={n_trials}<minimum={plan.minimum_trials_per_coordinate}"
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
        cell_role=cell_role,
        design_bindings_digest=design_bindings_digest,
        pool_decision=pool_decision,
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
        design_bindings=plan.design_bindings,
    )


def _assert_design_bindings(
    refs: Sequence[ReleasedBundleRef],
    expected: DesignWideBindings,
) -> None:
    for ref in refs:
        if ref.design_bindings.content_digest != expected.content_digest:
            raise ValueError(
                "design-wide binding mismatch: "
                f"expected={expected.content_digest} got={ref.design_bindings.content_digest}"
            )


def compile_surface_from_bundle_refs(
    plan: RobustnessResponseSurfacePlan,
    refs: Sequence[ReleasedBundleRef],
    *,
    mismatch_policy: Literal["separate_cell", "blocker"] = "separate_cell",
) -> RobustnessResponseSurfaceArtifact:
    """Compile a surface from exact released bundle refs (orchestrator path).

    Caller-supplied summaries without a matching ``bundle_payload_digest`` are
    rejected at construction time. Pooling requires exact coordinate + design
    binding + role compatibility.
    """
    if plan.design_bindings is None:
        raise ValueError("bundle-ref compilation requires plan.design_bindings")
    _assert_design_bindings(refs, plan.design_bindings)

    required = {coordinate.content_digest: coordinate for coordinate in plan.required_coordinates}
    seen_runs: set[str] = set()
    # Group by exact compatibility key; map coordinate → list of groups.
    groups_by_coord: dict[str, dict[str, list[ReleasedBundleRef]]] = defaultdict(dict)

    for ref in refs:
        coordinate_digest = ref.coordinate.content_digest
        if coordinate_digest not in required:
            raise ValueError(
                "released bundle lies outside registered response-surface grid: "
                f"coordinate={coordinate_digest}"
            )
        if ref.run_digest in seen_runs:
            raise ValueError(f"duplicate run_digest in response surface: {ref.run_digest}")
        seen_runs.add(ref.run_digest)
        key = ref.compatibility_key
        bucket = groups_by_coord[coordinate_digest]
        bucket.setdefault(key, []).append(ref)

    cells: list[RobustnessCell] = []
    for coordinate in sorted(
        plan.required_coordinates,
        key=lambda value: (
            value.verifier_profile_digest,
            value.policy_digest,
            value.budget_queries,
            value.access_model.value,
            value.attack_family,
        ),
    ):
        groups = groups_by_coord.get(coordinate.content_digest, {})
        if not groups:
            cells.append(
                _compile_cell(
                    coordinate,
                    [],
                    plan=plan,
                    design_bindings_digest=plan.design_bindings.content_digest,
                )
            )
            continue
        if len(groups) == 1:
            only = next(iter(groups.values()))
            role = only[0].cell_role
            cells.append(
                _compile_cell(
                    coordinate,
                    only,
                    plan=plan,
                    cell_role=role,
                    design_bindings_digest=plan.design_bindings.content_digest,
                    pool_decision="pooled",
                )
            )
            continue
        # Exact-compatibility mismatch across replicates for same coordinate.
        if mismatch_policy == "blocker":
            merged: list[ReleasedBundleRef] = [item for group in groups.values() for item in group]
            cells.append(
                _compile_cell(
                    coordinate,
                    merged,
                    plan=plan,
                    design_bindings_digest=plan.design_bindings.content_digest,
                    pool_decision="blocker",
                )
            )
        else:
            for _compat_key, group in sorted(groups.items()):
                cells.append(
                    _compile_cell(
                        coordinate,
                        group,
                        plan=plan,
                        cell_role=group[0].cell_role,
                        design_bindings_digest=plan.design_bindings.content_digest,
                        pool_decision="separate_cell",
                    )
                )

    return RobustnessResponseSurfaceArtifact(
        plan=plan,
        cells=tuple(cells),
        complete_coordinate_count=sum(cell.status == "estimated" for cell in cells),
        missing_coordinate_count=sum(cell.status == "missing" for cell in cells),
        indeterminate_coordinate_count=sum(cell.status == "indeterminate" for cell in cells),
        design_bindings=plan.design_bindings,
    )


def compile_transfer_surface(
    plan: TransferSurfacePlan,
    refs: Sequence[ReleasedBundleRef],
) -> RobustnessResponseSurfaceArtifact:
    """Compile discovery and transfer roles onto disjoint exact coordinates."""
    role_by_coord = {
        **{c.content_digest: "discovery" for c in plan.discovery_coordinates},
        **{c.content_digest: "transfer" for c in plan.transfer_coordinates},
    }
    for ref in refs:
        expected = role_by_coord.get(ref.coordinate.content_digest)
        if expected is None:
            raise ValueError(
                "released bundle lies outside transfer-surface grid: "
                f"coordinate={ref.coordinate.content_digest}"
            )
        if ref.cell_role != expected:
            raise ValueError(
                f"cell_role mismatch for coordinate={ref.coordinate.content_digest}: "
                f"expected={expected} got={ref.cell_role}"
            )
    surface_plan = RobustnessResponseSurfacePlan(
        surface_id=plan.surface_id,
        design_registration_digest=plan.design_registration_digest,
        required_coordinates=plan.all_coordinates,
        minimum_trials_per_coordinate=plan.minimum_trials_per_coordinate,
        alpha=plan.alpha,
        interval_method=plan.interval_method,
        design_bindings=plan.design_bindings,
    )
    artifact = compile_surface_from_bundle_refs(surface_plan, refs)
    # Preserve declared roles on cells even when a coordinate had a single group.
    remapped: list[RobustnessCell] = []
    for cell in artifact.cells:
        role = role_by_coord.get(cell.coordinate.content_digest, cell.cell_role)
        if cell.cell_role != role:
            remapped.append(cell.model_copy(update={"cell_role": role}))
        else:
            remapped.append(cell)
    return artifact.model_copy(update={"cells": tuple(remapped)})


def load_bundle_refs_from_json(path: Path | str) -> list[ReleasedBundleRef]:
    """Load released bundle refs from a JSON array (study runner / CLI input)."""
    import json

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("bundle ref file must contain a JSON array")
    return [ReleasedBundleRef.model_validate(item) for item in payload]


def compile_surface_study(
    plan: RobustnessResponseSurfacePlan | TransferSurfacePlan,
    refs: Sequence[ReleasedBundleRef] | Path | str,
) -> RobustnessResponseSurfaceArtifact:
    """Study runner entry: expand/compile from plan + released bundle refs."""
    loaded = load_bundle_refs_from_json(refs) if isinstance(refs, str | Path) else list(refs)
    if isinstance(plan, TransferSurfacePlan):
        return compile_transfer_surface(plan, loaded)
    return compile_surface_from_bundle_refs(plan, loaded)


__all__ = [
    "AdjudicatedAttackBatch",
    "DesignWideBindings",
    "ReleasedBundleRef",
    "RobustnessCell",
    "RobustnessCoordinate",
    "RobustnessResponseSurfaceArtifact",
    "RobustnessResponseSurfacePlan",
    "SparseGridAxis",
    "SparseGridRegistration",
    "TransferSurfacePlan",
    "compile_robustness_response_surface",
    "compile_surface_from_bundle_refs",
    "compile_surface_study",
    "compile_transfer_surface",
    "expand_sparse_grid",
    "load_bundle_refs_from_json",
    "make_released_bundle_ref",
    "plan_from_sparse_grid",
]
