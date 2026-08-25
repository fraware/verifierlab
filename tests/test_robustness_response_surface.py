"""Tests for exact-coordinate robustness response surfaces."""

from __future__ import annotations

from typing import Any

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.statistics.response_surface import (
    AdjudicatedAttackBatch,
    RobustnessCoordinate,
    RobustnessResponseSurfacePlan,
    compile_robustness_response_surface,
)


def _coordinate(
    *,
    verifier: str = "v1",
    policy: str = "p1",
    budget: int = 20,
    access: str = "black-box",
    attack: str = "fuzz",
) -> RobustnessCoordinate:
    return RobustnessCoordinate.model_validate(
        {
            "verifier_profile_digest": digest_of(verifier),
            "policy_digest": digest_of(policy),
            "budget_queries": budget,
            "access_model": access,
            "attack_family": attack,
        }
    )


def _plan(*coordinates: RobustnessCoordinate, minimum: int = 10) -> RobustnessResponseSurfacePlan:
    return RobustnessResponseSurfacePlan(
        surface_id="surface-fixture",
        design_registration_digest=digest_of("registered-design"),
        required_coordinates=coordinates,
        minimum_trials_per_coordinate=minimum,
        alpha=0.05,
        interval_method="wilson",
    )


def _batch(
    coordinate: RobustnessCoordinate,
    *,
    run: str,
    n: int,
    exploits: int,
    queries: int | None = None,
    blockers: tuple[str, ...] = (),
) -> AdjudicatedAttackBatch:
    return AdjudicatedAttackBatch(
        coordinate=coordinate,
        run_digest=digest_of(run),
        attacker_instance_digest=digest_of(f"attacker:{run}"),
        results_digest=digest_of(f"results:{run}"),
        adjudication_digest=digest_of(f"adjudication:{run}"),
        holdout_commitment_digest=digest_of(f"holdout:{run}"),
        n_trials=n,
        exploit_count=exploits,
        queries_used=queries if queries is not None else coordinate.budget_queries,
        qualification_blockers=blockers,
    )


def test_surface_pools_only_exact_coordinate_replicates() -> None:
    c1 = _coordinate(budget=20, access="black-box", attack="fuzz")
    c2 = _coordinate(budget=20, access="gray-box", attack="fuzz")
    artifact = compile_robustness_response_surface(
        _plan(c1, c2, minimum=10),
        [
            _batch(c1, run="r1", n=10, exploits=2),
            _batch(c1, run="r2", n=10, exploits=4),
            _batch(c2, run="r3", n=10, exploits=8),
        ],
    )
    by_access = {cell.coordinate.access_model.value: cell for cell in artifact.cells}
    assert by_access["black-box"].n_trials == 20
    assert by_access["black-box"].exploit_count == 6
    assert by_access["black-box"].exploit_rate == pytest.approx(0.3)
    assert by_access["black-box"].interval is not None
    assert by_access["gray-box"].n_trials == 10
    assert by_access["gray-box"].exploit_rate == pytest.approx(0.8)
    assert artifact.complete_coordinate_count == 2
    assert artifact.qualification_grade is False


def test_missing_registered_coordinate_is_explicit() -> None:
    observed = _coordinate(policy="p1")
    missing = _coordinate(policy="p2")
    artifact = compile_robustness_response_surface(
        _plan(observed, missing, minimum=5),
        [_batch(observed, run="observed", n=5, exploits=1)],
    )
    cells = {cell.coordinate.policy_digest: cell for cell in artifact.cells}
    assert cells[missing.policy_digest].status == "missing"
    assert cells[missing.policy_digest].interval is None
    assert cells[missing.policy_digest].reasons == (
        "registered_coordinate_has_no_adjudicated_batch",
    )
    assert artifact.missing_coordinate_count == 1


def test_underpowered_coordinate_keeps_descriptive_rate_without_interval() -> None:
    coordinate = _coordinate()
    artifact = compile_robustness_response_surface(
        _plan(coordinate, minimum=20),
        [_batch(coordinate, run="small", n=7, exploits=3)],
    )
    cell = artifact.cells[0]
    assert cell.status == "indeterminate"
    assert cell.exploit_rate == pytest.approx(3 / 7)
    assert cell.interval is None
    assert cell.reasons == ("underpowered_coordinate:n=7<minimum=20",)


def test_source_blocker_prevents_inferential_interval() -> None:
    coordinate = _coordinate()
    artifact = compile_robustness_response_surface(
        _plan(coordinate, minimum=5),
        [
            _batch(
                coordinate,
                run="blocked",
                n=10,
                exploits=2,
                blockers=("execution_not_security_grade",),
            )
        ],
    )
    cell = artifact.cells[0]
    assert cell.status == "indeterminate"
    assert cell.exploit_rate == pytest.approx(0.2)
    assert cell.interval is None
    assert cell.reasons == ("source_blocker:execution_not_security_grade",)


def test_surface_rejects_unregistered_coordinates() -> None:
    registered = _coordinate(policy="registered")
    outside = _coordinate(policy="outside")
    with pytest.raises(ValueError, match="outside registered"):
        compile_robustness_response_surface(
            _plan(registered),
            [_batch(outside, run="outside", n=10, exploits=1)],
        )


def test_surface_rejects_duplicate_run_digest_across_batches() -> None:
    c1 = _coordinate(policy="p1")
    c2 = _coordinate(policy="p2")
    same = digest_of("same-run")
    b1 = _batch(c1, run="one", n=10, exploits=1).model_copy(update={"run_digest": same})
    b2 = _batch(c2, run="two", n=10, exploits=1).model_copy(update={"run_digest": same})
    with pytest.raises(ValueError, match="duplicate run_digest"):
        compile_robustness_response_surface(_plan(c1, c2), [b1, b2])


def test_batch_rejects_exploit_count_and_query_budget_violations() -> None:
    coordinate = _coordinate(budget=4)
    common: dict[str, Any] = {
        "coordinate": coordinate.model_dump(mode="json"),
        "run_digest": digest_of("run"),
        "attacker_instance_digest": digest_of("attacker"),
        "results_digest": digest_of("results"),
        "adjudication_digest": digest_of("adjudication"),
        "holdout_commitment_digest": digest_of("holdout"),
        "n_trials": 3,
        "exploit_count": 2,
        "queries_used": 4,
    }
    with pytest.raises(ValueError, match="cannot exceed"):
        AdjudicatedAttackBatch.model_validate({**common, "exploit_count": 4})
    with pytest.raises(ValueError, match="exceeds"):
        AdjudicatedAttackBatch.model_validate({**common, "queries_used": 5})


def test_plan_rejects_duplicate_coordinates() -> None:
    coordinate = _coordinate()
    with pytest.raises(ValueError, match="must be unique"):
        _plan(coordinate, coordinate)


def test_exact_interval_method_is_recorded() -> None:
    coordinate = _coordinate()
    plan = RobustnessResponseSurfacePlan(
        surface_id="exact",
        design_registration_digest=digest_of("design"),
        required_coordinates=(coordinate,),
        minimum_trials_per_coordinate=5,
        interval_method="exact",
    )
    artifact = compile_robustness_response_surface(
        plan,
        [_batch(coordinate, run="exact", n=10, exploits=1)],
    )
    interval = artifact.cells[0].interval
    assert interval is not None
    assert interval["method"] == "exact"


def test_surface_digest_is_order_invariant_for_batch_input() -> None:
    coordinate = _coordinate()
    plan = _plan(coordinate, minimum=5)
    a = _batch(coordinate, run="a", n=5, exploits=1)
    b = _batch(coordinate, run="b", n=5, exploits=2)
    left = compile_robustness_response_surface(plan, [a, b])
    right = compile_robustness_response_surface(plan, [b, a])
    assert left.content_digest == right.content_digest
    assert left.claim_boundary == "released_adjudication_exact_coordinate_surface_no_extrapolation"
