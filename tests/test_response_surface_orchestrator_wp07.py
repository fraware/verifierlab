"""WP-07: response surface as executable study compiler."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.statistics.response_surface import (
    DesignWideBindings,
    ReleasedBundleRef,
    RobustnessCoordinate,
    RobustnessResponseSurfacePlan,
    SparseGridAxis,
    SparseGridRegistration,
    TransferSurfacePlan,
    compile_surface_from_bundle_refs,
    compile_surface_study,
    compile_transfer_surface,
    expand_sparse_grid,
    make_released_bundle_ref,
    plan_from_sparse_grid,
)


def _bindings() -> DesignWideBindings:
    return DesignWideBindings(
        task_distribution_digest=digest_of("tasks-v1"),
        environment_evidence_digest=digest_of("env-v1"),
        preregistration_digest=digest_of("prereg-v1"),
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


def _ref(
    coordinate: RobustnessCoordinate,
    *,
    run: str,
    n: int,
    exploits: int,
    role: str = "primary",
    bindings: DesignWideBindings | None = None,
    blockers: tuple[str, ...] = (),
) -> ReleasedBundleRef:
    return make_released_bundle_ref(
        run_digest=digest_of(run),
        sealed_run_digest=digest_of(f"sealed:{run}"),
        label_release_receipt_digest=digest_of(f"receipt:{run}"),
        adjudication_digest=digest_of(f"adj:{run}"),
        results_digest=digest_of(f"results:{run}"),
        attacker_instance_digest=digest_of(f"attacker:{run}"),
        holdout_commitment_digest=digest_of(f"holdout:{run}"),
        coordinate=coordinate,
        design_bindings=bindings or _bindings(),
        n_trials=n,
        exploit_count=exploits,
        queries_used=min(n, coordinate.budget_queries),
        cell_role=role,  # type: ignore[arg-type]
        qualification_blockers=blockers,
    )


def _plan(*coordinates: RobustnessCoordinate, minimum: int = 10) -> RobustnessResponseSurfacePlan:
    return RobustnessResponseSurfacePlan(
        surface_id="surface-orchestrator",
        design_registration_digest=digest_of("registered-design"),
        required_coordinates=coordinates,
        minimum_trials_per_coordinate=minimum,
        design_bindings=_bindings(),
    )


def test_wrong_bundle_payload_digest_rejected() -> None:
    coordinate = _coordinate()
    good = _ref(coordinate, run="good", n=10, exploits=1)
    with pytest.raises(ValueError, match="wrong digest"):
        ReleasedBundleRef.model_validate(
            {
                **good.model_dump(mode="json"),
                "bundle_payload_digest": digest_of("tampered"),
            }
        )


def test_out_of_grid_cell_rejected_on_sparse_expand() -> None:
    registration = SparseGridRegistration(
        grid_id="g1",
        design_bindings=_bindings(),
        axes=(
            SparseGridAxis(name="V", values=(digest_of("v1"),)),
            SparseGridAxis(name="P", values=(digest_of("p1"),)),
            SparseGridAxis(name="B", values=(10, 20)),
            SparseGridAxis(name="A", values=("black-box",)),
            SparseGridAxis(name="X", values=("fuzz",)),
        ),
        selected_cells=((digest_of("v1"), digest_of("p1"), 99, "black-box", "fuzz"),),
    )
    with pytest.raises(ValueError, match="out-of-grid"):
        expand_sparse_grid(registration)


def test_underpowered_cell_has_no_inferential_interval() -> None:
    coordinate = _coordinate()
    artifact = compile_surface_from_bundle_refs(
        _plan(coordinate, minimum=20),
        [_ref(coordinate, run="small", n=7, exploits=3)],
    )
    cell = artifact.cells[0]
    assert cell.status == "indeterminate"
    assert cell.exploit_rate == pytest.approx(3 / 7)
    assert cell.interval is None
    assert "underpowered_coordinate" in cell.reasons[0]
    assert artifact.scalar_robustness is None


def test_surface_digest_order_invariant_for_bundle_refs() -> None:
    coordinate = _coordinate()
    plan = _plan(coordinate, minimum=5)
    a = _ref(coordinate, run="a", n=5, exploits=1)
    b = _ref(coordinate, run="b", n=5, exploits=2)
    left = compile_surface_study(plan, [a, b])
    right = compile_surface_study(plan, [b, a])
    assert left.content_digest == right.content_digest


def test_sparse_grid_expands_then_compiles() -> None:
    v = digest_of("v1")
    p = digest_of("p1")
    registration = SparseGridRegistration(
        grid_id="sparse",
        design_bindings=_bindings(),
        axes=(
            SparseGridAxis(name="V", values=(v,)),
            SparseGridAxis(name="P", values=(p,)),
            SparseGridAxis(name="B", values=(10,)),
            SparseGridAxis(name="A", values=("black-box", "gray-box")),
            SparseGridAxis(name="X", values=("fuzz",)),
        ),
        selected_cells=(
            (v, p, 10, "black-box", "fuzz"),
            (v, p, 10, "gray-box", "fuzz"),
        ),
    )
    plan = plan_from_sparse_grid(
        registration, surface_id="from-sparse", minimum_trials_per_coordinate=5
    )
    assert len(plan.required_coordinates) == 2
    black = next(c for c in plan.required_coordinates if c.access_model.value == "black-box")
    gray = next(c for c in plan.required_coordinates if c.access_model.value == "gray-box")
    artifact = compile_surface_from_bundle_refs(
        plan,
        [
            _ref(black, run="b1", n=5, exploits=1),
            _ref(gray, run="g1", n=5, exploits=2),
        ],
    )
    assert artifact.complete_coordinate_count == 2
    assert artifact.design_bindings is not None


def test_transfer_surface_keeps_discovery_and_transfer_roles() -> None:
    discovery = _coordinate(policy="discovery")
    transfer = _coordinate(policy="transfer")
    plan = TransferSurfacePlan(
        surface_id="transfer-surface",
        design_registration_digest=digest_of("xfer-design"),
        design_bindings=_bindings(),
        discovery_coordinates=(discovery,),
        transfer_coordinates=(transfer,),
        minimum_trials_per_coordinate=5,
    )
    artifact = compile_transfer_surface(
        plan,
        [
            _ref(discovery, run="d1", n=5, exploits=1, role="discovery"),
            _ref(transfer, run="t1", n=5, exploits=2, role="transfer"),
        ],
    )
    by_role = {cell.cell_role: cell for cell in artifact.cells}
    assert by_role["discovery"].n_trials == 5
    assert by_role["transfer"].exploit_count == 2


def test_design_binding_mismatch_rejected() -> None:
    coordinate = _coordinate()
    other = DesignWideBindings(
        task_distribution_digest=digest_of("other-tasks"),
        environment_evidence_digest=digest_of("env-v1"),
    )
    with pytest.raises(ValueError, match="design-wide binding mismatch"):
        compile_surface_from_bundle_refs(
            _plan(coordinate, minimum=5),
            [_ref(coordinate, run="misbind", n=5, exploits=1, bindings=other)],
        )


def test_compatibility_mismatch_separate_cell_or_blocker() -> None:
    coordinate = _coordinate()
    plan = _plan(coordinate, minimum=5)
    # Same coordinate but different cell roles ⇒ incompatible pool key.
    a = _ref(coordinate, run="disc", n=5, exploits=1, role="discovery")
    b = _ref(coordinate, run="xfer", n=5, exploits=1, role="transfer")
    separate = compile_surface_from_bundle_refs(plan, [a, b], mismatch_policy="separate_cell")
    assert len(separate.cells) == 2
    assert all(cell.pool_decision == "separate_cell" for cell in separate.cells)
    blocked = compile_surface_from_bundle_refs(plan, [a, b], mismatch_policy="blocker")
    assert len(blocked.cells) == 1
    assert blocked.cells[0].pool_decision == "blocker"
    assert blocked.cells[0].interval is None
    assert "exact_compatibility_mismatch_blocker" in blocked.cells[0].reasons


def test_cli_surface_compile_json(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from verifierlab.cli import app

    coordinate = _coordinate()
    plan = _plan(coordinate, minimum=5)
    refs = [_ref(coordinate, run="cli", n=5, exploits=1)]
    plan_path = tmp_path / "plan.json"
    refs_path = tmp_path / "refs.json"
    plan_path.write_text(json.dumps(plan.model_dump(mode="json"), indent=2), encoding="utf-8")
    refs_path.write_text(
        json.dumps([r.model_dump(mode="json") for r in refs], indent=2),
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["stats", "surface-compile", str(plan_path), "--refs", str(refs_path), "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["complete_coordinate_count"] == 1
    assert payload["scalar_robustness"] is None
