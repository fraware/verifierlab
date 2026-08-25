"""Known planted-exploit calibration boundary and analysis tests."""

from __future__ import annotations

import json
from typing import Any

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.exploits.calibration import (
    CalibrationObservation,
    CalibrationPublicCommitment,
    CalibrationReleaseReceipt,
    CalibrationTruthItem,
    PlantedCalibrationDesign,
    make_calibration_public_commitment,
    verify_calibration_public_commitment,
)
from verifierlab.exploits.layers import FailureLayer
from verifierlab.exploits.taxonomy import ExploitClass
from verifierlab.statistics.calibration import (
    CalibrationAnalysisPlan,
    compile_planted_calibration_report,
)

NONCE = "post-run-opening-nonce"
PROFILE = digest_of("detector-profile")


def _plant(
    item_id: str,
    *,
    exploit_class: ExploitClass = ExploitClass.RUBRIC_GAMING,
    layer: FailureLayer = FailureLayer.SPECIFICATION,
    mechanism: str = "rubric-token-plant",
    difficulty: int = 2,
) -> CalibrationTruthItem:
    return CalibrationTruthItem(
        item_id=item_id,
        payload_digest=digest_of(f"payload:{item_id}"),
        kind="planted_exploit",
        exploit_class=exploit_class,
        failure_layer=layer,
        mechanism_id=mechanism,
        mechanism_version="1",
        difficulty_level=difficulty,
        difficulty_rationale=f"Fixture difficulty {difficulty} for {mechanism}.",
    )


def _clean(item_id: str) -> CalibrationTruthItem:
    return CalibrationTruthItem(
        item_id=item_id,
        payload_digest=digest_of(f"payload:{item_id}"),
        kind="clean_control",
    )


def _design(*items: CalibrationTruthItem) -> PlantedCalibrationDesign:
    selected = items or (
        _plant("plant-a"),
        _plant(
            "plant-b",
            exploit_class=ExploitClass.ISOMORPHIC_RELABEL,
            layer=FailureLayer.IMPLEMENTATION,
            mechanism="alias-sensitive-plant",
            difficulty=4,
        ),
        _clean("clean-a"),
        _clean("clean-b"),
    )
    return PlantedCalibrationDesign(
        calibration_id="calibration-fixture-v1",
        items=selected,
        custodian_identity_digest=digest_of("custodian"),
        assumptions=(
            "Fixture labels are exact by construction.",
            "Difficulty levels are declared calibration metadata, not empirical hardness estimates.",
        ),
    )


def _commitment(design: PlantedCalibrationDesign) -> CalibrationPublicCommitment:
    return make_calibration_public_commitment(design, commitment_nonce=NONCE)


def _release(
    design: PlantedCalibrationDesign,
    commitment: CalibrationPublicCommitment,
    *,
    nonce: str = NONCE,
) -> CalibrationReleaseReceipt:
    return CalibrationReleaseReceipt(
        calibration_id=design.calibration_id,
        public_commitment_digest=commitment.content_digest,
        released_design_digest=design.content_digest,
        adjudication_release_digest=digest_of("adjudication-release"),
        commitment_nonce=nonce,
    )


def _observation(
    item: CalibrationTruthItem,
    *,
    flagged: bool | None,
    run: str | None = None,
    profile: str = PROFILE,
) -> CalibrationObservation:
    run_name = run or item.item_id
    return CalibrationObservation(
        item_id=item.item_id,
        payload_digest=item.payload_digest,
        detector_profile_digest=profile,
        run_digest=digest_of(f"run:{run_name}"),
        detector_output_digest=digest_of(f"output:{run_name}:{flagged}"),
        flagged=flagged,
    )


def _plan(
    *,
    minimum_planted: int = 2,
    minimum_clean: int = 2,
    coverage: float = 1.0,
    method: str = "wilson",
) -> CalibrationAnalysisPlan:
    return CalibrationAnalysisPlan.model_validate(
        {
            "analysis_id": "calibration-analysis-v1",
            "registration_digest": digest_of("registered-calibration-analysis"),
            "minimum_planted_determinate": minimum_planted,
            "minimum_clean_determinate": minimum_clean,
            "minimum_determinate_fraction": coverage,
            "alpha": 0.05,
            "interval_method": method,
        }
    )


def test_design_requires_both_plants_and_clean_controls() -> None:
    with pytest.raises(ValueError, match="requires planted exploits and clean controls"):
        _design(_plant("plant-a"), _plant("plant-b"))
    with pytest.raises(ValueError, match="requires planted exploits and clean controls"):
        _design(_clean("clean-a"), _clean("clean-b"))


def test_design_rejects_duplicate_ids_and_payloads() -> None:
    plant = _plant("same")
    clean_same_id = CalibrationTruthItem(
        item_id="same",
        payload_digest=digest_of("different-payload"),
        kind="clean_control",
    )
    with pytest.raises(ValueError, match="item_id values must be unique"):
        _design(plant, clean_same_id)

    clean_same_payload = CalibrationTruthItem(
        item_id="other",
        payload_digest=plant.payload_digest,
        kind="clean_control",
    )
    with pytest.raises(ValueError, match="payload_digest values must be unique"):
        _design(plant, clean_same_payload)


def test_truth_item_shapes_fail_closed() -> None:
    with pytest.raises(ValueError, match="requires class, layer, mechanism"):
        CalibrationTruthItem(
            item_id="incomplete-plant",
            payload_digest=digest_of("incomplete"),
            kind="planted_exploit",
        )
    with pytest.raises(ValueError, match="clean_control cannot carry"):
        CalibrationTruthItem(
            item_id="contaminated-clean",
            payload_digest=digest_of("contaminated"),
            kind="clean_control",
            exploit_class=ExploitClass.RUBRIC_GAMING,
        )


def test_attack_plane_commitment_does_not_disclose_truth_fields() -> None:
    design = _design()
    commitment = _commitment(design)
    payload = commitment.model_dump(mode="json")
    serialized = json.dumps(payload, sort_keys=True)

    assert set(payload) == {
        "schema_version",
        "calibration_id",
        "salted_design_commitment",
        "item_count",
        "truth_withheld_from_attack_plane",
        "truth_fields_disclosed",
        "qualification_grade",
    }
    assert payload["truth_withheld_from_attack_plane"] is True
    assert payload["truth_fields_disclosed"] is False
    assert "planted_exploit" not in serialized
    assert "clean_control" not in serialized
    assert "rubric-token-plant" not in serialized
    assert "alias-sensitive-plant" not in serialized
    assert "specification" not in serialized
    assert "implementation" not in serialized
    assert "Fixture difficulty" not in serialized


def test_salted_commitment_changes_with_nonce_and_opens_exactly() -> None:
    design = _design()
    left = make_calibration_public_commitment(design, commitment_nonce="nonce-a")
    right = make_calibration_public_commitment(design, commitment_nonce="nonce-b")
    assert left.salted_design_commitment != right.salted_design_commitment
    verify_calibration_public_commitment(design, left, commitment_nonce="nonce-a")
    with pytest.raises(ValueError, match="does not open"):
        verify_calibration_public_commitment(design, left, commitment_nonce="nonce-b")
    with pytest.raises(ValueError, match="must be non-empty"):
        make_calibration_public_commitment(design, commitment_nonce="")


def test_tampered_design_does_not_open_existing_commitment() -> None:
    design = _design()
    commitment = _commitment(design)
    replacement = _plant(
        "plant-a",
        exploit_class=ExploitClass.RUBRIC_GAMING,
        layer=FailureLayer.ENVIRONMENT_ONTOLOGY,
        mechanism="rubric-token-plant",
        difficulty=2,
    )
    tampered = design.model_copy(update={"items": (replacement, *design.items[1:])})
    with pytest.raises(ValueError, match="does not open"):
        verify_calibration_public_commitment(tampered, commitment, commitment_nonce=NONCE)


def test_observation_schema_cannot_embed_hidden_truth() -> None:
    item = _plant("plant-a")
    payload: dict[str, Any] = {
        "item_id": item.item_id,
        "payload_digest": item.payload_digest,
        "detector_profile_digest": PROFILE,
        "run_digest": digest_of("run"),
        "detector_output_digest": digest_of("output"),
        "flagged": True,
        "exploit_class": ExploitClass.RUBRIC_GAMING.value,
    }
    with pytest.raises(ValueError):
        CalibrationObservation.model_validate(payload)


def test_released_report_computes_detection_and_false_alarm_metrics() -> None:
    design = _design()
    commitment = _commitment(design)
    release = _release(design, commitment)
    by_id = {item.item_id: item for item in design.items}
    observations = [
        _observation(by_id["plant-a"], flagged=True),
        _observation(by_id["plant-b"], flagged=False),
        _observation(by_id["clean-a"], flagged=True),
        _observation(by_id["clean-b"], flagged=False),
    ]
    report = compile_planted_calibration_report(
        design,
        commitment,
        release,
        observations,
        plan=_plan(),
    )
    assert report.status == "estimated"
    assert report.true_positive == 1
    assert report.false_negative == 1
    assert report.false_positive == 1
    assert report.true_negative == 1
    assert report.sensitivity.estimate == pytest.approx(0.5)
    assert report.false_negative_rate.estimate == pytest.approx(0.5)
    assert report.false_positive_rate.estimate == pytest.approx(0.5)
    assert report.specificity.estimate == pytest.approx(0.5)
    assert report.sensitivity.inferential is True
    assert report.sensitivity.interval is not None
    assert report.evidence_kind == "known_plant_calibration"
    assert report.supports_unknown_robustness_claim is False
    assert report.qualification_grade is False
    assert report.claim_boundary == (
        "known_plant_instrument_calibration_not_unknown_verifier_robustness"
    )


def test_strata_preserve_known_mechanism_layer_and_difficulty() -> None:
    design = _design()
    commitment = _commitment(design)
    release = _release(design, commitment)
    observations = [_observation(item, flagged=True) for item in design.items]
    report = compile_planted_calibration_report(
        design,
        commitment,
        release,
        observations,
        plan=_plan(),
    )
    assert len(report.strata) == 2
    signatures = {
        (
            stratum.exploit_class,
            stratum.failure_layer,
            stratum.mechanism_id,
            stratum.difficulty_level,
            stratum.detection_rate,
        )
        for stratum in report.strata
    }
    assert (
        ExploitClass.RUBRIC_GAMING,
        FailureLayer.SPECIFICATION,
        "rubric-token-plant",
        2,
        1.0,
    ) in signatures
    assert (
        ExploitClass.ISOMORPHIC_RELABEL,
        FailureLayer.IMPLEMENTATION,
        "alias-sensitive-plant",
        4,
        1.0,
    ) in signatures


def test_missing_and_indeterminate_outputs_reduce_coverage_without_coercion() -> None:
    design = _design()
    commitment = _commitment(design)
    release = _release(design, commitment)
    by_id = {item.item_id: item for item in design.items}
    observations = [
        _observation(by_id["plant-a"], flagged=None),
        _observation(by_id["clean-a"], flagged=False),
    ]
    report = compile_planted_calibration_report(
        design,
        commitment,
        release,
        observations,
        plan=_plan(minimum_planted=1, minimum_clean=1, coverage=0.75),
    )
    assert report.status == "indeterminate"
    assert report.observed_planted == 1
    assert report.missing_planted == 1
    assert report.indeterminate_planted == 1
    assert report.true_positive == 0
    assert report.false_negative == 0
    assert report.planted_determinate_fraction == 0.0
    assert report.sensitivity.estimate is None
    assert report.sensitivity.inferential is False
    assert report.sensitivity.interval is None
    assert report.missing_clean == 1
    assert report.clean_determinate_fraction == pytest.approx(0.5)
    assert report.false_positive_rate.inferential is False


def test_underpowered_report_keeps_estimates_but_suppresses_intervals() -> None:
    design = _design()
    commitment = _commitment(design)
    release = _release(design, commitment)
    observations = [
        _observation(item, flagged=item.kind == "planted_exploit") for item in design.items
    ]
    report = compile_planted_calibration_report(
        design,
        commitment,
        release,
        observations,
        plan=_plan(minimum_planted=10, minimum_clean=10, coverage=1.0),
    )
    assert report.status == "indeterminate"
    assert report.sensitivity.estimate == 1.0
    assert report.sensitivity.inferential is False
    assert report.sensitivity.interval is None
    assert report.false_positive_rate.estimate == 0.0
    assert report.false_positive_rate.inferential is False
    assert report.false_positive_rate.interval is None
    assert any(reason.startswith("underpowered_planted") for reason in report.reasons)
    assert any(reason.startswith("underpowered_clean") for reason in report.reasons)


def test_exact_interval_uses_existing_canonical_method_label() -> None:
    design = _design()
    commitment = _commitment(design)
    release = _release(design, commitment)
    observations = [
        _observation(item, flagged=item.kind == "planted_exploit") for item in design.items
    ]
    report = compile_planted_calibration_report(
        design,
        commitment,
        release,
        observations,
        plan=_plan(method="exact"),
    )
    assert report.sensitivity.interval is not None
    assert report.sensitivity.interval["method"] == "exact"


def test_release_and_observation_binding_fail_closed() -> None:
    design = _design()
    commitment = _commitment(design)
    release = _release(design, commitment)
    by_id = {item.item_id: item for item in design.items}
    observation = _observation(by_id["plant-a"], flagged=True)

    wrong_design_release = release.model_copy(update={"released_design_digest": digest_of("wrong")})
    with pytest.raises(ValueError, match="does not bind the supplied calibration design"):
        compile_planted_calibration_report(
            design,
            commitment,
            wrong_design_release,
            [observation],
            plan=_plan(minimum_planted=1, minimum_clean=1, coverage=0.1),
        )

    wrong_commitment_release = release.model_copy(
        update={"public_commitment_digest": digest_of("wrong")}
    )
    with pytest.raises(ValueError, match="does not bind the supplied public commitment"):
        compile_planted_calibration_report(
            design,
            commitment,
            wrong_commitment_release,
            [observation],
            plan=_plan(minimum_planted=1, minimum_clean=1, coverage=0.1),
        )

    wrong_nonce_release = release.model_copy(update={"commitment_nonce": "wrong"})
    with pytest.raises(ValueError, match="does not open"):
        compile_planted_calibration_report(
            design,
            commitment,
            wrong_nonce_release,
            [observation],
            plan=_plan(minimum_planted=1, minimum_clean=1, coverage=0.1),
        )

    bad_payload = observation.model_copy(update={"payload_digest": digest_of("wrong-payload")})
    with pytest.raises(ValueError, match="payload digest mismatch"):
        compile_planted_calibration_report(
            design,
            commitment,
            release,
            [bad_payload],
            plan=_plan(minimum_planted=1, minimum_clean=1, coverage=0.1),
        )


def test_out_of_design_duplicates_and_mixed_profiles_are_rejected() -> None:
    design = _design()
    commitment = _commitment(design)
    release = _release(design, commitment)
    by_id = {item.item_id: item for item in design.items}
    a = _observation(by_id["plant-a"], flagged=True, run="a")
    duplicate_item = _observation(by_id["plant-a"], flagged=False, run="b")
    with pytest.raises(ValueError, match="duplicate observation"):
        compile_planted_calibration_report(
            design, commitment, release, [a, duplicate_item], plan=_plan()
        )

    outside = CalibrationObservation(
        item_id="outside",
        payload_digest=digest_of("outside-payload"),
        detector_profile_digest=PROFILE,
        run_digest=digest_of("outside-run"),
        detector_output_digest=digest_of("outside-output"),
        flagged=True,
    )
    with pytest.raises(ValueError, match="outside calibration design"):
        compile_planted_calibration_report(design, commitment, release, [outside], plan=_plan())

    b = _observation(
        by_id["plant-b"],
        flagged=True,
        run="mixed-profile",
        profile=digest_of("other-profile"),
    )
    with pytest.raises(ValueError, match="one detector profile"):
        compile_planted_calibration_report(design, commitment, release, [a, b], plan=_plan())

    same_run = _observation(by_id["plant-b"], flagged=True, run="a")
    with pytest.raises(ValueError, match="duplicate calibration run_digest"):
        compile_planted_calibration_report(design, commitment, release, [a, same_run], plan=_plan())


def test_report_digest_is_observation_order_invariant() -> None:
    design = _design()
    commitment = _commitment(design)
    release = _release(design, commitment)
    observations = [
        _observation(item, flagged=item.kind == "planted_exploit") for item in design.items
    ]
    plan = _plan()
    left = compile_planted_calibration_report(
        design,
        commitment,
        release,
        observations,
        plan=plan,
    )
    right = compile_planted_calibration_report(
        design,
        commitment,
        release,
        list(reversed(observations)),
        plan=plan,
    )
    assert left.content_digest == right.content_digest
