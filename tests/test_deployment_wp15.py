"""WP-15 prospective deployment calibration tests."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.assurance.deployment import (
    DeploymentCalibrationPlan,
    build_calibration_report,
    ingest_outcome,
    register_prediction,
)
from verifierlab.assurance.maturity import AssuranceClaim
from verifierlab.assurance.resolver import qualify_run


def _pred_payload(*, synthetic: bool = True) -> dict:
    return {
        "prediction_id": "pred-1",
        "study_id": "study-dep-1",
        "environment_assurance_digest": "a" * 64,
        "verifier_assurance_digest": "b" * 64,
        "agent_configuration_digest": "c" * 64,
        "applicability_regime": "lab-synthetic",
        "outcome_definition": "binary_accept",
        "outcome_window": "T+7d",
        "predicted_probability": 0.4,
        "prediction_method": "fixture_model",
        "prediction_method_version": "0",
        "assumptions": ("fixture only",),
        "registered_at": time.time(),
        "synthetic_non_deployment_evidence": synthetic,
    }


def test_register_ingest_report_synthetic_cannot_claim(tmp_path: Path) -> None:
    root = tmp_path / "deployment"
    pred = register_prediction(root, prediction=_pred_payload(synthetic=True))
    assert pred.chronology_event_digest
    out = ingest_outcome(
        root,
        outcome={
            "outcome_id": "out-1",
            "prediction_id": "pred-1",
            "study_id": "study-dep-1",
            "outcome_value": 0,
            "observation_window": "T+7d",
            "provenance_digest": digest_of({"src": "fixture"}),
            "observed_at": time.time() + 1,
        },
    )
    assert out.synthetic_non_deployment_evidence is True
    plan = DeploymentCalibrationPlan(
        plan_id="plan-1",
        study_id="study-dep-1",
        primary_metrics=("brier",),
        synthetic_non_deployment_evidence=True,
    )
    report = build_calibration_report(root, plan=plan)
    assert report.synthetic_non_deployment_evidence is True
    assert report.supports_deployment_calibrated_claim is False
    assert "synthetic_non_deployment_evidence" in report.blockers


def test_retrospective_registration_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "deployment"
    register_prediction(root, prediction=_pred_payload())
    ingest_outcome(
        root,
        outcome={
            "outcome_id": "out-1",
            "prediction_id": "pred-1",
            "study_id": "study-dep-1",
            "outcome_value": 1,
            "observation_window": "T+7d",
            "provenance_digest": digest_of({"src": "fixture"}),
            "observed_at": time.time() + 1,
        },
    )
    with pytest.raises(ValueError, match="retrospective"):
        register_prediction(
            root,
            prediction={**_pred_payload(), "prediction_id": "pred-1"},
        )


def test_outcome_before_prediction_wallclock_rejected(tmp_path: Path) -> None:
    root = tmp_path / "deployment"
    now = time.time()
    register_prediction(root, prediction={**_pred_payload(), "registered_at": now})
    with pytest.raises(ValueError, match="earlier than prediction"):
        ingest_outcome(
            root,
            outcome={
                "outcome_id": "out-early",
                "prediction_id": "pred-1",
                "study_id": "study-dep-1",
                "outcome_value": 1,
                "observation_window": "T+7d",
                "provenance_digest": digest_of({"src": "fixture"}),
                "observed_at": now - 100,
            },
        )


def test_resolver_blocks_deployment_calibrated_for_synthetic(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "sealed_run.json").write_text(
        json.dumps(
            {
                "content_digest": "d" * 64,
                "budget_digest": "e" * 64,
                "custody_digest": "f" * 64,
                "preregistration_digest": "1" * 64,
                "metadata": {"execution_mode": "local_dev", "security_grade": False},
            }
        ),
        encoding="utf-8",
    )
    dep = run / "deployment"
    register_prediction(dep, prediction=_pred_payload(synthetic=True))
    ingest_outcome(
        dep,
        outcome={
            "outcome_id": "out-1",
            "prediction_id": "pred-1",
            "study_id": "study-dep-1",
            "outcome_value": 0,
            "observation_window": "T+7d",
            "provenance_digest": digest_of({"src": "fixture"}),
            "observed_at": time.time() + 1,
        },
    )
    plan = DeploymentCalibrationPlan(
        plan_id="plan-1",
        study_id="study-dep-1",
        primary_metrics=("brier",),
        synthetic_non_deployment_evidence=True,
    )
    build_calibration_report(dep, plan=plan)
    claim = AssuranceClaim(
        proposition="p",
        scope="s",
        assumptions=("a",),
        trust_boundary="t",
        specification_refs=("r",),
    )
    # Even with deployment artifacts, synthetic blocks deployment_calibrated.
    # Also missing lifecycle → stays below scientifically_qualified.
    q = qualify_run(run, claim=claim)
    assert q.level != "deployment_calibrated"
    from verifierlab.assurance import EvidenceResolver

    facts = {f.fact_id: f for f in EvidenceResolver(run, claim=claim).resolve_facts()}
    assert facts["deployment_not_synthetic"].outcome == "false"
