"""Shared adapter conformance suite (VAL-R17): decision, timeout/error, isolation."""

from __future__ import annotations

from pathlib import Path

import pytest

from verifierlab.api.decision import DecisionKind
from verifierlab.api.verifier import normalize_decision
from verifierlab.targets.conformance import (
    check_decision_normalization,
    check_isolation,
    check_timeout_error_mapping,
    run_conformance,
)
from verifierlab.targets.harbor_adapter import HarborAdapter
from verifierlab.targets.inspect_adapter import InspectAdapter, inspect_sdk_available
from verifierlab.targets.nemo_adapter import NeMoGymAdapter

FIXTURES = Path(__file__).parent / "fixtures"


def test_decision_normalization_suite() -> None:
    checks = check_decision_normalization()
    assert all(checks.values()), checks
    # Explicit timeout → error (never truthy accept).
    d = normalize_decision({"decision": "timeout"})
    assert d.kind is DecisionKind.ERROR
    assert d.accepted is not True


def test_conformance_isolation_helper() -> None:
    clean = check_isolation({"obs": 1}, {"reward": 0.0}, {"steps": []})
    assert clean["hidden_label_separation"] is True
    leaky = check_isolation({"gt_valid": True}, {"reward": 1}, {"steps": [{"hidden_label": 1}]})
    assert leaky["hidden_label_separation"] is False


@pytest.mark.inspect
def test_inspect_fixture_timeout_error_isolation() -> None:
    adapter = InspectAdapter(eval_log_path=FIXTURES / "inspect_eval_log.json")
    timeout_checks = check_timeout_error_mapping(adapter)
    assert timeout_checks["timeout_mapping"] is True
    assert timeout_checks["timeout_no_gt_leak"] is True
    assert timeout_checks["error_mapping"] is True
    result = run_conformance(adapter, seed=0)
    assert result.ok, result.as_dict()
    assert result.checks["norm_decision_reject_not_truthy"] is True
    assert result.checks["hidden_label_separation"] is True


@pytest.mark.harbor
def test_harbor_fixture_conformance_suite() -> None:
    adapter = HarborAdapter(atif_path=FIXTURES / "harbor_atif_trajectory.json")
    result = run_conformance(adapter, seed=1)
    assert result.ok, result.as_dict()


@pytest.mark.nemo
def test_nemo_live_conformance_suite() -> None:
    adapter = NeMoGymAdapter(own_server=True)
    try:
        result = run_conformance(adapter, seed=2)
        assert result.ok, result.as_dict()
    finally:
        adapter.close()


def test_trainer_adapter_conformance_fixture() -> None:
    """VALAB-09 #6: trainer adapter is base-install and conformance-gated."""
    from verifierlab.budgets import Budget, ProvenanceLedger
    from verifierlab.targets.fake import fake_refund_verifier
    from verifierlab.targets.trainer_adapter import TrainerAdapter
    from verifierlab.verifiers.broker import VerifierBroker
    from verifierlab.verifiers.profile import VerifierProfile

    broker = VerifierBroker(
        profile=VerifierProfile.for_callable(fake_refund_verifier),
        verifier=fake_refund_verifier,
        access_model="black-box",
        ledger=ProvenanceLedger(budget=Budget(max_queries=20)),
    )
    adapter = TrainerAdapter(broker=broker)
    result = run_conformance(adapter, seed=4)  # type: ignore[arg-type]
    assert result.checks["config_capture"] is True
    assert result.checks["hidden_label_separation"] is True
    assert result.checks["timeout_mapping"] is True


@pytest.mark.inspect
@pytest.mark.skipif(not inspect_sdk_available(), reason="inspect-ai not installed")
def test_inspect_live_sdk_conformance_skip_if_missing() -> None:
    """Live SDK path: scheduled extras matrix; skip locally when SDK absent."""
    from verifierlab.targets.inspect_adapter import (
        build_minimal_task,
        eval_log_to_dict,
        run_inspect_eval,
    )

    logs = run_inspect_eval(build_minimal_task(), model="mockllm/model")
    assert logs
    adapter = InspectAdapter(eval_log=eval_log_to_dict(logs[0]))
    result = run_conformance(adapter, seed=3)
    assert result.ok, result.as_dict()
