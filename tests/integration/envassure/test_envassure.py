"""EnvAssure protocol/fixture tests (live only when package installable)."""

from __future__ import annotations

import json

import pytest

from verifierlab.targets.conformance import run_conformance
from verifierlab.targets.envassure_adapter import (
    EnvAssureAdapter,
    EnvAssureTarget,
    envassure_available,
)

pytestmark = [pytest.mark.envassure, pytest.mark.integration]


def test_envassure_fixture_protocol_not_live() -> None:
    adapter = EnvAssureAdapter(fixture=True, max_steps=4)
    assert adapter.integration_status == "not-live"
    cfg = adapter.capture_config()
    assert cfg["integration_status"] == "not-live"
    assert cfg["evaluator_state"] == "adjudication_only"
    result = run_conformance(adapter, seed=1)
    assert result.ok, result.as_dict()
    traj = adapter.finalize()
    blob = json.dumps(traj)
    assert "evaluator_state" not in blob
    assert "planted_label" not in blob
    assert "hidden_label" not in blob
    # Adjudication can still read evaluator state.
    adj = adapter.adjudication_evaluator_state()
    assert "planted_label" in adj or "hidden_target" in adj


def test_envassure_attacker_sees_public_feedback_only() -> None:
    target = EnvAssureTarget.fixture(max_steps=4)
    assert target.integration_status == "not-live"
    target.reset(seed=2)
    step = target.act({"action": 1, "public_feedback": {"accepted": True, "score": 1.0}})
    assert step["public_feedback"]["accepted"] is True
    assert "evaluator_state" not in step
    traj = target.finalize()
    assert traj["integration_status"] == "not-live"
    assert traj["public_feedback"]


@pytest.mark.skipif(not envassure_available(), reason="envassure package not installed")
def test_envassure_live_when_installable() -> None:
    adapter = EnvAssureAdapter(fixture=False)
    assert adapter.integration_status == "live"
    result = run_conformance(adapter, seed=0)
    assert result.ok, result.as_dict()
