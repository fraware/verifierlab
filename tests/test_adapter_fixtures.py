"""Inspect / Harbor log-format regression and NeMo/OpenEnv live protocol tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from verifierlab.targets.conformance import run_conformance
from verifierlab.targets.harbor_adapter import (
    HarborAdapter,
    atif_to_native,
    harbor_install_status,
    harbor_sdk_available,
    load_atif_trajectory,
    native_to_atif,
)
from verifierlab.targets.inspect_adapter import (
    InspectAdapter,
    inspect_log_to_native,
    inspect_sdk_available,
    load_inspect_eval_log,
    native_to_inspect_log,
)
from verifierlab.targets.nemo_adapter import (
    NeMoGymAdapter,
    NeMoGymClient,
    NeMoReferenceServer,
    load_nemo_endpoint_payload,
    native_to_nemo_payload,
    nemo_payload_to_native,
)
from verifierlab.targets.openenv_adapter import (
    OpenEnvAdapter,
    OpenEnvEnvironment,
    OpenEnvHttpClient,
    OpenEnvReferenceServer,
    openenv_sdk_available,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.inspect
def test_inspect_log_format_regression() -> None:
    """Fixture eval-log JSON round-trip (labeled log-format regression)."""
    path = FIXTURES / "inspect_eval_log.json"
    log = load_inspect_eval_log(path)
    assert log["version"] == 2
    assert len(log["samples"]) == 2

    native = inspect_log_to_native(log)
    assert native["framework"] == "inspect"
    assert native["task"] == "refund_policy"
    assert len(native["steps"]) == 2
    assert native["steps"][0]["verifier_accepted"] is True
    assert native["steps"][1]["verifier_accepted"] is False
    blob = str(native)
    assert "hidden_label" not in blob
    assert "gt_label" not in blob
    assert "inspect_target" in native["steps"][0]

    rebuilt = native_to_inspect_log(native)
    assert rebuilt["version"] == 2
    assert len(rebuilt["samples"]) == 2
    assert rebuilt["samples"][0]["target"] == "yes"
    assert rebuilt["eval"]["task"] == "refund_policy"

    adapter = InspectAdapter(eval_log_path=path)
    assert adapter.integration_status == "log_format_regression"
    result = run_conformance(adapter, seed=1)
    assert result.ok, result.as_dict()
    traj = adapter.finalize()
    assert traj["steps"][0]["op"] == "inspect_sample"


@pytest.mark.inspect
@pytest.mark.skipif(not inspect_sdk_available(), reason="inspect-ai not installed")
def test_inspect_live_minimal_task(tmp_path: Path) -> None:
    """Run a real Inspect Task with mockllm and map the EvalLog."""
    from verifierlab.targets.inspect_adapter import (
        build_minimal_task,
        eval_log_to_dict,
        run_inspect_eval,
    )

    logs = run_inspect_eval(build_minimal_task(), model="mockllm/model", log_dir=tmp_path)
    assert logs
    log_dict = eval_log_to_dict(logs[0])
    native = inspect_log_to_native(log_dict)
    assert native["framework"] == "inspect"
    assert len(native["steps"]) >= 1

    adapter = InspectAdapter(inspect_task=build_minimal_task(), model="mockllm/model")
    assert adapter.integration_status == "live"
    obs = adapter.reset(seed=0)
    assert obs["seed"] == 0
    step = adapter.step({"model": "mockllm/model"})
    assert "resources" in step
    traj = adapter.finalize()
    assert traj["integration_status"] == "live"
    assert isinstance(traj["steps"], list)
    result = run_conformance(
        InspectAdapter(eval_log=log_dict),
        seed=2,
    )
    assert result.ok, result.as_dict()


@pytest.mark.inspect
def test_inspect_adapter_requires_log_or_sdk() -> None:
    if inspect_sdk_available():
        adapter = InspectAdapter()
        assert adapter.integration_status == "live"
        return
    with pytest.raises(ImportError, match="inspect-ai"):
        InspectAdapter()


@pytest.mark.harbor
def test_harbor_atif_log_format_regression() -> None:
    path = FIXTURES / "harbor_atif_trajectory.json"
    atif = load_atif_trajectory(path)
    assert atif["schema_version"] == "ATIF-v1.5"
    assert len(atif["steps"]) == 3

    native = atif_to_native(atif)
    assert native["framework"] == "harbor"
    assert native["session_id"] == atif["session_id"]
    assert len(native["steps"]) == 3
    assert native["steps"][1]["tool_calls"]
    assert native["resources"]["total_prompt_tokens"] == 1120

    rebuilt = native_to_atif(native)
    assert rebuilt["schema_version"] == "ATIF-v1.5"
    assert rebuilt["session_id"] == atif["session_id"]
    assert len(rebuilt["steps"]) == 3
    assert rebuilt["steps"][1]["tool_calls"][0]["function_name"] == "financial_search"

    adapter = HarborAdapter(atif_path=path)
    assert adapter.integration_status in {"log_format_regression", "live"}
    result = run_conformance(adapter, seed=2)
    assert result.ok, result.as_dict()


@pytest.mark.harbor
@pytest.mark.skipif(
    not harbor_sdk_available(),
    reason=harbor_install_status().get("hint")
    or harbor_install_status().get("reason")
    or "harbor package not installed",
)
def test_harbor_live_trajectory_types() -> None:
    path = FIXTURES / "harbor_atif_trajectory.json"
    adapter = HarborAdapter(atif_path=path, validate=True)
    assert adapter.integration_status == "live"
    cfg = adapter.capture_config()
    assert cfg["sdk_available"] is True
    assert cfg["harbor_type"] is not None
    assert "Trajectory" in str(cfg["harbor_type"])
    result = run_conformance(adapter, seed=1)
    assert result.ok, result.as_dict()


@pytest.mark.harbor
def test_harbor_adapter_requires_atif() -> None:
    with pytest.raises(ValueError, match="atif"):
        HarborAdapter()


@pytest.mark.nemo
def test_nemo_endpoint_log_format_regression() -> None:
    path = FIXTURES / "nemo_endpoint.json"
    payload = load_nemo_endpoint_payload(path)
    native = nemo_payload_to_native(payload)
    assert native["framework"] == "nemo_gym"
    assert len(native["steps"]) == 4
    rebuilt = native_to_nemo_payload(native)
    assert len(rebuilt["episodes"]) == 2
    assert len(rebuilt["verifications"]) == 2
    assert rebuilt["verifications"][1]["accepted"] is False

    adapter = NeMoGymAdapter(payload_path=path)
    assert adapter.integration_status == "log_format_regression"
    result = run_conformance(adapter, seed=0)
    assert result.ok, result.as_dict()


@pytest.mark.nemo
def test_nemo_live_http_against_reference_server() -> None:
    server = NeMoReferenceServer()
    server.start_background()
    try:
        client = NeMoGymClient(server.base_url)
        assert client.health()["status"] == "ok"
        seeded = client.seed_session({"balance": 500.0})
        assert seeded["session_id"]
        obs = client.call_tool("act", {"action": {"op": "refund", "amount": 50}})
        assert obs["observation"]["balance"] == 450.0
        verify = client.verify({})
        assert verify["reward"] == 1.0
        assert verify["info"]["accepted"] is True

        adapter = NeMoGymAdapter(base_url=server.base_url)
        assert adapter.integration_status == "live"
        result = run_conformance(adapter, seed=3)
        assert result.ok, result.as_dict()
        traj = adapter.finalize()
        assert traj["framework"] == "nemo_gym"
        assert any(s.get("op") == "nemo_verify" for s in traj["steps"])
        adapter.close()
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.nemo
def test_nemo_adapter_owns_reference_server() -> None:
    adapter = NeMoGymAdapter(own_server=True)
    try:
        assert adapter.integration_status == "live"
        result = run_conformance(adapter, seed=1)
        assert result.ok, result.as_dict()
    finally:
        adapter.close()


@pytest.mark.openenv
def test_openenv_live_http_reference() -> None:
    server = OpenEnvReferenceServer(max_steps=4)
    server.start_background()
    try:
        client = OpenEnvHttpClient(server.base_url)
        assert client.health()["status"] == "ok"
        reset = client.reset(seed=7)
        assert "observation" in reset
        stepped = client.step({"action": 1})
        assert "reward" in stepped
        state = client.state()
        assert state["step_count"] >= 1

        env = OpenEnvEnvironment(client, env_name="ref", max_steps=4)
        env.reset(seed=1)
        env.act({"action": 1})
        traj = env.finalize()
        assert traj["framework"] == "openenv"
        assert traj["integration_status"] == "live"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.openenv
def test_openenv_adapter_conformance() -> None:
    adapter = OpenEnvAdapter()
    try:
        assert adapter.integration_status == "live"
        assert adapter.capture_config()["protocol"] == "http_simulation"
        result = run_conformance(adapter, seed=4)
        assert result.ok, result.as_dict()
    finally:
        adapter.close()


@pytest.mark.openenv
@pytest.mark.skipif(not openenv_sdk_available(), reason="openenv package not installed")
def test_openenv_sdk_discovery() -> None:
    adapter = OpenEnvAdapter()
    try:
        assert adapter.capture_config()["sdk_available"] is True
    finally:
        adapter.close()
