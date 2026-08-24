"""Static regressions for the live container-isolation workflow."""

from __future__ import annotations

from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "container-isolation.yml"


def test_live_isolation_workflow_keeps_rootful_conformance_below_security_grade() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "ContainerWorkerExecutor" in text
    assert "require_rootless=False" in text
    assert 'boundary.get("security_grade")' in text
    assert "rootful hosted execution must not be security-grade" in text


def test_live_isolation_workflow_runs_two_fresh_containers() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert '"isolation-probe-1"' in text
    assert '"isolation-probe-2"' in text
    assert "stale_cross_unit_state" in text
    assert "executor.execute(payload)" in text
    assert "executor.execute(second_payload)" in text


def test_live_isolation_workflow_asserts_adversarial_probe_dimensions() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    for field in (
        "labels_importable",
        "root_write_succeeded",
        "network_connect_succeeded",
        "docker_socket_visible",
        "sensitive_env_names",
        "cap_eff_zero",
        "non_root",
    ):
        assert field in text
