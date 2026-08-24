"""Source-level contract for adversarial worker isolation probes."""

from __future__ import annotations

from pathlib import Path

PROBE = Path(__file__).resolve().parents[1] / "src" / "verifierlab" / "targets" / "isolation_probe.py"


def test_probe_contains_no_reference_answers() -> None:
    text = PROBE.read_text(encoding="utf-8")
    assert "PlantedOracleGroundTruth" not in text
    assert "gt_valid" not in text
    assert "hidden_label" not in text.lower()


def test_probe_exercises_boundary_failures_not_task_semantics() -> None:
    text = PROBE.read_text(encoding="utf-8")
    for token in (
        "/proc/self/status",
        "/var/run/docker.sock",
        "verifierlab.labels",
        "198.51.100.1",
        "stale_cross_unit_state",
        "root_write_succeeded",
    ):
        assert token in text
