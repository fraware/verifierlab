"""Source-level contract for adversarial worker isolation probes."""

from __future__ import annotations

from pathlib import Path

PROBE = (
    Path(__file__).resolve().parents[1] / "src" / "verifierlab" / "targets" / "isolation_probe.py"
)


def test_probe_contains_no_reference_answers() -> None:
    text = PROBE.read_text(encoding="utf-8")
    for forbidden in (
        "PlantedOracleGroundTruth",
        "ground_truth_ref",
        "gt_valid",
        "label_value",
        "decrypt_label",
    ):
        assert forbidden not in text
    # The probe must know only the name prefix used to detect accidental
    # secret-environment inheritance. No hidden-label value is embedded here.
    assert 'key.startswith("VALAB_HIDDEN_LABEL")' in text


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
