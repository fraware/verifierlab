"""VALAB-01 baseline gate: doctor smoke + reproducible science digests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from verifierlab.diagnostics.doctor import run_doctor

REPO = Path(__file__).resolve().parents[1]
FAKE_SMOKE = REPO / "campaigns" / "fake-smoke.yaml"
REPRO_SCRIPT = REPO / "scripts" / "repro_bundle_check.py"


def test_valab01_doctor_ok() -> None:
    report = run_doctor()
    assert report.ok, [d.message for d in report.diagnostics]


def test_valab01_science_digest_helpers() -> None:
    """Canonical science keys used by repro_bundle_check must be stable helpers."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("repro_bundle_check", REPRO_SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    a = {
        "campaign_digest": "abc",
        "status": "completed",
        "exploit_count": 1,
        "taxonomies": ["x"],
        "metrics": {"ordinary": {"far": 0.1, "n": 2}},
    }
    b = dict(a)
    assert mod.science_digest(a) == mod.science_digest(b)
    b["exploit_count"] = 2
    assert mod.science_digest(a) != mod.science_digest(b)


@pytest.mark.integration
def test_valab01_repro_bundle_canonical_digests(tmp_path: Path) -> None:
    assert REPRO_SCRIPT.is_file()
    proc = subprocess.run(
        [sys.executable, str(REPRO_SCRIPT), str(FAKE_SMOKE)],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
    payload = json.loads(proc.stdout)
    assert not payload.get("mismatch")
    assert payload["first"]["science_digest"] == payload["second"]["science_digest"]
    assert "OK:" in proc.stderr or "match" in proc.stderr.lower()
