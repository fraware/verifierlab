"""End-to-end fake campaign via local launcher."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest

from verifierlab.artifacts.cas import ContentAddressedStore
from verifierlab.budgets import Budget, OverrunPolicy
from verifierlab.campaigns.engine import freeze_run, init_workspace, run_campaign
from verifierlab.execution.local import LocalLauncher, _run_fake_work_unit

REPO_ROOT = Path(__file__).resolve().parents[1]
FAKE_SMOKE = REPO_ROOT / "campaigns" / "fake-smoke.yaml"


@pytest.mark.integration
def test_fake_campaign_e2e(tmp_path: Path) -> None:
    workspace = init_workspace(tmp_path / ".valab")
    started = time.perf_counter()
    # Thread workers keep M0 smoke under ~2s on Windows spawn-heavy hosts;
    # process workers remain the CLI default (see use_processes=True).
    result = run_campaign(
        FAKE_SMOKE,
        workspace=workspace,
        max_workers=2,
        use_processes=False,
    )
    elapsed = time.perf_counter() - started
    assert result.elapsed_s < 2.0
    assert elapsed < 2.5
    assert len(result.run_digest) == 64
    assert result.manifest.status == "completed"
    manifest_path = result.run_dir / "manifest.json"
    assert manifest_path.is_file()
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert data["run_digest"] == result.run_digest
    assert data["campaign_digest"]
    assert len(data["work_unit_digests"]) >= 1

    profile_digest = result.manifest.metadata["verifier_profile_digest"]
    assert len(profile_digest) == 64
    assert result.manifest.metadata["verifier_profile_digest_source"] == "worker_consensus"

    freeze_run(result.run_dir)
    sealed = json.loads((result.run_dir / "sealed_run.json").read_text(encoding="utf-8"))
    assert sealed["verifier_digest"] == profile_digest


@pytest.mark.integration
def test_work_unit_idempotency_and_resume(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "store")
    run_dir = tmp_path / "run"
    budget = Budget(max_queries=100, overrun_policy=OverrunPolicy.STOP)
    launcher = LocalLauncher(
        store=store,
        run_dir=run_dir,
        budget=budget,
        max_workers=1,
        use_processes=False,
    )
    units = [
        {"unit_id": "u0", "seed": 1, "unit_index": 0, "max_steps": 2},
        {"unit_id": "u1", "seed": 1, "unit_index": 1, "max_steps": 2},
    ]

    first = asyncio.run(launcher.run_all(units))
    assert first["status"] == "completed"
    assert len(first["results"]) == 2

    launcher2 = LocalLauncher(
        store=store,
        run_dir=run_dir,
        budget=budget,
        max_workers=1,
        use_processes=False,
    )
    second = asyncio.run(launcher2.run_all(units))
    assert second["status"] == "completed"
    assert {r["unit_digest"] for r in first["results"]} == {
        r["unit_digest"] for r in second["results"]
    }


def test_run_fake_work_unit_digest_stable() -> None:
    a = _run_fake_work_unit({"unit_id": "x", "seed": 42, "unit_index": 0, "max_steps": 2})
    b = _run_fake_work_unit({"unit_id": "x", "seed": 42, "unit_index": 0, "max_steps": 2})
    assert a["unit_digest"] == b["unit_digest"]
    assert a["commitment"] == b["commitment"]
