"""Process-pool picklability for the campaign worker entry point (VAL-R06)."""

from __future__ import annotations

import asyncio
import json
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest

from verifierlab.artifacts.cas import ContentAddressedStore
from verifierlab.budgets import Budget, OverrunPolicy
from verifierlab.campaigns.engine import init_workspace, run_campaign
from verifierlab.campaigns.worker import execute_work_unit
from verifierlab.execution.local import LocalLauncher

REPO_ROOT = Path(__file__).resolve().parents[1]
FAKE_SMOKE = REPO_ROOT / "campaigns" / "fake-smoke.yaml"

_FAKE_UNIT = {
    "unit_id": "proc-u0",
    "seed": 7,
    "unit_index": 0,
    "max_steps": 2,
    "cohort": "ordinary",
    "access_model": "black-box",
    "strategy": "ordinary",
    "strategy_config": {"actions": [{"op": "noop"}]},
    "environment_kind": "fake",
    "environment_ref": "verifierlab.targets.fake:FakeEnvironment",
    "environment_config": {},
    "verifier_ref": "verifierlab.targets.fake:fake_refund_verifier",
    "commitment_nonce": "proc-nonce-0",
}


def test_execute_work_unit_in_process() -> None:
    """Module-level entry must survive spawn-based ProcessPoolExecutor."""
    with ProcessPoolExecutor(max_workers=1) as pool:
        future = pool.submit(execute_work_unit, _FAKE_UNIT)
        result = future.result(timeout=120)
    assert result["unit_id"] == "proc-u0"
    assert "unit_digest" in result
    assert "verifier_accepted" in result
    assert result.get("verifier_status") in {
        "accept",
        "reject",
        "abstain",
        "indeterminate",
        "error",
    }


def test_execute_work_unit_json_blob() -> None:
    blob = json.dumps(_FAKE_UNIT).encode("utf-8")
    with ProcessPoolExecutor(max_workers=1) as pool:
        result = pool.submit(execute_work_unit, blob).result(timeout=120)
    assert result["unit_id"] == "proc-u0"


@pytest.mark.integration
def test_campaign_process_pool_smoke(tmp_path: Path) -> None:
    workspace = init_workspace(tmp_path / ".valab")
    result = run_campaign(
        FAKE_SMOKE,
        workspace=workspace,
        max_workers=1,
        use_processes=True,
    )
    assert result.manifest.status == "completed"
    assert len(result.run_digest) == 64
    units = list((result.run_dir / "work_units").glob("*.json"))
    assert len(units) >= 1


@pytest.mark.integration
def test_launcher_process_pool_with_worker(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "store")
    run_dir = tmp_path / "run"
    budget = Budget(max_queries=10, overrun_policy=OverrunPolicy.STOP)
    launcher = LocalLauncher(
        store=store,
        run_dir=run_dir,
        budget=budget,
        max_workers=1,
        use_processes=True,
    )
    outcome = asyncio.run(launcher.run_all([_FAKE_UNIT], executor_fn=execute_work_unit))
    assert outcome["status"] == "completed"
    assert len(outcome["results"]) == 1
    assert outcome["results"][0]["unit_id"] == "proc-u0"
