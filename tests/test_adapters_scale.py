"""Adapter conformance and object-store / launcher tests."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from verifierlab.artifacts.cas import ContentAddressedStore
from verifierlab.artifacts.object_store import LocalObjectStoreClient, ObjectStoreCAS
from verifierlab.campaigns.coevolution import run_coevolution_epoch
from verifierlab.execution.kubernetes import KubernetesLauncher
from verifierlab.execution.slurm import SlurmLauncher
from verifierlab.targets.conformance import EnvAdapter, run_conformance
from verifierlab.targets.gym_adapter import GymAdapter, gymnasium_available
from verifierlab.targets.harbor_adapter import HarborAdapter
from verifierlab.targets.inspect_adapter import InspectAdapter
from verifierlab.targets.nemo_adapter import NeMoGymAdapter
from verifierlab.targets.openenv_adapter import OpenEnvAdapter

FIXTURES = Path(__file__).parent / "fixtures"


def test_all_adapters_conform() -> None:
    """Each adapter exercises a real path (fixture, live HTTP, or live SDK)."""
    adapters: list[tuple[EnvAdapter, Callable[[], None]]] = []

    inspect_adapter = InspectAdapter(eval_log_path=FIXTURES / "inspect_eval_log.json")
    adapters.append((inspect_adapter, lambda: None))

    harbor_adapter = HarborAdapter(atif_path=FIXTURES / "harbor_atif_trajectory.json")
    adapters.append((harbor_adapter, lambda: None))

    nemo_adapter = NeMoGymAdapter(own_server=True)
    adapters.append((nemo_adapter, nemo_adapter.close))

    openenv_adapter = OpenEnvAdapter()
    adapters.append((openenv_adapter, openenv_adapter.close))

    if gymnasium_available():
        adapters.append((GymAdapter(env_id="TinyDiscrete-v0"), lambda: None))

    try:
        for adapter, _cleanup in adapters:
            result = run_conformance(adapter, seed=1)
            assert result.ok, result.as_dict()
            cfg = adapter.capture_config()
            assert cfg["integration_status"] != "stub"
    finally:
        for _adapter, cleanup in adapters:
            cleanup()


@pytest.mark.gym
@pytest.mark.skipif(not gymnasium_available(), reason="gymnasium not installed")
def test_gym_adapter_import_error_message() -> None:
    adapter = GymAdapter(env_id="TinyDiscrete-v0")
    assert adapter.integration_status == "live"


def test_object_store_cas(tmp_path: Path) -> None:
    client = LocalObjectStoreClient(tmp_path / "s3")
    cas = ObjectStoreCAS(client)
    digest = cas.put_json({"a": 1})
    assert cas.has(digest)
    assert cas.get_json(digest) == {"a": 1}
    fs = ContentAddressedStore(tmp_path / "fs")
    fs.put_json({"b": 2})
    mirrored = cas.mirror_from_fs(fs)
    assert mirrored


def test_slurm_and_k8s_launchers(tmp_path: Path) -> None:
    slurm = SlurmLauncher(tmp_path / "slurm", dry_run=True)
    assert slurm.integration_status == "dry_run"
    h = slurm.submit({"unit_id": "u0", "seed": 1})
    assert slurm.status(h) == "submitted"
    collected = slurm.collect(h)
    assert collected["launcher"] == "slurm"
    assert collected["dry_run"] is True

    k8s = KubernetesLauncher(dry_run=True)
    assert k8s.integration_status == "dry_run"
    h2 = k8s.submit({"unit_id": "u1"})
    assert k8s.collect(h2)["launcher"] == "kubernetes"
    k8s.cancel(h2)
    assert k8s.status(h2) == "cancelled"


def test_coevolution_epoch() -> None:
    def v(_t: dict) -> bool:
        return True

    epoch = run_coevolution_epoch(
        epoch=0,
        verifier_fn=v,
        verifier_version="1",
        attack_results=[
            {"unit_id": "u0", "verifier_accepted": True, "gt_valid": False},
        ],
    )
    assert epoch["n_exploits"] == 1
    assert len(epoch["epoch_digest"]) == 64
