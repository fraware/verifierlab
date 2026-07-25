"""Slurm and Kubernetes launcher tests (mocked live paths)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from verifierlab.execution.kubernetes import KubernetesLauncher, kubernetes_client_available
from verifierlab.execution.slurm import SlurmLauncher, slurm_binaries_available


def test_slurm_dry_run_explicit(tmp_path: Path) -> None:
    slurm = SlurmLauncher(tmp_path / "slurm", dry_run=True)
    assert slurm.integration_status == "dry_run"
    h = slurm.submit({"unit_id": "u0", "seed": 1})
    assert slurm.status(h) == "submitted"
    script = tmp_path / "slurm" / "u0.sbatch"
    assert script.is_file()
    text = script.read_text(encoding="utf-8")
    assert "SBATCH" in text
    assert "dry_run_reason=requested" in text
    result = slurm.collect(h)
    assert result["launcher"] == "slurm"
    assert result["dry_run"] is True
    assert result["integration_status"] == "dry_run"
    slurm.cancel(h)
    assert slurm.status(h) == "cancelled"


@pytest.mark.slurm
def test_slurm_live_submit_mocked(tmp_path: Path) -> None:
    with (
        patch("verifierlab.execution.slurm.slurm_binaries_available", return_value=True),
        patch("verifierlab.execution.slurm._run") as run_mock,
    ):
        run_mock.return_value = MagicMock(returncode=0, stdout="12345\n", stderr="")
        slurm = SlurmLauncher(tmp_path / "slurm", dry_run=False)
        assert slurm.integration_status == "live"
        h = slurm.submit({"unit_id": "live0"})
        assert slurm._jobs[h]["job_id"] == "12345"
        run_mock.assert_called()
        # status via squeue
        run_mock.return_value = MagicMock(returncode=0, stdout="RUNNING\n", stderr="")
        assert slurm.status(h) == "running"
        result = slurm.collect(h)
        assert result["integration_status"] == "live"
        assert result["job_id"] == "12345"


@pytest.mark.slurm
def test_slurm_forces_dry_run_without_binaries(tmp_path: Path) -> None:
    with patch("verifierlab.execution.slurm.slurm_binaries_available", return_value=False):
        slurm = SlurmLauncher(tmp_path / "slurm", dry_run=False)
        assert slurm.dry_run is True
        assert slurm._dry_run_reason == "sbatch_unavailable"
        h = slurm.submit({"unit_id": "fallback"})
        assert slurm.collect(h)["dry_run_reason"] == "sbatch_unavailable"


@pytest.mark.slurm
@pytest.mark.skipif(not slurm_binaries_available(), reason="Slurm binaries not on PATH")
def test_slurm_binaries_detected() -> None:
    assert slurm_binaries_available()


def test_k8s_dry_run(tmp_path: Path) -> None:
    del tmp_path
    k8s = KubernetesLauncher(dry_run=True)
    assert k8s.integration_status == "dry_run"
    h = k8s.submit({"unit_id": "k0"})
    assert k8s.collect(h)["launcher"] == "kubernetes"
    assert k8s.collect(h)["dry_run"] is True
    k8s.cancel(h)
    assert k8s.status(h) == "cancelled"


@pytest.mark.kubernetes
def test_k8s_live_with_mock_api() -> None:
    api = MagicMock()
    remote = MagicMock()
    remote.status.succeeded = 1
    remote.status.failed = None
    remote.status.active = None
    api.read_namespaced_job_status.return_value = remote

    k8s = KubernetesLauncher(dry_run=False, batch_api=api)
    assert k8s.integration_status == "live"
    h = k8s.submit({"unit_id": "k-live"})
    api.create_namespaced_job.assert_called_once()
    assert k8s.status(h) == "done"
    result = k8s.collect(h)
    assert result["integration_status"] == "live"
    k8s.cancel(h)
    api.delete_namespaced_job.assert_called_once()
    assert k8s.status(h) == "cancelled"


@pytest.mark.kubernetes
def test_k8s_forces_dry_run_without_client() -> None:
    with patch(
        "verifierlab.execution.kubernetes.kubernetes_client_available",
        return_value=False,
    ):
        k8s = KubernetesLauncher(dry_run=False)
        assert k8s.dry_run is True
        assert k8s._dry_run_reason == "kubernetes_client_unavailable"


@pytest.mark.kubernetes
@pytest.mark.skipif(not kubernetes_client_available(), reason="kubernetes client not installed")
def test_kubernetes_package_importable() -> None:
    assert kubernetes_client_available()
