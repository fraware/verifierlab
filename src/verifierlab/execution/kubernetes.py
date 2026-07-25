"""Kubernetes CampaignLauncher (``[kubernetes]`` extra).

**Live mode:** when the ``kubernetes`` Python client is installed and
``dry_run=False``, creates batch/v1 Jobs via the API.

**Dry-run mode (default):** builds Job manifests and synthetic collect results
with ``integration_status=dry_run``. Also used when the client is missing or
kubeconfig cannot be loaded.

Install::

    pip install "verifierlab[kubernetes]"
"""

from __future__ import annotations

import contextlib
import importlib
import uuid
from typing import Any


def kubernetes_client_available() -> bool:
    try:
        importlib.import_module("kubernetes")
    except ImportError:
        return False
    return True


class KubernetesLauncher:
    """Create Job manifests for work units (live API or dry-run)."""

    def __init__(
        self,
        *,
        namespace: str = "default",
        dry_run: bool = True,
        image: str = "ghcr.io/fraware/verifierlab:latest",
        batch_api: Any | None = None,
        load_config: bool = True,
    ) -> None:
        self.namespace = namespace
        self.image = image
        self._jobs: dict[str, dict[str, Any]] = {}
        self._batch_api = batch_api
        self._dry_run_reason: str | None

        if dry_run and batch_api is None:
            self.dry_run = True
            self._dry_run_reason = "requested"
            return

        if batch_api is not None:
            self.dry_run = False
            self._dry_run_reason = None
            return

        if not kubernetes_client_available():
            self.dry_run = True
            self._dry_run_reason = "kubernetes_client_unavailable"
            return

        if not load_config:
            self.dry_run = True
            self._dry_run_reason = "config_not_loaded"
            return

        try:
            config = importlib.import_module("kubernetes.config")
            client = importlib.import_module("kubernetes.client")
            try:
                config.load_incluster_config()
            except Exception:
                config.load_kube_config()
            self._batch_api = client.BatchV1Api()
            self.dry_run = False
            self._dry_run_reason = None
        except Exception:
            self._batch_api = None
            self.dry_run = True
            self._dry_run_reason = "kubeconfig_unavailable"

    @property
    def integration_status(self) -> str:
        return "dry_run" if self.dry_run else "live"

    def _manifest(self, handle: str, work_unit: dict[str, Any]) -> dict[str, Any]:
        name = f"valab-{handle}"[:63].rstrip("-").lower()
        return {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": name,
                "namespace": self.namespace,
                "labels": {"app": "verifierlab", "valab-unit": handle[:63]},
            },
            "spec": {
                "backoffLimit": 0,
                "template": {
                    "metadata": {"labels": {"app": "verifierlab", "valab-unit": handle[:63]}},
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": [
                            {
                                "name": "worker",
                                "image": self.image,
                                "args": ["campaign", "run", "--help"],
                                "env": [
                                    {"name": "VALAB_UNIT", "value": handle},
                                    {
                                        "name": "VALAB_WORK_UNIT_JSON",
                                        "value": str(work_unit.get("unit_id", handle)),
                                    },
                                ],
                            }
                        ],
                    },
                },
            },
        }

    def submit(self, work_unit: dict[str, Any]) -> str:
        handle = str(work_unit.get("unit_id") or uuid.uuid4())
        manifest = self._manifest(handle, work_unit)
        api_error: str | None = None

        if not self.dry_run and self._batch_api is not None:
            try:
                # Prefer dict body for easier mocking; real client accepts dicts.
                self._batch_api.create_namespaced_job(
                    namespace=self.namespace,
                    body=manifest,
                )
            except Exception as exc:
                api_error = str(exc)
                self._jobs[handle] = {
                    "status": "failed",
                    "manifest": manifest,
                    "work_unit": work_unit,
                    "result": None,
                    "integration_status": "live",
                    "dry_run": False,
                    "dry_run_reason": None,
                    "api_error": api_error,
                }
                return handle

        self._jobs[handle] = {
            "status": "submitted",
            "manifest": manifest,
            "work_unit": work_unit,
            "result": None,
            "integration_status": self.integration_status,
            "dry_run": self.dry_run,
            "dry_run_reason": self._dry_run_reason,
            "api_error": api_error,
        }
        return handle

    def status(self, handle: str) -> str:
        job = self._jobs[handle]
        if job["status"] in {"done", "cancelled", "failed"}:
            return str(job["status"])
        if self.dry_run or self._batch_api is None:
            return str(job["status"])

        name = job["manifest"]["metadata"]["name"]
        try:
            remote = self._batch_api.read_namespaced_job_status(
                name=name,
                namespace=self.namespace,
            )
            status = getattr(remote, "status", remote)
            succeeded = getattr(status, "succeeded", None)
            failed = getattr(status, "failed", None)
            active = getattr(status, "active", None)
            if isinstance(status, dict):
                succeeded = status.get("succeeded")
                failed = status.get("failed")
                active = status.get("active")
            if succeeded:
                job["status"] = "done"
            elif failed:
                job["status"] = "failed"
            elif active:
                job["status"] = "running"
            else:
                job["status"] = "pending"
        except Exception:
            # Keep last known status on API errors.
            pass
        return str(job["status"])

    def collect(self, handle: str) -> dict[str, Any]:
        job = self._jobs[handle]
        if job["result"] is not None:
            result: dict[str, Any] = job["result"]
            return result
        payload = {
            "schema_version": "1",
            "unit_id": handle,
            "launcher": "kubernetes",
            "manifest": job["manifest"],
            "work_unit": job["work_unit"],
            "integration_status": job["integration_status"],
            "dry_run": job["dry_run"],
            "dry_run_reason": job.get("dry_run_reason"),
            "api_error": job.get("api_error"),
            "ok": job.get("api_error") is None and job["status"] != "failed",
        }
        if job["status"] != "failed":
            job["status"] = "done"
        job["result"] = payload
        return payload

    def cancel(self, handle: str) -> None:
        if handle not in self._jobs:
            return
        job = self._jobs[handle]
        if not self.dry_run and self._batch_api is not None:
            name = job["manifest"]["metadata"]["name"]
            with contextlib.suppress(Exception):
                self._batch_api.delete_namespaced_job(
                    name=name,
                    namespace=self.namespace,
                    propagation_policy="Background",
                )
        job["status"] = "cancelled"
