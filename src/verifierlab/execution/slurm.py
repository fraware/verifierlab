"""Slurm CampaignLauncher (``[slurm]`` extra).

**Live mode:** when ``sbatch`` / ``squeue`` / ``scancel`` are on ``PATH`` and
``dry_run=False``, submits real batch scripts and queries job state.

**Dry-run mode (default):** writes ``.sbatch`` scripts and synthetic collect
results with an explicit ``integration_status`` of ``dry_run``. Also used when
Slurm binaries are missing even if ``dry_run=False`` was requested.

Install (no Python deps; system Slurm required for live)::

    pip install "verifierlab[slurm]"
"""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any


def slurm_binaries_available() -> bool:
    """Return True when ``sbatch``, ``squeue``, and ``scancel`` are on PATH."""
    return all(shutil.which(name) for name in ("sbatch", "squeue", "scancel"))


def _run(cmd: list[str], *, timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class SlurmLauncher:
    """Submit work units as sbatch scripts (live or dry-run)."""

    def __init__(
        self,
        work_dir: Path,
        *,
        dry_run: bool = True,
        partition: str | None = None,
        time_limit: str = "00:10:00",
        sbatch_extra: list[str] | None = None,
    ) -> None:
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.partition = partition
        self.time_limit = time_limit
        self.sbatch_extra = list(sbatch_extra or [])
        self._jobs: dict[str, dict[str, Any]] = {}

        binaries = slurm_binaries_available()
        self._dry_run_reason: str | None
        if dry_run:
            self.dry_run = True
            self._dry_run_reason = "requested"
        elif not binaries:
            self.dry_run = True
            self._dry_run_reason = "sbatch_unavailable"
        else:
            self.dry_run = False
            self._dry_run_reason = None

    @property
    def integration_status(self) -> str:
        return "dry_run" if self.dry_run else "live"

    def _render_script(self, handle: str, work_unit: dict[str, Any]) -> str:
        lines = [
            "#!/bin/bash",
            "#SBATCH --job-name=valab",
            f"#SBATCH --time={self.time_limit}",
            f"#SBATCH --output={self.work_dir / (handle + '.out')}",
            f"#SBATCH --error={self.work_dir / (handle + '.err')}",
        ]
        if self.partition:
            lines.append(f"#SBATCH --partition={self.partition}")
        for extra in self.sbatch_extra:
            lines.append(f"#SBATCH {extra}")
        lines.append(f"# valab_unit={handle}")
        lines.append(f"# integration_status={self.integration_status}")
        if self._dry_run_reason:
            lines.append(f"# dry_run_reason={self._dry_run_reason}")
        payload_path = self.work_dir / f"{handle}.json"
        payload_path.write_text(json.dumps(work_unit, sort_keys=True), encoding="utf-8")
        result_path = self.work_dir / f"{handle}.result.json"
        lines.append(
            f'echo \'{{"unit_id":"{handle}","launcher":"slurm","ok":true}}\' > {result_path}'
        )
        lines.append(f"# work_unit_path={payload_path}")
        return "\n".join(lines) + "\n"

    def submit(self, work_unit: dict[str, Any]) -> str:
        handle = str(work_unit.get("unit_id") or uuid.uuid4())
        script = self.work_dir / f"{handle}.sbatch"
        script.write_text(self._render_script(handle, work_unit), encoding="utf-8")
        script.chmod(script.stat().st_mode | 0o111)

        job_id: str
        submit_error: str | None = None
        if self.dry_run:
            job_id = f"slurm-dry-{handle}"
        else:
            cmd = ["sbatch", "--parsable", str(script)]
            proc = _run(cmd)
            if proc.returncode != 0:
                job_id = f"slurm-error-{handle}"
                submit_error = (proc.stderr or proc.stdout or "sbatch failed").strip()
                # Fall back to dry-run semantics for collect while recording failure.
                self._jobs[handle] = {
                    "status": "failed",
                    "job_id": job_id,
                    "script": str(script),
                    "work_unit": work_unit,
                    "result": None,
                    "integration_status": "live",
                    "dry_run": False,
                    "dry_run_reason": None,
                    "submit_error": submit_error,
                }
                return handle
            job_id = proc.stdout.strip().split(";")[0].strip()

        self._jobs[handle] = {
            "status": "submitted",
            "job_id": job_id,
            "script": str(script),
            "work_unit": work_unit,
            "result": None,
            "integration_status": self.integration_status,
            "dry_run": self.dry_run,
            "dry_run_reason": self._dry_run_reason,
            "submit_error": submit_error,
        }
        return handle

    def status(self, handle: str) -> str:
        job = self._jobs[handle]
        if job["status"] in {"done", "cancelled", "failed"}:
            return str(job["status"])
        if self.dry_run:
            return str(job["status"])

        job_id = str(job["job_id"])
        proc = _run(["squeue", "-h", "-j", job_id, "-o", "%T"])
        if proc.returncode != 0 or not proc.stdout.strip():
            # Not in queue — treat as completed (or vanished).
            job["status"] = "done"
            return "done"
        state = proc.stdout.strip().splitlines()[0].strip().upper()
        mapping = {
            "PD": "pending",
            "PENDING": "pending",
            "R": "running",
            "RUNNING": "running",
            "CG": "running",
            "CD": "done",
            "COMPLETED": "done",
            "F": "failed",
            "FAILED": "failed",
            "CA": "cancelled",
            "CANCELLED": "cancelled",
        }
        mapped = mapping.get(state, state.lower())
        job["status"] = mapped
        return mapped

    def collect(self, handle: str) -> dict[str, Any]:
        job = self._jobs[handle]
        if job["result"] is not None:
            result: dict[str, Any] = job["result"]
            return result

        result_path = self.work_dir / f"{handle}.result.json"
        file_result: dict[str, Any] | None = None
        if result_path.is_file():
            try:
                loaded = json.loads(result_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    file_result = loaded
            except json.JSONDecodeError:
                file_result = None

        payload = {
            "schema_version": "1",
            "unit_id": handle,
            "launcher": "slurm",
            "job_id": job["job_id"],
            "work_unit": job["work_unit"],
            "integration_status": job["integration_status"],
            "dry_run": job["dry_run"],
            "dry_run_reason": job.get("dry_run_reason"),
            "submit_error": job.get("submit_error"),
            "script": job["script"],
        }
        if file_result is not None:
            payload["job_result"] = file_result
        if job["status"] == "failed":
            payload["ok"] = False
        else:
            payload["ok"] = job.get("submit_error") is None
            job["status"] = "done"
        job["result"] = payload
        return payload

    def cancel(self, handle: str) -> None:
        if handle not in self._jobs:
            return
        job = self._jobs[handle]
        if not self.dry_run and job.get("job_id") and not str(job["job_id"]).startswith("slurm-"):
            _run(["scancel", str(job["job_id"])])
        job["status"] = "cancelled"
