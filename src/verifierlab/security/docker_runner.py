"""Optional Docker sandbox runner for untrusted attack/env plugins (VAL-R17).

Uses the Docker CLI (no mandatory Python ``docker`` SDK). When Docker is
missing or unhealthy, callers receive an explicit ``unavailable`` result —
never a silent claim of isolation.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

DEFAULT_IMAGE = "python:3.12-slim"
DEFAULT_MEMORY = "512m"
DEFAULT_CPUS = "1.0"
DEFAULT_PIDS = 256
DEFAULT_TIMEOUT_S = 60


def docker_engine_status() -> dict[str, Any]:
    """Probe whether a Docker engine is usable."""
    exe = shutil.which("docker")
    if not exe:
        return {
            "available": False,
            "reason": "docker_cli_not_found",
            "detail": "Install Docker and ensure `docker` is on PATH.",
        }
    try:
        proc = subprocess.run(
            [exe, "info", "--format", "{{json .ServerVersion}}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "available": False,
            "reason": "docker_probe_failed",
            "detail": str(exc),
            "cli": exe,
        }
    if proc.returncode != 0:
        return {
            "available": False,
            "reason": "docker_daemon_unavailable",
            "detail": (proc.stderr or proc.stdout or "").strip()[:500],
            "cli": exe,
        }
    return {
        "available": True,
        "reason": "ok",
        "cli": exe,
        "server_version": (proc.stdout or "").strip().strip('"') or None,
    }


def build_docker_run_argv(
    *,
    image: str = DEFAULT_IMAGE,
    command: list[str],
    workdir: str = "/work",
    read_only_mounts: list[tuple[str, str]] | None = None,
    memory: str = DEFAULT_MEMORY,
    cpus: str = DEFAULT_CPUS,
    pids_limit: int = DEFAULT_PIDS,
    network: str = "none",
    name: str | None = None,
) -> list[str]:
    """Declarative ``docker run`` argv (no network, RO mounts, resource limits)."""
    argv = [
        "docker",
        "run",
        "--rm",
        "--network",
        network,
        "--memory",
        memory,
        "--cpus",
        cpus,
        "--pids-limit",
        str(pids_limit),
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "-w",
        workdir,
    ]
    if name:
        argv.extend(["--name", name])
    for host, container in read_only_mounts or []:
        argv.extend(["-v", f"{host}:{container}:ro"])
    argv.append(image)
    argv.extend(command)
    return argv


def run_in_docker(
    *,
    script: str,
    read_only_dirs: list[Path] | None = None,
    image: str = DEFAULT_IMAGE,
    memory: str = DEFAULT_MEMORY,
    cpus: str = DEFAULT_CPUS,
    pids_limit: int = DEFAULT_PIDS,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    network: str = "none",
) -> dict[str, Any]:
    """Run a Python script snippet inside Docker with hardened defaults.

    Returns a result dict. When Docker is unavailable, ``status`` is
    ``unavailable`` and ``enforced`` is False (honest degradation).
    """
    status = docker_engine_status()
    if not status.get("available"):
        return {
            "schema_version": "1",
            "status": "unavailable",
            "enforced": False,
            "docker": status,
            "stdout": "",
            "stderr": "",
            "exit_code": None,
            "argv": None,
            "notes": (
                "Docker sandbox not enforced. Default local path trusts the host "
                "Python process; see SandboxProfile trust_boundary."
            ),
        }

    mounts: list[tuple[str, str]] = []
    for i, path in enumerate(read_only_dirs or []):
        host = str(Path(path).resolve())
        mounts.append((host, f"/ro/{i}"))

    with tempfile.TemporaryDirectory(prefix="valab-sandbox-") as tmp:
        script_path = Path(tmp) / "plugin_main.py"
        script_path.write_text(script, encoding="utf-8")
        mounts.append((str(Path(tmp).resolve()), "/work"))
        argv = build_docker_run_argv(
            image=image,
            command=["python", "/work/plugin_main.py"],
            workdir="/work",
            read_only_mounts=mounts,
            memory=memory,
            cpus=cpus,
            pids_limit=pids_limit,
            network=network,
        )
        # Replace leading "docker" with resolved CLI path.
        cli = str(status.get("cli") or "docker")
        argv = [cli, *argv[1:]]
        try:
            proc = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
        except subprocess.TimeoutExpired as exc:
            return {
                "schema_version": "1",
                "status": "timeout",
                "enforced": True,
                "docker": status,
                "stdout": (exc.stdout or "") if isinstance(exc.stdout, str) else "",
                "stderr": (exc.stderr or "") if isinstance(exc.stderr, str) else "timeout",
                "exit_code": None,
                "argv": argv,
                "timeout_s": timeout_s,
            }
        except OSError as exc:
            return {
                "schema_version": "1",
                "status": "error",
                "enforced": False,
                "docker": {**status, "available": False, "detail": str(exc)},
                "stdout": "",
                "stderr": str(exc),
                "exit_code": None,
                "argv": argv,
            }

        return {
            "schema_version": "1",
            "status": "ok" if proc.returncode == 0 else "failed",
            "enforced": True,
            "docker": status,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "exit_code": proc.returncode,
            "argv": argv,
            "policy": {
                "network": network,
                "memory": memory,
                "cpus": cpus,
                "pids_limit": pids_limit,
                "read_only_root": True,
            },
        }


def describe_sandbox_invocation(result: dict[str, Any]) -> str:
    """Short human-readable summary for reports / CLI."""
    return json.dumps(
        {
            "status": result.get("status"),
            "enforced": result.get("enforced"),
            "exit_code": result.get("exit_code"),
            "docker_reason": (result.get("docker") or {}).get("reason"),
        },
        sort_keys=True,
    )
