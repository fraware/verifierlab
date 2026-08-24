"""Adversarial target for live worker-boundary conformance tests.

The target intentionally attempts operations an untrusted attack/environment
plugin might try: importing adjudication code, writing the immutable root,
using network egress, observing inherited secrets, retaining cross-unit state,
and running with effective Linux capabilities. It contains no hidden labels or
reference answers.
"""

from __future__ import annotations

import importlib.util
import os
import socket
from pathlib import Path
from typing import Any

from verifierlab.api.verifier import verifier
from verifierlab.artifacts.records import DecisionSpace

_MARKER = Path("/var/lib/verifierlab/worker/isolation-probe-marker")
_ROOT_PROBE = Path("/etc/verifierlab-isolation-probe")
_TMP_PROBE = Path("/tmp/verifierlab-isolation-probe")


def _cap_eff_zero() -> bool:
    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("CapEff:"):
                return int(line.split(":", 1)[1].strip(), 16) == 0
    except (OSError, ValueError):
        return False
    return False


def _labels_importable() -> bool:
    try:
        return importlib.util.find_spec("verifierlab.labels") is not None
    except (ImportError, ModuleNotFoundError, AttributeError):
        return False


def _can_write(path: Path) -> bool:
    try:
        path.write_text("probe", encoding="utf-8")
    except OSError:
        return False
    try:
        path.unlink()
    except OSError:
        pass
    return True


def _network_connect_succeeds() -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.25)
    try:
        # TEST-NET-2: no production endpoint is contacted even if isolation fails.
        sock.connect(("198.51.100.1", 9))
    except OSError:
        return False
    finally:
        sock.close()
    return True


def collect_isolation_probe() -> dict[str, Any]:
    stale_state = _MARKER.exists()
    marker_write = _can_write(_MARKER)
    sensitive_env = sorted(
        key
        for key in os.environ
        if key.startswith("VALAB_TEST_SECRET")
        or key.startswith("VALAB_VAULT")
        or key.startswith("VALAB_HIDDEN_LABEL")
    )
    return {
        "euid": os.geteuid(),
        "non_root": os.geteuid() != 0,
        "labels_importable": _labels_importable(),
        "root_write_succeeded": _can_write(_ROOT_PROBE),
        "tmp_write_succeeded": _can_write(_TMP_PROBE),
        "network_connect_succeeded": _network_connect_succeeds(),
        "sensitive_env_names": sensitive_env,
        "cap_eff_zero": _cap_eff_zero(),
        "docker_socket_visible": Path("/var/run/docker.sock").exists(),
        "stale_cross_unit_state": stale_state,
        "worker_state_tmpfs_writable": marker_write,
    }


class IsolationProbeEnvironment:
    """One-step environment that records attempted boundary violations."""

    def __init__(self, *, max_steps: int = 1) -> None:
        self.max_steps = max_steps
        self._seed = 0
        self._done = False
        self._probe: dict[str, Any] = {}

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._seed = seed
        self._done = False
        self._probe = {}
        return {"seed": seed, "probe": "ready"}

    def act(self, action: dict[str, Any]) -> dict[str, Any]:
        del action
        if self._done:
            raise RuntimeError("probe episode already finalized")
        self._probe = collect_isolation_probe()
        self._done = True
        return {
            "observation": {"probe_complete": True},
            "reward": 0.0,
            "done": True,
        }

    def finalize(self) -> dict[str, Any]:
        self._done = True
        return {
            "schema_version": "1",
            "seed": self._seed,
            "steps": [{"op": "isolation_probe"}],
            "probe": dict(self._probe),
        }


@verifier(
    name="isolation_probe_verifier",
    decision_space=DecisionSpace.BINARY,
    limitations=["Security-conformance target only; not a task-quality verifier"],
)
def isolation_probe_verifier(trajectory: dict[str, Any]) -> bool:
    """Pass only when all intended worker-boundary probe outcomes hold."""
    probe = trajectory.get("probe")
    if not isinstance(probe, dict):
        return False
    return bool(
        probe.get("non_root") is True
        and probe.get("labels_importable") is False
        and probe.get("root_write_succeeded") is False
        and probe.get("tmp_write_succeeded") is True
        and probe.get("network_connect_succeeded") is False
        and probe.get("sensitive_env_names") == []
        and probe.get("cap_eff_zero") is True
        and probe.get("docker_socket_visible") is False
        and probe.get("stale_cross_unit_state") is False
        and probe.get("worker_state_tmpfs_writable") is True
    )


__all__ = [
    "IsolationProbeEnvironment",
    "collect_isolation_probe",
    "isolation_probe_verifier",
]
