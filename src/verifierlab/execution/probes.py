"""Malicious isolation probe catalogue for security-grade executors.

Probes are intended to run *inside* the real worker executor. Structural
Dockerfile/command string tests alone never set ``security_grade=True``.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import random
import socket
import uuid
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any

from verifierlab.artifacts.canonical import digest_of
from verifierlab.execution.protocol import (
    ExecutionBackendKind,
    IsolationProbeOutcome,
    IsolationProbeReport,
)

REQUIRED_PROBE_IDS: tuple[str, ...] = (
    "filesystem_inventory",
    "environment_scrape",
    "proc_scrape",
    "forbidden_imports",
    "secret_sentinel_search",
    "network_tcp",
    "network_udp",
    "network_dns",
    "writable_root_escape",
    "host_mount_device",
    "privilege_escalation",
    "fork_pid_exhaustion",
    "cross_unit_persistence",
    "randomized_gt_path_guess",
)

_COORDINATOR_SENTINEL_PREFIX = "VALAB_COORDINATOR_SENTINEL_"
_ADJUDICATOR_SENTINEL_PREFIX = "VALAB_ADJUDICATOR_SENTINEL_"


def inject_secret_sentinels(*, prefix: str = "VALAB") -> dict[str, str]:
    """Create coordinator/adjudicator secret sentinels for absence proofs."""
    token = uuid.uuid4().hex
    return {
        f"{_COORDINATOR_SENTINEL_PREFIX}{prefix}": f"coord-{token}",
        f"{_ADJUDICATOR_SENTINEL_PREFIX}{prefix}": f"adj-{token}",
    }


def randomized_gt_guess_paths(*, seed: int, count: int = 8) -> tuple[str, ...]:
    """Generate randomized ground-truth path guesses (not a fixed denylist)."""
    rng = random.Random(seed)
    roots = (
        "/var/lib/verifierlab",
        "/home/valab",
        "/tmp",
        "/run",
        "/opt",
        "/usr/local/share",
    )
    names = (
        "labels",
        "vault",
        "ground_truth",
        "gt",
        "hidden",
        "oracle",
        "adjudication",
    )
    out: list[str] = []
    for _ in range(count):
        root = rng.choice(roots)
        name = rng.choice(names)
        suffix = rng.randbytes(4).hex()
        out.append(f"{root}/{name}-{suffix}")
    return tuple(out)


def _outcome(
    probe_id: str, *, denied: bool, evidence: dict[str, Any], detail: str | None = None
) -> IsolationProbeOutcome:
    return IsolationProbeOutcome(
        probe_id=probe_id,
        attempted=True,
        denied_or_absent=denied,
        evidence_digest=digest_of(evidence),
        detail=detail,
    )


def run_malicious_probe_catalogue(
    *,
    backend_kind: ExecutionBackendKind,
    ran_inside_executor: bool,
    secret_sentinels: dict[str, str] | None = None,
    gt_guess_seed: int = 0,
    host_environ: dict[str, str] | None = None,
) -> IsolationProbeReport:
    """Execute the probe catalogue in the current process (worker context).

    When invoked on the coordinator host without a container boundary, results
    are marked ``structural_only`` / not security-grade eligible.
    """
    sentinels = secret_sentinels or {}
    env = host_environ if host_environ is not None else dict(os.environ)
    outcomes: list[IsolationProbeOutcome] = []

    # Filesystem inventory — sensitive coordinator paths must be absent.
    sensitive_paths = [
        Path("/var/run/docker.sock"),
        Path("/etc/shadow"),
        Path("/proc/1/root"),
    ]
    visible = [str(p) for p in sensitive_paths if p.exists()]
    outcomes.append(
        _outcome(
            "filesystem_inventory",
            denied=len(visible) == 0,
            evidence={"visible": visible},
        )
    )

    # Environment scrape — coordinator/adjudicator sentinels must be absent.
    leaked = sorted(
        k
        for k in env
        if k in sentinels
        or k.startswith(_COORDINATOR_SENTINEL_PREFIX)
        or k.startswith(_ADJUDICATOR_SENTINEL_PREFIX)
    )
    also_sensitive = sorted(
        k
        for k in env
        if k.startswith("VALAB_TEST_SECRET")
        or k.startswith("VALAB_VAULT")
        or k.startswith("VALAB_HIDDEN_LABEL")
    )
    leaked = sorted(set(leaked) | set(also_sensitive))
    outcomes.append(
        _outcome(
            "environment_scrape",
            denied=len(leaked) == 0,
            evidence={"leaked_keys": leaked},
        )
    )

    # /proc scrape — CapEff should be zero for non-root workers when isolation holds.
    cap_eff_zero = False
    proc_readable = False
    try:
        status = Path("/proc/self/status").read_text(encoding="utf-8")
        proc_readable = True
        for line in status.splitlines():
            if line.startswith("CapEff:"):
                cap_eff_zero = int(line.split(":", 1)[1].strip(), 16) == 0
                break
    except (OSError, ValueError):
        proc_readable = False
        cap_eff_zero = True  # non-Linux hosts: treat as not escalating via /proc
    outcomes.append(
        _outcome(
            "proc_scrape",
            denied=(not proc_readable) or cap_eff_zero,
            evidence={"proc_readable": proc_readable, "cap_eff_zero": cap_eff_zero},
        )
    )

    # Forbidden imports — labels/adjudication must be pruned from worker image.
    forbidden_mods = ("verifierlab.labels", "verifierlab.repairs", "verifierlab.disclosure")
    importable = [name for name in forbidden_mods if importlib.util.find_spec(name) is not None]
    outcomes.append(
        _outcome(
            "forbidden_imports",
            denied=len(importable) == 0,
            evidence={"importable": importable},
        )
    )

    # Secret sentinel values must not appear in worker-visible environment.
    sentinel_values_present = [
        key for key, value in sentinels.items() if key in env and env.get(key) == value
    ]
    outcomes.append(
        _outcome(
            "secret_sentinel_search",
            denied=len(sentinel_values_present) == 0,
            evidence={"present_keys": sentinel_values_present},
        )
    )

    # Network TCP / UDP / DNS
    def _tcp() -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.25)
        try:
            sock.connect(("198.51.100.1", 9))
            return True
        except OSError:
            return False
        finally:
            sock.close()

    def _udp() -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.25)
        try:
            sock.sendto(b"probe", ("198.51.100.1", 9))
            return True
        except OSError:
            return False
        finally:
            sock.close()

    def _dns() -> bool:
        try:
            socket.getaddrinfo("example.invalid", 80)
            return True
        except OSError:
            return False

    tcp_ok = _tcp()
    udp_ok = _udp()
    dns_ok = _dns()
    outcomes.append(_outcome("network_tcp", denied=not tcp_ok, evidence={"connected": tcp_ok}))
    outcomes.append(_outcome("network_udp", denied=not udp_ok, evidence={"sent": udp_ok}))
    outcomes.append(_outcome("network_dns", denied=not dns_ok, evidence={"resolved": dns_ok}))

    # Writable root escape
    root_probe = Path("/etc/verifierlab-isolation-probe-write")
    root_write = False
    try:
        root_probe.write_text("probe", encoding="utf-8")
        root_write = True
    except OSError:
        root_write = False
    if root_write:
        with suppress(OSError):
            root_probe.unlink()
    outcomes.append(
        _outcome("writable_root_escape", denied=not root_write, evidence={"wrote": root_write})
    )

    # Host mount / device
    docker_sock = Path("/var/run/docker.sock").exists()
    outcomes.append(
        _outcome(
            "host_mount_device",
            denied=not docker_sock,
            evidence={"docker_sock": docker_sock},
        )
    )

    # Privilege escalation indicator
    try:
        euid = os.geteuid()  # type: ignore[attr-defined]
    except AttributeError:
        euid = -1  # Windows: not a Linux security domain
    non_root = euid not in (0, -1) or (euid == -1 and os.name != "posix")
    # On Windows/non-POSIX, privilege probe cannot attest Linux isolation.
    if os.name != "posix":
        privilege_denied = False
        privilege_detail = "non_posix_host_cannot_attest_euid"
    else:
        privilege_denied = euid != 0
        privilege_detail = None
    outcomes.append(
        _outcome(
            "privilege_escalation",
            denied=privilege_denied,
            evidence={"euid": euid, "non_root": non_root},
            detail=privilege_detail,
        )
    )

    # Fork/pid exhaustion — soft check: spawn is limited; we only confirm we are not pid 1 host.
    try:
        pid = os.getpid()
        host_pid_ns = Path("/proc/1/ns/pid").resolve() == Path("/proc/self/ns/pid").resolve()
    except OSError:
        pid = os.getpid()
        host_pid_ns = False
    outcomes.append(
        _outcome(
            "fork_pid_exhaustion",
            denied=not host_pid_ns,
            evidence={"pid": pid, "shares_host_pid_ns": host_pid_ns},
        )
    )

    # Cross-unit persistence marker
    marker = Path("/var/lib/verifierlab/worker/isolation-probe-marker")
    stale = marker.exists()
    outcomes.append(
        _outcome(
            "cross_unit_persistence",
            denied=not stale,
            evidence={"stale_marker": stale},
        )
    )

    # Randomized GT path guessing
    guesses = randomized_gt_guess_paths(seed=gt_guess_seed)
    found = [path for path in guesses if Path(path).exists()]
    outcomes.append(
        _outcome(
            "randomized_gt_path_guess",
            denied=len(found) == 0,
            evidence={"guesses": list(guesses), "found": found},
        )
    )

    missing = [pid for pid in REQUIRED_PROBE_IDS if pid not in {o.probe_id for o in outcomes}]
    if missing:
        raise RuntimeError(f"probe catalogue incomplete: {missing}")

    all_denied = all(o.denied_or_absent for o in outcomes)
    secret_absent = all(
        o.denied_or_absent
        for o in outcomes
        if o.probe_id in {"environment_scrape", "secret_sentinel_search"}
    )
    gt_absent = next(
        o.denied_or_absent for o in outcomes if o.probe_id == "randomized_gt_path_guess"
    )
    structural_only = not ran_inside_executor
    # Security-grade eligibility requires real executor + rootless/stronger backend.
    security_eligible = (
        ran_inside_executor
        and not structural_only
        and backend_kind in {"docker_rootless", "microvm", "separate_host"}
        and all_denied
        and secret_absent
        and gt_absent
    )

    return IsolationProbeReport(
        backend_kind=backend_kind,
        ran_inside_executor=ran_inside_executor,
        structural_only=structural_only,
        secret_sentinels_absent=secret_absent,
        randomized_gt_paths_absent=gt_absent,
        outcomes=tuple(outcomes),
        all_required_denied=all_denied,
        security_grade_eligible=security_eligible,
    )


def compile_probe_report_from_worker_payload(
    payload: dict[str, Any],
    *,
    backend_kind: ExecutionBackendKind,
    ran_inside_executor: bool,
) -> IsolationProbeReport:
    """Rebuild a typed probe report from a worker-returned catalogue payload."""
    outcomes = tuple(
        IsolationProbeOutcome.model_validate(row) for row in payload.get("outcomes") or ()
    )
    return IsolationProbeReport(
        backend_kind=backend_kind,
        ran_inside_executor=ran_inside_executor,
        structural_only=bool(payload.get("structural_only", not ran_inside_executor)),
        secret_sentinels_absent=bool(payload.get("secret_sentinels_absent", False)),
        randomized_gt_paths_absent=bool(payload.get("randomized_gt_paths_absent", False)),
        outcomes=outcomes,
        all_required_denied=bool(payload.get("all_required_denied", False)),
        security_grade_eligible=bool(payload.get("security_grade_eligible", False)),
    )


def probe_work_unit(
    *,
    secret_sentinels: dict[str, str],
    gt_guess_seed: int,
) -> dict[str, Any]:
    """Build a one-shot worker request that runs the malicious probe catalogue."""
    return {
        "unit_id": f"isolation-probe-{hashlib.sha256(str(gt_guess_seed).encode()).hexdigest()[:12]}",
        "probe_catalogue": True,
        "secret_sentinel_keys": sorted(secret_sentinels),
        "gt_guess_seed": gt_guess_seed,
        # Workers must never receive sentinel *values*.
        "persistent": False,
    }


ProbeRunner = Callable[..., IsolationProbeReport]

__all__ = [
    "REQUIRED_PROBE_IDS",
    "compile_probe_report_from_worker_payload",
    "inject_secret_sentinels",
    "probe_work_unit",
    "randomized_gt_guess_paths",
    "run_malicious_probe_catalogue",
]
