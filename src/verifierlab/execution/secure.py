"""Security-grade launcher selection with fail-closed capability negotiation."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from verifierlab.execution.container import (
    ContainerIsolationPolicy,
    ContainerWorkerExecutor,
    daemon_is_rootless,
)
from verifierlab.execution.microvm import MicroVMExecutionBackend
from verifierlab.execution.probes import (
    inject_secret_sentinels,
    probe_work_unit,
    run_malicious_probe_catalogue,
)
from verifierlab.execution.protocol import (
    CapabilityNegotiation,
    ExecutionBackendKind,
    ExecutionPolicy,
    IsolationProbeReport,
    SecureLauncher,
)


class SecurityGradeRefused(RuntimeError):
    """Raised when security-grade execution cannot be attested on this host."""


def _docker_info_security_options(docker_binary: str = "docker") -> list[str] | None:
    if shutil.which(docker_binary) is None:
        return None
    try:
        proc = subprocess.run(
            [docker_binary, "info", "--format", "{{json .SecurityOptions}}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15.0,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, list):
        return None
    return [str(item) for item in data]


def negotiate_execution_capabilities(
    policy: ExecutionPolicy,
    *,
    docker_binary: str = "docker",
    microvm_available: bool = False,
    separate_host_available: bool = False,
) -> CapabilityNegotiation:
    """Negotiate host capabilities. Never silently degrade to local for security-grade."""
    reasons: list[str] = []
    options = _docker_info_security_options(docker_binary)
    docker_available = options is not None
    rootless = bool(options and daemon_is_rootless(options))
    image_pinned = bool(policy.worker_image and "@sha256:" in policy.worker_image)

    # Container control support is assumed when Docker answers; effective controls
    # are still attested per work unit via inspect.
    supports = docker_available
    selected: ExecutionBackendKind | None = None
    refused = False

    if policy.mode == "local_dev":
        selected = "local_dev"
    elif policy.mode == "security_grade":
        if policy.backend == "microvm":
            if not microvm_available:
                refused = True
                reasons.append("microvm_backend_unavailable")
            else:
                selected = "microvm"
        elif policy.backend == "separate_host":
            if not separate_host_available:
                refused = True
                reasons.append("separate_host_backend_unavailable")
            else:
                selected = "separate_host"
        else:
            # Default security-grade path: Docker rootless.
            if not docker_available:
                refused = True
                reasons.append("docker_unavailable")
            if not image_pinned:
                refused = True
                reasons.append("worker_image_not_digest_pinned")
            if policy.require_rootless and not rootless:
                refused = True
                reasons.append("daemon_not_rootless")
            if not supports:
                refused = True
                reasons.append("container_controls_unavailable")
            if not refused:
                selected = "docker_rootless" if rootless else "docker_rootful"
                if selected == "docker_rootful" and policy.require_rootless:
                    refused = True
                    reasons.append("rootful_refused_for_security_grade")
                    selected = None
        if refused:
            selected = None

    return CapabilityNegotiation(
        requested_mode=policy.mode,
        docker_available=docker_available,
        daemon_rootless=rootless,
        image_digest_pinned=image_pinned,
        supports_network_none=supports,
        supports_read_only_root=supports,
        supports_cap_drop=supports,
        supports_no_new_privileges=supports,
        supports_seccomp=supports,
        supports_private_ipc=supports,
        supports_private_cgroupns=supports,
        supports_tmpfs_only=supports,
        supports_resource_limits=supports,
        microvm_available=microvm_available,
        separate_host_available=separate_host_available,
        selected_backend=selected,
        refused=refused,
        refusal_reasons=tuple(reasons),
    )


class DockerRootlessSecureLauncher:
    """SecureLauncher backed by digest-pinned rootless ContainerWorkerExecutor."""

    def __init__(
        self,
        policy: ExecutionPolicy,
        *,
        docker_binary: str = "docker",
        isolation: ContainerIsolationPolicy | None = None,
    ) -> None:
        if not policy.worker_image:
            raise SecurityGradeRefused("security-grade launcher requires worker_image")
        self.policy = policy
        self.docker_binary = docker_binary
        self.isolation = isolation or ContainerIsolationPolicy(
            image=policy.worker_image,
            require_rootless=policy.require_rootless,
        )
        self._executor = ContainerWorkerExecutor(self.isolation, docker_binary=docker_binary)
        self._negotiation = negotiate_execution_capabilities(
            policy,
            docker_binary=docker_binary,
        )
        if self._negotiation.refused or self._negotiation.selected_backend != "docker_rootless":
            raise SecurityGradeRefused(
                "security-grade Docker rootless refused: "
                + ", ".join(self._negotiation.refusal_reasons)
            )
        self._security_grade = True
        self._last_probe: IsolationProbeReport | None = None

    @property
    def backend_kind(self) -> ExecutionBackendKind:
        return "docker_rootless"

    @property
    def security_grade(self) -> bool:
        return self._security_grade

    def negotiate(self) -> CapabilityNegotiation:
        return self._negotiation

    def run_isolation_probes(self, *, gt_guess_seed: int = 0) -> IsolationProbeReport:
        """Run the malicious catalogue inside the real container executor."""
        sentinels = inject_secret_sentinels()
        # Sentinels stay on coordinator env only; worker receives keys, not values.
        unit = probe_work_unit(secret_sentinels=sentinels, gt_guess_seed=gt_guess_seed)
        # Prefer in-executor catalogue via worker payload flag when image supports it;
        # otherwise execute catalogue in a dedicated probe unit and attest absence.
        try:
            result = self._executor.execute({**unit, "strategy": "ordinary", "cohort": "probe"})
            probe_payload = result.get("isolation_probe_report")
            if isinstance(probe_payload, dict):
                report = IsolationProbeReport.model_validate(probe_payload)
            else:
                # Fallback: host-side catalogue is structural-only and cannot grade.
                report = run_malicious_probe_catalogue(
                    backend_kind="docker_rootless",
                    ran_inside_executor=False,
                    secret_sentinels=sentinels,
                    gt_guess_seed=gt_guess_seed,
                )
        except Exception:
            # If the worker image cannot run the catalogue yet, mark honestly.
            report = run_malicious_probe_catalogue(
                backend_kind="docker_rootless",
                ran_inside_executor=False,
                secret_sentinels=sentinels,
                gt_guess_seed=gt_guess_seed,
            )
        self._last_probe = report
        if not report.security_grade_eligible:
            self._security_grade = False
        return report

    def execute(self, work_unit: dict[str, Any]) -> dict[str, Any]:
        if self.policy.run_isolation_probes and self._last_probe is None:
            self.run_isolation_probes()
        result = self._executor.execute(work_unit)
        boundary = result.get("execution_boundary")
        if isinstance(boundary, dict) and boundary.get("security_grade") is not True:
            self._security_grade = False
        if self._last_probe is not None:
            result["isolation_probe_report"] = self._last_probe.model_dump(mode="json")
            result["isolation_probe_report_digest"] = self._last_probe.content_digest
            # Re-bind probe digest into returned boundary copy for sealed-run hooks.
            if isinstance(boundary, dict):
                boundary = dict(boundary)
                boundary["probe_report_digest"] = self._last_probe.content_digest
                # Probe failure demotes security_grade even on rootless hosts.
                if not self._last_probe.security_grade_eligible:
                    boundary["security_grade"] = False
                    self._security_grade = False
                result["execution_boundary"] = boundary
        return result


def select_secure_launcher(
    policy: ExecutionPolicy, *, docker_binary: str = "docker"
) -> SecureLauncher:
    """Select a SecureLauncher from campaign policy. Fail closed — never local fallback."""
    negotiation = negotiate_execution_capabilities(policy, docker_binary=docker_binary)
    if policy.mode != "security_grade":
        raise SecurityGradeRefused("select_secure_launcher requires mode=security_grade")
    if negotiation.refused or negotiation.selected_backend is None:
        raise SecurityGradeRefused(
            "capability negotiation refused security-grade launch: "
            + (", ".join(negotiation.refusal_reasons) or "unknown")
        )
    if negotiation.selected_backend == "docker_rootless":
        return DockerRootlessSecureLauncher(policy, docker_binary=docker_binary)
    if negotiation.selected_backend == "microvm":
        backend = MicroVMExecutionBackend()
        # Interface exists; production readiness is still false on this tree.
        raise SecurityGradeRefused(
            "microvm backend negotiated but not production-ready on this host: "
            f"available={backend.available()}"
        )
    if negotiation.selected_backend == "separate_host":
        raise SecurityGradeRefused("separate_host backend is not production-ready on this host")
    raise SecurityGradeRefused(f"unsupported backend: {negotiation.selected_backend}")


def assert_local_dev_maturity_cap(policy: ExecutionPolicy) -> None:
    """Local threads/processes remain development-only with a hard maturity cap."""
    if policy.mode == "local_dev" and policy.local_dev_maturity_cap != "development_only":
        raise ValueError("local_dev maturity cap must be development_only")


__all__ = [
    "DockerRootlessSecureLauncher",
    "SecurityGradeRefused",
    "assert_local_dev_maturity_cap",
    "negotiate_execution_capabilities",
    "select_secure_launcher",
]
