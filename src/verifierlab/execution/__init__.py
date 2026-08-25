"""Execution launchers and attested worker boundaries."""

from __future__ import annotations

from verifierlab.api.protocols import CampaignLauncher
from verifierlab.execution.attacker_state import (
    DEFAULT_MAX_STATE_BYTES,
    AttackerStateEnvelope,
    AttackerStateLineage,
    append_envelope,
    assert_fresh_attack_qualification,
    make_attacker_state_envelope,
    scan_envelope_payload,
    store_envelope_payload,
    work_unit_state_binding,
)
from verifierlab.execution.container import (
    ContainerExecutionRecord,
    ContainerIsolationPolicy,
    ContainerWorkerExecutor,
    ExecutionBoundaryManifest,
    assert_security_compatible_work_unit,
    boundary_manifest_from_inspect,
    build_create_command,
    daemon_is_rootless,
    host_trust_domain_digest,
)
from verifierlab.execution.local import LocalLauncher
from verifierlab.execution.microvm import MicroVMExecutionBackend, SeparateHostExecutionBackend
from verifierlab.execution.probes import (
    REQUIRED_PROBE_IDS,
    inject_secret_sentinels,
    probe_work_unit,
    randomized_gt_guess_paths,
    run_malicious_probe_catalogue,
)
from verifierlab.execution.protocol import (
    CapabilityNegotiation,
    ExecutionBackendKind,
    ExecutionPolicy,
    IsolationProbeOutcome,
    IsolationProbeReport,
    SecureLauncher,
    WorkUnitExecutor,
)
from verifierlab.execution.secure import (
    DockerRootlessSecureLauncher,
    SecurityGradeRefused,
    assert_local_dev_maturity_cap,
    negotiate_execution_capabilities,
    select_secure_launcher,
)

__all__ = [
    "DEFAULT_MAX_STATE_BYTES",
    "REQUIRED_PROBE_IDS",
    "AttackerStateEnvelope",
    "AttackerStateLineage",
    "CampaignLauncher",
    "CapabilityNegotiation",
    "ContainerExecutionRecord",
    "ContainerIsolationPolicy",
    "ContainerWorkerExecutor",
    "DockerRootlessSecureLauncher",
    "ExecutionBackendKind",
    "ExecutionBoundaryManifest",
    "ExecutionPolicy",
    "IsolationProbeOutcome",
    "IsolationProbeReport",
    "LocalLauncher",
    "MicroVMExecutionBackend",
    "SecureLauncher",
    "SecurityGradeRefused",
    "SeparateHostExecutionBackend",
    "WorkUnitExecutor",
    "append_envelope",
    "assert_fresh_attack_qualification",
    "assert_local_dev_maturity_cap",
    "assert_security_compatible_work_unit",
    "boundary_manifest_from_inspect",
    "build_create_command",
    "daemon_is_rootless",
    "host_trust_domain_digest",
    "inject_secret_sentinels",
    "make_attacker_state_envelope",
    "negotiate_execution_capabilities",
    "probe_work_unit",
    "randomized_gt_guess_paths",
    "run_malicious_probe_catalogue",
    "scan_envelope_payload",
    "select_secure_launcher",
    "store_envelope_payload",
    "work_unit_state_binding",
]
