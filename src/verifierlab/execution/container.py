"""Strict container execution boundary for untrusted attack workers.

The local process launcher is a development convenience, not a security
boundary. This module defines a separate one-shot worker executor that creates a
container with mandatory isolation controls, inspects the effective runtime
configuration before execution, and emits content-addressed boundary and
execution records.

A digest-pinned worker image is mandatory. Rootless daemon execution is required
for ``security_grade=True``. The policy may explicitly permit a rootful daemon
for CI/conformance exercises, but such a run remains below security grade even
when every container-local control passes. No host bind/volume/device mount is
permitted. Mutable persistent-attacker state is intentionally unsupported until
it has a dedicated protocol that cannot expose coordinator state.
"""

from __future__ import annotations

import json
import re
import subprocess
import uuid
from contextlib import suppress
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from verifierlab.artifacts.canonical import digest_of

_IMAGE_DIGEST_RE = re.compile(r"(?:@sha256:|^sha256:)([0-9a-f]{64})$")
_WORKER_DATA = "/var/lib/verifierlab/worker"
_TMP = "/tmp"


class ContainerIsolationPolicy(BaseModel):
    """Mandatory controls for the isolated worker execution path."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    image: str = Field(min_length=1)
    user: Literal["10001:10001"] = "10001:10001"
    pids_limit: int = Field(default=128, ge=16, le=1024)
    memory_bytes: int = Field(default=1024 * 1024 * 1024, ge=128 * 1024 * 1024)
    nano_cpus: int = Field(default=1_000_000_000, ge=100_000_000, le=8_000_000_000)
    tmpfs_bytes: int = Field(default=64 * 1024 * 1024, ge=4 * 1024 * 1024)
    timeout_s: float = Field(default=120.0, gt=0.0, le=3600.0)
    require_rootless: bool = True

    @field_validator("image")
    @classmethod
    def _image_must_be_digest_pinned(cls, value: str) -> str:
        if _IMAGE_DIGEST_RE.search(value) is None:
            raise ValueError("isolated worker image must be pinned by sha256 digest")
        return value

    @property
    def image_digest(self) -> str:
        match = _IMAGE_DIGEST_RE.search(self.image)
        assert match is not None
        return match.group(1)


class ExecutionBoundaryManifest(BaseModel):
    """Observed isolation controls for one worker container."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    mode: Literal["container_isolated"] = "container_isolated"
    engine: Literal["docker"] = "docker"
    image_ref: str
    image_digest: str = Field(min_length=64, max_length=64)
    container_id_digest: str = Field(min_length=64, max_length=64)
    daemon_security_options: tuple[str, ...]
    policy_requires_rootless: bool
    daemon_rootless: bool
    network_none: bool
    read_only_root: bool
    cap_drop_all: bool
    no_new_privileges: bool
    seccomp_builtin: bool
    non_root_user: bool
    no_host_mounts: bool
    tmpfs_only_writable_paths: bool
    private_ipc: bool
    private_cgroupns: bool
    host_pid_namespace_disabled: bool
    privileged_disabled: bool
    devices_absent: bool
    pids_limit: int
    memory_bytes: int
    nano_cpus: int
    create_command_digest: str = Field(min_length=64, max_length=64)
    inspect_digest: str = Field(min_length=64, max_length=64)
    policy_satisfied: bool
    security_grade: bool

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class ContainerExecutionRecord(BaseModel):
    """Bind one request/result pair to the attested boundary and final state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    boundary_digest: str = Field(min_length=64, max_length=64)
    request_digest: str = Field(min_length=64, max_length=64)
    worker_result_digest: str = Field(min_length=64, max_length=64)
    final_inspect_digest: str = Field(min_length=64, max_length=64)
    container_exit_code: int
    attach_return_code: int

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def build_create_command(
    policy: ContainerIsolationPolicy,
    *,
    name: str,
    docker_binary: str = "docker",
) -> list[str]:
    """Build the shell-free container-create command for one work unit."""
    cpus = policy.nano_cpus / 1_000_000_000
    tmpfs_common = f"rw,noexec,nosuid,size={policy.tmpfs_bytes}"
    tmpfs_tmp = f"{tmpfs_common},mode=1777"
    tmpfs_worker = f"{tmpfs_common},uid=10001,gid=10001,mode=0700"
    return [
        docker_binary,
        "container",
        "create",
        "--interactive",
        f"--name={name}",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--security-opt=seccomp=builtin",
        f"--user={policy.user}",
        "--ipc=private",
        "--cgroupns=private",
        f"--pids-limit={policy.pids_limit}",
        f"--memory={policy.memory_bytes}",
        f"--cpus={cpus:g}",
        f"--tmpfs={_TMP}:{tmpfs_tmp}",
        f"--tmpfs={_WORKER_DATA}:{tmpfs_worker}",
        policy.image,
    ]


def daemon_is_rootless(security_options: list[str] | tuple[str, ...]) -> bool:
    """Return whether daemon security metadata explicitly reports rootless mode."""
    normalized = {str(item).strip().lower() for item in security_options}
    return any(item == "name=rootless" or item.startswith("name=rootless;") for item in normalized)


def _security_opt_present(options: Any, expected: str) -> bool:
    if not isinstance(options, list):
        return False
    expected_l = expected.lower()
    return any(str(item).lower() == expected_l for item in options)


def _tmpfs_is_restricted(value: Any, *, policy: ContainerIsolationPolicy) -> bool:
    if not isinstance(value, dict):
        return False
    if set(value) != {_TMP, _WORKER_DATA}:
        return False
    common = {"rw", "noexec", "nosuid", f"size={policy.tmpfs_bytes}"}
    required_by_path = {
        _TMP: common | {"mode=1777"},
        _WORKER_DATA: common | {"uid=10001", "gid=10001", "mode=0700"},
    }
    for path, required in required_by_path.items():
        tokens = {token.strip().lower() for token in str(value[path]).split(",")}
        if not required.issubset(tokens):
            return False
    return True


def boundary_manifest_from_inspect(
    *,
    policy: ContainerIsolationPolicy,
    container_id: str,
    inspect_payload: dict[str, Any],
    daemon_security_options: list[str] | tuple[str, ...],
    create_command: list[str],
) -> ExecutionBoundaryManifest:
    """Validate effective runtime controls and compile their immutable manifest."""
    host = inspect_payload.get("HostConfig")
    config = inspect_payload.get("Config")
    if not isinstance(host, dict) or not isinstance(config, dict):
        raise RuntimeError("container inspection missing HostConfig/Config")

    binds = host.get("Binds")
    mounts = inspect_payload.get("Mounts")
    no_host_mounts = (binds in (None, [])) and (mounts in (None, []))
    cap_drop = {str(item).upper() for item in (host.get("CapDrop") or [])}
    device_requests = host.get("DeviceRequests")
    devices = host.get("Devices")

    controls = {
        "daemon_rootless": daemon_is_rootless(daemon_security_options),
        "network_none": str(host.get("NetworkMode") or "") == "none",
        "read_only_root": host.get("ReadonlyRootfs") is True,
        "cap_drop_all": "ALL" in cap_drop,
        "no_new_privileges": _security_opt_present(
            host.get("SecurityOpt"), "no-new-privileges=true"
        ),
        "seccomp_builtin": _security_opt_present(host.get("SecurityOpt"), "seccomp=builtin"),
        "non_root_user": str(config.get("User") or "") == policy.user,
        "no_host_mounts": no_host_mounts,
        "tmpfs_only_writable_paths": _tmpfs_is_restricted(host.get("Tmpfs"), policy=policy),
        "private_ipc": str(host.get("IpcMode") or "") == "private",
        "private_cgroupns": str(host.get("CgroupnsMode") or "") == "private",
        "host_pid_namespace_disabled": str(host.get("PidMode") or "") != "host",
        "privileged_disabled": host.get("Privileged") is False,
        "devices_absent": (devices in (None, [])) and (device_requests in (None, [])),
    }

    observed_pids = int(host.get("PidsLimit") or 0)
    observed_memory = int(host.get("Memory") or 0)
    observed_nano_cpus = int(host.get("NanoCpus") or 0)
    resources_match = (
        observed_pids == policy.pids_limit
        and observed_memory == policy.memory_bytes
        and observed_nano_cpus == policy.nano_cpus
    )
    container_controls_ok = all(
        value for name, value in controls.items() if name != "daemon_rootless"
    )
    rootless_policy_ok = controls["daemon_rootless"] or not policy.require_rootless
    policy_satisfied = container_controls_ok and resources_match and rootless_policy_ok
    security_grade = all(controls.values()) and resources_match

    manifest = ExecutionBoundaryManifest(
        image_ref=policy.image,
        image_digest=policy.image_digest,
        container_id_digest=digest_of({"container_id": container_id}),
        daemon_security_options=tuple(sorted(str(v) for v in daemon_security_options)),
        policy_requires_rootless=policy.require_rootless,
        pids_limit=observed_pids,
        memory_bytes=observed_memory,
        nano_cpus=observed_nano_cpus,
        create_command_digest=digest_of(create_command),
        inspect_digest=digest_of(inspect_payload),
        policy_satisfied=policy_satisfied,
        security_grade=security_grade,
        daemon_rootless=controls["daemon_rootless"],
        network_none=controls["network_none"],
        read_only_root=controls["read_only_root"],
        cap_drop_all=controls["cap_drop_all"],
        no_new_privileges=controls["no_new_privileges"],
        seccomp_builtin=controls["seccomp_builtin"],
        non_root_user=controls["non_root_user"],
        no_host_mounts=controls["no_host_mounts"],
        tmpfs_only_writable_paths=controls["tmpfs_only_writable_paths"],
        private_ipc=controls["private_ipc"],
        private_cgroupns=controls["private_cgroupns"],
        host_pid_namespace_disabled=controls["host_pid_namespace_disabled"],
        privileged_disabled=controls["privileged_disabled"],
        devices_absent=controls["devices_absent"],
    )
    if not manifest.policy_satisfied:
        failed = [
            name
            for name, ok in controls.items()
            if not ok and (name != "daemon_rootless" or policy.require_rootless)
        ]
        if not resources_match:
            failed.append("resource_limits_mismatch")
        raise RuntimeError("container isolation attestation failed: " + ", ".join(failed))
    return manifest


def assert_security_compatible_work_unit(work_unit: dict[str, Any]) -> None:
    """Reject state channels that would require a writable host mount."""
    if work_unit.get("persistent") or work_unit.get("attacker_dir") or work_unit.get("run_dir"):
        raise RuntimeError(
            "isolated worker refuses host-backed mutable attacker state; "
            "use a dedicated state-transfer protocol"
        )
    if "ground_truth_ref" in work_unit:
        raise RuntimeError("isolated worker refuses ground-truth references")


class ContainerWorkerExecutor:
    """Execute one worker request in an inspected, mount-free container."""

    def __init__(
        self,
        policy: ContainerIsolationPolicy,
        *,
        docker_binary: str = "docker",
    ) -> None:
        self.policy = policy
        self.docker_binary = docker_binary

    def _run(
        self,
        args: list[str],
        *,
        input_text: str | None = None,
        timeout: float | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            args,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=check,
        )

    def _daemon_security_options(self) -> list[str]:
        proc = self._run(
            [
                self.docker_binary,
                "info",
                "--format",
                "{{json .SecurityOptions}}",
            ],
            timeout=15.0,
        )
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("cannot parse container daemon security options") from exc
        if not isinstance(data, list):
            raise RuntimeError("container daemon security options are not a list")
        options = [str(item) for item in data]
        if self.policy.require_rootless and not daemon_is_rootless(options):
            raise RuntimeError("security-grade container execution requires a rootless daemon")
        return options

    def execute(self, work_unit: dict[str, Any]) -> dict[str, Any]:
        assert_security_compatible_work_unit(work_unit)
        daemon_options = self._daemon_security_options()
        name = f"valab-worker-{uuid.uuid4().hex[:16]}"
        create_cmd = build_create_command(
            self.policy,
            name=name,
            docker_binary=self.docker_binary,
        )
        container_id: str | None = None
        try:
            created = self._run(create_cmd, timeout=30.0)
            container_id = created.stdout.strip()
            if not container_id:
                raise RuntimeError("container create returned no container id")

            inspected = self._run(
                [self.docker_binary, "container", "inspect", container_id],
                timeout=15.0,
            )
            try:
                inspect_rows = json.loads(inspected.stdout)
            except json.JSONDecodeError as exc:
                raise RuntimeError("cannot parse container inspection") from exc
            if not isinstance(inspect_rows, list) or len(inspect_rows) != 1:
                raise RuntimeError("container inspection must contain exactly one object")
            inspect_payload = inspect_rows[0]
            if not isinstance(inspect_payload, dict):
                raise RuntimeError("container inspection row must be an object")

            boundary = boundary_manifest_from_inspect(
                policy=self.policy,
                container_id=container_id,
                inspect_payload=inspect_payload,
                daemon_security_options=daemon_options,
                create_command=create_cmd,
            )

            request = json.dumps(work_unit, sort_keys=True, separators=(",", ":"))
            executed = self._run(
                [
                    self.docker_binary,
                    "container",
                    "start",
                    "--attach",
                    "--interactive",
                    container_id,
                ],
                input_text=request,
                timeout=self.policy.timeout_s,
                check=False,
            )
            final_inspect = self._run(
                [self.docker_binary, "container", "inspect", container_id],
                timeout=15.0,
            )
            try:
                final_rows = json.loads(final_inspect.stdout)
                if not isinstance(final_rows, list) or len(final_rows) != 1:
                    raise TypeError("unexpected final inspect shape")
                final_payload = final_rows[0]
                if not isinstance(final_payload, dict):
                    raise TypeError("unexpected final inspect row")
                state = final_payload["State"]
                exit_code = int(state["ExitCode"])
            except (json.JSONDecodeError, KeyError, IndexError, TypeError, ValueError) as exc:
                raise RuntimeError("cannot verify worker container exit state") from exc
            if executed.returncode != 0 or exit_code != 0:
                raise RuntimeError(
                    f"isolated worker failed: command_status={executed.returncode}, exit_code={exit_code}"
                )

            try:
                worker_result = json.loads(executed.stdout)
            except json.JSONDecodeError as exc:
                raise RuntimeError("isolated worker emitted invalid JSON") from exc
            if not isinstance(worker_result, dict):
                raise RuntimeError("isolated worker result must be a JSON object")

            record = ContainerExecutionRecord(
                boundary_digest=boundary.content_digest,
                request_digest=digest_of(work_unit),
                worker_result_digest=digest_of(worker_result),
                final_inspect_digest=digest_of(final_payload),
                container_exit_code=exit_code,
                attach_return_code=executed.returncode,
            )
            result = dict(worker_result)
            result["execution_boundary"] = boundary.model_dump(mode="json")
            result["execution_boundary_digest"] = boundary.content_digest
            result["execution_record"] = record.model_dump(mode="json")
            result["execution_record_digest"] = record.content_digest
            return result
        finally:
            if container_id:
                # Cleanup failure must not overwrite the primary execution error.
                with suppress(Exception):
                    self._run(
                        [self.docker_binary, "container", "rm", "--force", container_id],
                        timeout=15.0,
                        check=False,
                    )


__all__ = [
    "ContainerExecutionRecord",
    "ContainerIsolationPolicy",
    "ContainerWorkerExecutor",
    "ExecutionBoundaryManifest",
    "assert_security_compatible_work_unit",
    "boundary_manifest_from_inspect",
    "build_create_command",
    "daemon_is_rootless",
]
