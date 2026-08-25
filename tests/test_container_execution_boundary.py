"""Pure tests for the strict container execution policy and attestation."""

from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from verifierlab.execution.container import (
    ContainerExecutionRecord,
    ContainerIsolationPolicy,
    assert_security_compatible_work_unit,
    boundary_manifest_from_inspect,
    build_create_command,
    daemon_is_rootless,
)

IMAGE = "registry.example/verifierlab-worker@sha256:" + "a" * 64


def _policy() -> ContainerIsolationPolicy:
    return ContainerIsolationPolicy(image=IMAGE)


def _inspect(policy: ContainerIsolationPolicy) -> dict[str, object]:
    tmpfs = f"rw,noexec,nosuid,size={policy.tmpfs_bytes}"
    return {
        "Config": {"User": policy.user},
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges=true", "seccomp=builtin"],
            "Binds": None,
            "Tmpfs": {
                "/tmp": tmpfs,
                "/var/lib/verifierlab/worker": tmpfs,
            },
            "IpcMode": "private",
            "CgroupnsMode": "private",
            "PidMode": "",
            "Privileged": False,
            "Devices": [],
            "DeviceRequests": [],
            "PidsLimit": policy.pids_limit,
            "Memory": policy.memory_bytes,
            "NanoCpus": policy.nano_cpus,
        },
        "Mounts": [],
        "State": {"ExitCode": 0},
    }


def _manifest(
    payload: dict[str, object] | None = None,
    *,
    security_options: list[str] | None = None,
):
    policy = _policy()
    command = build_create_command(policy, name="unit-1")
    return boundary_manifest_from_inspect(
        policy=policy,
        container_id="c" * 64,
        inspect_payload=payload or _inspect(policy),
        daemon_security_options=security_options
        or ["name=seccomp,profile=builtin", "name=rootless"],
        create_command=command,
    )


def test_policy_requires_digest_pinned_image() -> None:
    with pytest.raises(ValidationError, match="pinned by sha256 digest"):
        ContainerIsolationPolicy(image="registry.example/verifierlab-worker:latest")


def test_create_command_contains_non_negotiable_controls() -> None:
    policy = _policy()
    command = build_create_command(policy, name="unit-1")
    joined = " ".join(command)
    for required in (
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--security-opt=seccomp=builtin",
        "--user=10001:10001",
        "--ipc=private",
        "--cgroupns=private",
        "--pids-limit=128",
    ):
        assert required in command
    assert "--privileged" not in joined
    assert "--volume" not in joined
    assert "--mount" not in joined
    assert command[-1] == IMAGE


def test_rootless_detection_is_explicit() -> None:
    assert daemon_is_rootless(["name=seccomp,profile=builtin", "name=rootless"]) is True
    assert daemon_is_rootless(["name=seccomp,profile=builtin"]) is False


def test_complete_effective_controls_attest_security_grade() -> None:
    manifest = _manifest()
    assert manifest.security_grade is True
    assert manifest.daemon_rootless is True
    assert manifest.network_none is True
    assert manifest.read_only_root is True
    assert manifest.no_host_mounts is True
    assert manifest.tmpfs_only_writable_paths is True
    assert manifest.content_digest


@pytest.mark.parametrize(
    ("field", "value", "failure"),
    [
        ("NetworkMode", "host", "network_none"),
        ("ReadonlyRootfs", False, "read_only_root"),
        ("CapDrop", [], "cap_drop_all"),
        ("IpcMode", "host", "private_ipc"),
        ("CgroupnsMode", "host", "private_cgroupns"),
        ("PidMode", "host", "host_pid_namespace_disabled"),
        ("Privileged", True, "privileged_disabled"),
    ],
)
def test_changed_effective_control_fails_closed(field: str, value: object, failure: str) -> None:
    policy = _policy()
    payload = _inspect(policy)
    host = payload["HostConfig"]
    assert isinstance(host, dict)
    host[field] = value
    with pytest.raises(RuntimeError, match=failure):
        _manifest(payload)


def test_host_bind_mount_fails_closed() -> None:
    policy = _policy()
    payload = _inspect(policy)
    host = payload["HostConfig"]
    assert isinstance(host, dict)
    host["Binds"] = ["/host/secret:/secret:ro"]
    payload["Mounts"] = [{"Type": "bind", "Source": "/host/secret", "Destination": "/secret"}]
    with pytest.raises(RuntimeError, match="no_host_mounts"):
        _manifest(payload)


def test_missing_rootless_daemon_fails_closed() -> None:
    with pytest.raises(RuntimeError, match="daemon_rootless"):
        _manifest(security_options=["name=seccomp,profile=builtin"])


def test_resource_limit_mismatch_fails_closed() -> None:
    policy = _policy()
    payload = _inspect(policy)
    host = payload["HostConfig"]
    assert isinstance(host, dict)
    host["PidsLimit"] = policy.pids_limit + 1
    with pytest.raises(RuntimeError, match="resource_limits_mismatch"):
        _manifest(payload)


def test_tmpfs_must_be_only_declared_writable_surface() -> None:
    policy = _policy()
    payload = _inspect(policy)
    host = payload["HostConfig"]
    assert isinstance(host, dict)
    tmpfs = deepcopy(host["Tmpfs"])
    assert isinstance(tmpfs, dict)
    tmpfs["/extra"] = "rw"
    host["Tmpfs"] = tmpfs
    with pytest.raises(RuntimeError, match="tmpfs_only_writable_paths"):
        _manifest(payload)


def test_host_backed_state_and_ground_truth_are_refused() -> None:
    with pytest.raises(RuntimeError, match="host-backed mutable attacker state"):
        assert_security_compatible_work_unit({"unit_id": "u", "persistent": True})
    with pytest.raises(RuntimeError, match="host-backed mutable attacker state"):
        assert_security_compatible_work_unit({"unit_id": "u", "attacker_dir": "/host/state"})
    with pytest.raises(RuntimeError, match="ground-truth references"):
        assert_security_compatible_work_unit({"unit_id": "u", "ground_truth_ref": "x:y"})


def test_execution_record_binds_request_result_boundary_and_final_state() -> None:
    base = ContainerExecutionRecord(
        boundary_digest="a" * 64,
        request_digest="b" * 64,
        worker_result_digest="c" * 64,
        final_inspect_digest="d" * 64,
        container_exit_code=0,
        attach_return_code=0,
    )
    changed = base.model_copy(update={"worker_result_digest": "e" * 64})
    assert base.content_digest != changed.content_digest
