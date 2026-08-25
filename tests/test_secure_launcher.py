"""Fail-closed security-grade launcher and probe catalogue tests."""

from __future__ import annotations

import os

import pytest

from verifierlab.execution.microvm import MicroVMExecutionBackend, SeparateHostExecutionBackend
from verifierlab.execution.probes import (
    REQUIRED_PROBE_IDS,
    inject_secret_sentinels,
    randomized_gt_guess_paths,
    run_malicious_probe_catalogue,
)
from verifierlab.execution.protocol import ExecutionPolicy
from verifierlab.execution.secure import (
    SecurityGradeRefused,
    assert_local_dev_maturity_cap,
    negotiate_execution_capabilities,
    select_secure_launcher,
)

IMAGE = "registry.example/verifierlab-worker@sha256:" + "b" * 64


def test_local_dev_maturity_cap_is_hard() -> None:
    policy = ExecutionPolicy(mode="local_dev")
    assert_local_dev_maturity_cap(policy)
    assert policy.local_dev_maturity_cap == "development_only"


def test_security_grade_refuses_without_rootless_docker() -> None:
    policy = ExecutionPolicy(
        mode="security_grade",
        worker_image=IMAGE,
        require_rootless=True,
    )
    negotiation = negotiate_execution_capabilities(policy)
    # On this Windows/hosted tree Docker rootless is typically unavailable.
    if not negotiation.daemon_rootless or not negotiation.docker_available:
        assert negotiation.refused is True
        assert negotiation.may_degrade_to_local is False
        with pytest.raises(SecurityGradeRefused):
            select_secure_launcher(policy)
    else:
        launcher = select_secure_launcher(policy)
        assert launcher.backend_kind == "docker_rootless"


def test_security_grade_never_selects_local_backend() -> None:
    policy = ExecutionPolicy(mode="security_grade", worker_image="not-pinned")
    negotiation = negotiate_execution_capabilities(policy)
    assert negotiation.refused is True
    assert negotiation.selected_backend is None
    assert "worker_image_not_digest_pinned" in negotiation.refusal_reasons
    assert negotiation.may_degrade_to_local is False


def test_microvm_and_separate_host_interfaces_exist_but_refuse() -> None:
    micro = MicroVMExecutionBackend()
    separate = SeparateHostExecutionBackend()
    assert micro.available() is False
    assert separate.available() is False
    policy = ExecutionPolicy(mode="security_grade", backend="microvm", worker_image=IMAGE)
    negotiation = negotiate_execution_capabilities(policy, microvm_available=False)
    assert negotiation.refused is True
    assert "microvm_backend_unavailable" in negotiation.refusal_reasons


def test_probe_catalogue_covers_required_ids_and_marks_structural_honestly() -> None:
    sentinels = inject_secret_sentinels()
    # Inject into process env then prove catalogue detects them when present.
    key = next(iter(sentinels))
    os.environ[key] = sentinels[key]
    try:
        report = run_malicious_probe_catalogue(
            backend_kind="local_dev",
            ran_inside_executor=False,
            secret_sentinels=sentinels,
            gt_guess_seed=7,
        )
    finally:
        os.environ.pop(key, None)
    assert {o.probe_id for o in report.outcomes} == set(REQUIRED_PROBE_IDS)
    assert report.structural_only is True
    assert report.ran_inside_executor is False
    assert report.security_grade_eligible is False
    assert any(
        o.probe_id == "secret_sentinel_search" and not o.denied_or_absent for o in report.outcomes
    )


def test_probe_catalogue_without_sentinels_still_not_security_grade_off_executor() -> None:
    report = run_malicious_probe_catalogue(
        backend_kind="docker_rootless",
        ran_inside_executor=False,
        secret_sentinels={},
        gt_guess_seed=3,
    )
    assert report.security_grade_eligible is False
    assert report.structural_only is True


def test_randomized_gt_paths_are_not_a_fixed_denylist() -> None:
    a = randomized_gt_guess_paths(seed=1, count=8)
    b = randomized_gt_guess_paths(seed=2, count=8)
    assert a != b
    assert len(a) == 8
