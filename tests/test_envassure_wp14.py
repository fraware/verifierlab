"""WP-14 EnvAssure interoperability tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.assurance.envassure import (
    EnvAssureBundleError,
    build_assurance_chain,
    propagate_envassure_into_qualification,
    verify_frozen_envassure_bundle,
    write_synthetic_frozen_bundle,
)
from verifierlab.config.campaign import load_campaign_dict


def test_synthetic_bundle_verifies_and_binds(tmp_path: Path) -> None:
    path, ref, dig = write_synthetic_frozen_bundle(tmp_path / "bundle.json")
    loaded = verify_frozen_envassure_bundle(path, expected_digest=dig)
    assert loaded.bundle_digest == dig
    assert loaded.is_determinate
    assert ref.digest == loaded.digest


def test_tamper_fail_closed(tmp_path: Path) -> None:
    path, _ref, dig = write_synthetic_frozen_bundle(tmp_path / "bundle.json")
    body = json.loads(path.read_text(encoding="utf-8"))
    body["ir_runtime_digest"] = "f" * 64
    path.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(EnvAssureBundleError, match="tamper|drift"):
        verify_frozen_envassure_bundle(path, expected_digest=dig)


def test_schema_mismatch_fail_closed_with_migration_guidance(tmp_path: Path) -> None:
    path, _ref, _dig = write_synthetic_frozen_bundle(tmp_path / "bundle.json")
    body = json.loads(path.read_text(encoding="utf-8"))
    body["schema_version"] = "99"
    body.pop("content_digest", None)
    body["content_digest"] = digest_of(body)
    path.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(EnvAssureBundleError, match="migration guidance"):
        verify_frozen_envassure_bundle(path)


def test_indeterminate_propagates_despite_verifier_success(tmp_path: Path) -> None:
    _path, ref, _dig = write_synthetic_frozen_bundle(
        tmp_path / "bundle.json", validation_status="indeterminate"
    )
    outcome, reasons = propagate_envassure_into_qualification(env_ref=ref, verifier_success=True)
    assert outcome == "indeterminate"
    assert "verifier_success_cannot_erase_envassure_uncertainty" in reasons


def test_assurance_chain_copies_envassure_status(tmp_path: Path) -> None:
    _path, ref, _dig = write_synthetic_frozen_bundle(
        tmp_path / "bundle.json", validation_status="conflict"
    )
    chain = build_assurance_chain(
        chain_id="chain-1",
        env_ref=ref,
        verifier_assurance_digest="a" * 64,
        agent_configuration_digest="b" * 64,
        proposition_digest="c" * 64,
        applicability_regime="lab-fixture",
    )
    assert chain.chain_indeterminate
    assert chain.envassure_status == "conflict"


def test_campaign_spec_binds_environment_assurance_digest(tmp_path: Path) -> None:
    _, ref, _ = write_synthetic_frozen_bundle(tmp_path / "b.json")
    data = {
        "name": "env-bound",
        "access_model": "black-box",
        "budget": {"max_queries": 1},
        "environment": {"kind": "fake", "ref": "x"},
        "verifier": {"kind": "python", "ref": "y"},
        "ground_truth": {"provider": "planted-oracle"},
        "pinned_versions": {"verifierlab": "0.2.0rc2", "campaign": "x"},
        "environment_assurance": ref.model_dump(mode="json"),
    }
    spec, diags = load_campaign_dict(data)
    assert spec is not None
    assert not any(d.severity.value == "error" for d in diags)
    assert spec.environment_assurance_digest == ref.digest
    dumped = spec.model_dump(mode="json")
    assert dumped["environment_assurance"]["bundle_digest"] == ref.bundle_digest
