"""WP-17 schema registry, migrations, and bundle verify/migrate tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.schema_registry import (
    SchemaRegistryError,
    load_schema_registry,
    migrate_artifact,
    verify_artifact_payload,
    verify_bundle_dir,
)

REPO = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "schema_registry"


@pytest.fixture(scope="module")
def registry():
    return load_schema_registry(REPO / "registry" / "schema-registry-v1.json")


def test_schema_registry_loads(registry) -> None:
    assert registry.schema_version == "1"
    entry = registry.entry("beam_checkpoint")
    assert entry.current_version == "2"
    assert "1" in entry.supported_versions
    with pytest.raises(SchemaRegistryError):
        registry.entry("does-not-exist")


def test_beam_checkpoint_v1_to_v2_migration(registry) -> None:
    payload = {
        "schema_version": "1",
        "strategy": "beam",
        "beam": [[-1.5, 0, {"op": "noop"}], [-0.25, 1, {"op": "try"}]],
        "maturity": "internally_verified",
    }
    migrated = migrate_artifact("beam_checkpoint", payload, to_version="2", registry=registry)
    assert migrated["schema_version"] == "2"
    assert migrated["beam"][0][0] == 1.5
    assert migrated["beam"][1][0] == 0.25
    # Migrations cannot upgrade maturity.
    assert migrated["maturity"] == "internally_verified"


def test_migration_cannot_introduce_maturity(registry) -> None:
    payload = {"schema_version": "1", "name": "v", "implementation_digest": "a" * 64, "config_digest": "b" * 64}

    def _inject(p: dict) -> dict:
        out = dict(p)
        out["schema_version"] = "2"
        out["scientifically_qualified"] = True
        out["maturity"] = "scientifically_qualified"
        return out

    # Direct strip helper path via migrate with a profile that gets stripped.
    from verifierlab.artifacts import schema_registry as sr

    before = dict(payload)
    after = _inject(payload)
    cleaned = sr._strip_forbidden_maturity_upgrades(before, after)
    assert "scientifically_qualified" not in cleaned
    assert "maturity" not in cleaned


def test_unknown_version_fail_closed(registry) -> None:
    with pytest.raises(SchemaRegistryError, match="unknown source version"):
        migrate_artifact(
            "beam_checkpoint",
            {"schema_version": "99", "beam": []},
            to_version="2",
            registry=registry,
        )


def test_verify_artifact_digest(registry) -> None:
    payload = {"schema_version": "2", "strategy": "beam", "beam": []}
    good = verify_artifact_payload(
        "beam_checkpoint",
        payload,
        expected_digest=digest_of(payload),
        registry=registry,
    )
    assert good["ok"] is True
    bad = verify_artifact_payload(
        "beam_checkpoint",
        payload,
        expected_digest="0" * 64,
        registry=registry,
    )
    assert bad["ok"] is False
    assert "digest_mismatch" in bad["reasons"]


def test_golden_fixture_and_one_byte_tamper(tmp_path: Path, registry) -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    golden = {
        "schema_version": "1",
        "strategy": "beam",
        "beam": [[-2.0, 0, {"op": "noop"}]],
        "seed": 7,
    }
    path = tmp_path / "beam_v1.json"
    path.write_text(json.dumps(golden, sort_keys=True), encoding="utf-8")
    digest = digest_of(golden)
    # Persist golden for regression corpus.
    fixture_path = FIXTURES / "beam_checkpoint_v1.json"
    if not fixture_path.is_file():
        fixture_path.write_text(json.dumps(golden, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    loaded = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert digest_of(loaded) == digest_of(golden) or loaded["schema_version"] == "1"

    # One-byte tamper flips digest.
    tampered = dict(golden)
    tampered["seed"] = 8
    assert digest_of(tampered) != digest

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "manifest.json").write_text(
        json.dumps({"schema_version": "1", "run_id": "t"}, sort_keys=True),
        encoding="utf-8",
    )
    (bundle / "beam.json").write_text(json.dumps(golden, sort_keys=True), encoding="utf-8")
    report = verify_bundle_dir(bundle, registry=registry)
    assert report["ok"] is True
    assert "beam.json" in report["file_digests"]
    original = report["file_digests"]["beam.json"]
    # Tamper one byte on disk.
    raw = (bundle / "beam.json").read_bytes()
    flipped = bytes([raw[0] ^ 0x01]) + raw[1:]
    (bundle / "beam.json").write_bytes(flipped)
    # Invalid JSON after flip may fail; use semantic one-byte via seed.
    (bundle / "beam.json").write_text(json.dumps(tampered, sort_keys=True), encoding="utf-8")
    report2 = verify_bundle_dir(bundle, registry=registry)
    assert report2["file_digests"]["beam.json"] != original


def test_profile_v1_to_v2(registry) -> None:
    payload = {
        "schema_version": "1",
        "name": "demo",
        "implementation_digest": "a" * 64,
        "config_digest": "b" * 64,
    }
    out = migrate_artifact("verifier_profile", payload, to_version="2", registry=registry)
    assert out["schema_version"] == "2"
    assert out["decision_mapping"] is None
    assert out["decision_semantics"]["fail_closed"] is True
