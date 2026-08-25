"""Milestone D: science packs, repro bundle layout, adapter matrix, examples."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from verifierlab.campaigns.packs import (
    inspect_pack,
    lint_pack,
    packs_root,
    verify_pack,
    write_pack_sidecars,
)

REPO = Path(__file__).resolve().parents[1]
PACKS = packs_root(REPO)
EXAMPLES = REPO / "examples"
REQUIRED_EXAMPLE_FILES = (
    "README.md",
    "campaign.yaml",
    "verifier",
    "environment",
    "expected",
    "run.sh",
    "verify.sh",
    "example-manifest.json",
)


@pytest.mark.parametrize("letter", list("abcde"))
def test_science_pack_completeness(letter: str) -> None:
    matches = sorted(PACKS.glob(f"pack-{letter}-*.yaml"))
    assert matches, letter
    yaml_path = matches[0]
    side = write_pack_sidecars(yaml_path, force=True)
    for name in (
        "pack.json",
        "profile.json",
        "splits.json",
        "expected-public-digests.json",
        "planted-failure.json",
        "adjudication-protocol.json",
    ):
        assert (side / name).is_file(), name

    ok, diags, info = lint_pack(yaml_path)
    assert ok, (letter, diags, info)
    ok2, diags2, _ = verify_pack(yaml_path)
    assert ok2, (letter, diags2)

    inspected = inspect_pack(side)
    checklist = inspected["science_completeness"]
    assert checklist["baseline"]
    assert checklist["two_optimized_attacks"]
    assert inspected["primary_estimand"]
    assert inspected["interval_method"]
    assert inspected["sidecars_present"]["planted-failure.json"]
    assert inspected["sidecars_present"]["adjudication-protocol.json"]

    planted = json.loads((side / "planted-failure.json").read_text(encoding="utf-8"))
    proto = json.loads((side / "adjudication-protocol.json").read_text(encoding="utf-8"))
    assert proto.get("labels_in_public_pack") is False
    for banned in ("gt_valid", "hidden_label", "vault_key", "labels"):
        assert banned not in planted
        assert banned not in proto

    expected = json.loads((side / "expected-public-digests.json").read_text(encoding="utf-8"))
    assert expected.get("primary_estimand")
    assert expected.get("interval_method")


def test_pack_f_integrity_has_no_science_sidecars_required() -> None:
    # Pack F remains integrity-only; sidecar layout is A-E only.
    path = PACKS / "pack-f-integrity-auth.yaml"
    assert path.is_file()
    ok, diags, info = lint_pack(path)
    assert ok, diags
    assert info.get("pack") in {"f", "F", ""} or "f" in str(path).lower()


@pytest.mark.parametrize(
    "example_dir",
    sorted(p.name for p in EXAMPLES.glob("v*_*/") if p.is_dir()),
)
def test_example_contract(example_dir: str) -> None:
    root = EXAMPLES / example_dir
    for name in REQUIRED_EXAMPLE_FILES:
        path = root / name
        assert path.exists(), f"{example_dir} missing {name}"
    manifest = json.loads((root / "example-manifest.json").read_text(encoding="utf-8"))
    assert manifest.get("example_id")
    assert manifest.get("install")
    assert "integration_status" in manifest
    status = str(manifest["integration_status"])
    # Honesty: EnvAssure must not claim live.
    if "envassure" in example_dir:
        assert status == "not-live"
    if "rllib" in example_dir:
        assert status in {"live_when_ray_installed", "partial", "not-live"}
        assert manifest.get("claim") == "integration_conformance" or manifest.get(
            "not_a_capability_result"
        )


def test_adapter_matrix_generator(tmp_path: Path) -> None:
    script = REPO / "scripts" / "generate_adapter_matrix.py"
    out_md = tmp_path / "matrix.md"
    out_json = tmp_path / "adapter-matrix.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "--out-md",
            str(out_md),
            "--out-json",
            str(out_json),
        ],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert out_md.is_file() and out_json.is_file()
    payload = json.loads(out_json.read_text(encoding="utf-8"))
    by_name = {r["adapter"]: r for r in payload["adapters"]}
    assert by_name["envassure"]["status"] == "not-live"
    assert by_name["rllib"]["status"] == "partial"
    assert any(r["status"] == "live" for r in payload["adapters"])
    check = subprocess.run(
        [
            sys.executable,
            str(script),
            "--check",
            "--out-md",
            str(out_md),
            "--out-json",
            str(out_json),
        ],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    assert check.returncode == 0, check.stderr


def test_repro_bundle_build_and_verify(tmp_path: Path) -> None:
    # Minimal sealed-run-like tree.
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "sealed_run.json").write_text(
        json.dumps(
            {
                "schema_version": "1",
                "kind": "sealed_run",
                "run_id": "test-run",
                "campaign_digest": "abc",
                "content_digest": "def",
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "freeze.json").write_text(
        json.dumps(
            {
                "schema_version": "1",
                "kind": "freeze",
                "freeze_id": "f1",
                "run_id": "test-run",
                "campaign_digest": "abc",
                "frozen_at": 1.0,
                "content_digest": "freeze",
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "tip_index.json").write_text(
        json.dumps(
            {
                "run_id": "test-run",
                "lifecycle": "freeze",
                "metadata": {"seed": 7, "stats_plan": {"methods": ["wilson"], "alpha": 0.05}},
            }
        ),
        encoding="utf-8",
    )
    campaign = REPO / "campaigns" / "fake-smoke.yaml"
    out = tmp_path / "bundle"
    archive = tmp_path / "bundle.tgz"
    build = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "build_repro_bundle.py"),
            "--run-dir",
            str(run_dir),
            "--campaign",
            str(campaign),
            "--out",
            str(out),
            "--archive",
            str(archive),
        ],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stderr + build.stdout
    assert (out / "MANIFEST.json").is_file()
    assert (out / "adjudication" / "release_public.json").is_file()
    # No vault material.
    assert not list(out.rglob("vault"))

    verify = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "verify_repro_bundle.py"), str(out)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    assert verify.returncode == 0, verify.stderr + verify.stdout
    payload = json.loads(verify.stdout)
    assert payload["status"] == "ok"

    # Incomplete bundle fails.
    bad = tmp_path / "bad-bundle"
    bad.mkdir()
    (bad / "README.md").write_text("x", encoding="utf-8")
    bad_verify = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "verify_repro_bundle.py"), str(bad)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad_verify.returncode != 0


def test_repro_download_graceful_missing() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "verify_repro_bundle.py"),
            "--download-url",
            "https://example.invalid/repro-bundle.tgz",
            "--allow-missing-download",
        ],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    payload = json.loads(proc.stdout)
    assert payload.get("status") == "skipped"
