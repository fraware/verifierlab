"""Structural tests for role-separated container images.

These tests do not require a container daemon. They verify source and image
recipe invariants. Runtime network, mount, filesystem, capability, and resource
isolation require separate execution tests.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DOCKER = REPO / "docker"

ROLES = ("cli", "worker", "adjudicator", "rllib")


def _dockerfile(role: str) -> Path:
    return DOCKER / role / "Dockerfile"


@pytest.mark.parametrize("role", ROLES)
def test_dockerfile_exists(role: str) -> None:
    path = _dockerfile(role)
    assert path.is_file(), f"missing Dockerfile for {role}"


@pytest.mark.parametrize("role", ROLES)
def test_dockerfile_non_root_and_labels(role: str) -> None:
    text = _dockerfile(role).read_text(encoding="utf-8")
    assert re.search(r"^USER\s+10001", text, re.M), f"{role} must run as non-root USER 10001"
    assert "org.opencontainers.image.title=" in text or 'org.opencontainers.image.title="' in text
    assert f'io.verifierlab.role="{role}"' in text or f"io.verifierlab.role={role}" in text
    assert "io.verifierlab.trust-boundary=" in text
    assert "@sha256:" in text or "PYTHON_BASE" in text


def test_rllib_marked_post_qualification() -> None:
    text = _dockerfile("rllib").read_text(encoding="utf-8")
    assert (
        "post-qualification" in text.lower()
        or "partial-qualification" in text.lower()
        or "PARTIAL QUALIFICATION" in text
    )
    assert "integration_conformance" in text or "integration conformance" in text.lower()


def test_distinct_default_data_paths() -> None:
    paths: dict[str, str] = {}
    for role in ("cli", "worker", "adjudicator"):
        text = _dockerfile(role).read_text(encoding="utf-8")
        match = re.search(r"VALAB_DATA=(\S+)", text)
        assert match, f"{role} must set VALAB_DATA"
        paths[role] = match.group(1)
    assert len(set(paths.values())) == 3, f"roles must not share data paths: {paths}"


def test_worker_image_physically_prunes_coordinator_surfaces() -> None:
    text = _dockerfile("worker").read_text(encoding="utf-8")
    for surface in ("labels", "repairs", "disclosure", "reports", "cli"):
        assert f'"{surface}"' in text
    assert '"campaigns/engine.py"' in text
    assert '"campaigns/lifecycle.py"' in text
    assert "shutil.rmtree" in text
    assert "target.unlink" in text
    assert "worker image pruning failed" in text


def test_worker_entrypoint_is_one_shot_not_general_cli() -> None:
    path = DOCKER / "worker" / "entrypoint.py"
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text)

    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)

    assert "verifierlab.cli" not in imports
    assert "from verifierlab.campaigns.worker import execute_work_unit" in text
    assert "_assert_pruned_runtime()" in text
    assert "worker accepts at most one JSON request file" in text
    for surface in ("labels", "repairs", "disclosure", "reports", "cli"):
        assert f'"{surface}"' in text


def test_adjudicator_entrypoint_bans_campaign_run() -> None:
    text = (DOCKER / "adjudicator" / "entrypoint.py").read_text(encoding="utf-8")
    assert 'argv[1] == "run"' in text or "forbids campaign run" in text
    assert "verifierlab.attacks.rl" in text


def test_cli_entrypoint_exists_and_sets_role() -> None:
    text = (DOCKER / "cli" / "entrypoint.py").read_text(encoding="utf-8")
    assert 'ROLE = "cli"' in text
    assert "verifierlab.cli" in text


def test_worker_and_adjudicator_do_not_share_default_path() -> None:
    worker = _dockerfile("worker").read_text(encoding="utf-8")
    adj = _dockerfile("adjudicator").read_text(encoding="utf-8")
    w_match = re.search(r"VALAB_DATA=(\S+)", worker)
    a_match = re.search(r"VALAB_DATA=(\S+)", adj)
    assert w_match and a_match
    assert w_match.group(1) != a_match.group(1)
