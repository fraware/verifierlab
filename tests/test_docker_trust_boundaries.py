"""Structure tests for trust-boundary Docker images (Milestone A3).

These tests do not require a Docker daemon. They assert Dockerfile invariants
and entrypoint import / path bans that separate CLI, worker, and adjudicator.
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


@pytest.mark.parametrize("role", ("cli", "worker", "adjudicator", "rllib"))
def test_dockerfile_non_root_and_labels(role: str) -> None:
    text = _dockerfile(role).read_text(encoding="utf-8")
    assert re.search(r"^USER\s+10001", text, re.M), f"{role} must run as non-root USER 10001"
    assert "org.opencontainers.image.title=" in text or 'org.opencontainers.image.title="' in text
    assert f'io.verifierlab.role="{role}"' in text or f"io.verifierlab.role={role}" in text
    assert "io.verifierlab.trust-boundary=" in text
    # Prefer digest-pinned bases where practical (rllib stub included).
    assert "@sha256:" in text or "PYTHON_BASE" in text


def test_rllib_marked_post_qualification() -> None:
    text = _dockerfile("rllib").read_text(encoding="utf-8")
    # Partial qualification until full release-image smoke lands (Milestone C/D).
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


def test_worker_entrypoint_bans_vault_and_release() -> None:
    path = DOCKER / "worker" / "entrypoint.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    forbidden_literals: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            forbidden_literals.add(node.value)
    assert "verifierlab.labels.vault" in forbidden_literals
    assert "release-labels" in forbidden_literals
    assert "adjudicate" in forbidden_literals


def test_adjudicator_entrypoint_bans_campaign_run() -> None:
    text = (DOCKER / "adjudicator" / "entrypoint.py").read_text(encoding="utf-8")
    assert 'argv[1] == "run"' in text or "forbids campaign run" in text
    assert "verifierlab.attacks.rl" in text


def test_cli_entrypoint_exists_and_sets_role() -> None:
    text = (DOCKER / "cli" / "entrypoint.py").read_text(encoding="utf-8")
    assert 'ROLE = "cli"' in text
    assert "verifierlab.cli" in text


def test_worker_and_adjudicator_do_not_share_default_path_constant() -> None:
    worker = (DOCKER / "worker" / "entrypoint.py").read_text(encoding="utf-8")
    adj = (DOCKER / "adjudicator" / "entrypoint.py").read_text(encoding="utf-8")
    w_match = re.search(r'VALAB_DATA",\s*"([^"]+)"', worker)
    a_match = re.search(r'VALAB_DATA",\s*"([^"]+)"', adj)
    assert w_match and a_match
    assert w_match.group(1) != a_match.group(1)
