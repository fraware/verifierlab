"""Source-boundary regressions for the attack worker plane."""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "verifierlab"


def test_fake_target_contains_no_planted_ground_truth_implementation() -> None:
    text = (SRC / "targets" / "fake.py").read_text(encoding="utf-8")
    assert "PlantedOracleGroundTruth" not in text
    assert "def _is_valid" not in text
    assert "secrets" not in text


def test_targets_namespace_does_not_reexport_ground_truth() -> None:
    text = (SRC / "targets" / "__init__.py").read_text(encoding="utf-8")
    assert "PlantedOracleGroundTruth" not in text
    assert "labels.planted_fake" not in text


def test_planted_oracle_lives_on_labels_plane() -> None:
    text = (SRC / "labels" / "planted_fake.py").read_text(encoding="utf-8")
    assert "class PlantedOracleGroundTruth" in text
    assert "def _is_valid" in text


def test_campaign_package_initializer_does_not_eagerly_import_engine() -> None:
    path = SRC / "campaigns" / "__init__.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    eager_modules: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            eager_modules.add(node.module)
        elif isinstance(node, ast.Import):
            eager_modules.update(alias.name for alias in node.names)
    assert "verifierlab.campaigns.engine" not in eager_modules
    assert "verifierlab.campaigns.lifecycle" not in eager_modules


def test_fake_adjudication_fallback_points_to_labels_plane() -> None:
    text = (SRC / "labels" / "adjudication_service.py").read_text(encoding="utf-8")
    assert "verifierlab.labels.planted_fake:PlantedOracleGroundTruth._is_valid" in text
    assert "verifierlab.targets.fake:PlantedOracleGroundTruth._is_valid" not in text
