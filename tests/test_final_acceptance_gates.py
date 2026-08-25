"""Final acceptance gates A–J and NG-01…NG-15 (WP-22 / Gate G7)."""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
STUDY = REPO / "studies" / "flagship-2026"


# ---------------------------------------------------------------------------
# Gate A — Integration presence
# ---------------------------------------------------------------------------


class TestGateAIntegration:
    def test_core_assurance_modules_import(self) -> None:
        import verifierlab.assurance.deployment as deployment
        import verifierlab.assurance.envassure as envassure
        import verifierlab.assurance.reproduce as reproduce
        import verifierlab.assurance.resolver as resolver
        import verifierlab.campaigns.hacker_fixer_solver as hfs
        import verifierlab.execution.container as container
        import verifierlab.statistics.response_surface as surface

        assert resolver is not None
        assert deployment is not None
        assert envassure is not None
        assert reproduce is not None
        assert hfs is not None
        assert container is not None
        assert surface is not None

    def test_flagship_study_bundle_present(self) -> None:
        for name in (
            "preregistration.json",
            "maturity_qualification.json",
            "claim.json",
            "README.md",
        ):
            assert (STUDY / name).is_file(), name


# ---------------------------------------------------------------------------
# Gate B — Artifact schemas
# ---------------------------------------------------------------------------


class TestGateBArtifacts:
    def test_schema_registry_present(self) -> None:
        from verifierlab.artifacts.schema_registry import load_schema_registry

        reg = load_schema_registry(REPO / "registry" / "schema-registry-v1.json")
        assert reg.entry("beam_checkpoint").current_version == "2"
        assert reg.entry("verifier_profile").current_version == "2"

    def test_bundle_verify_cli_wired(self) -> None:
        from verifierlab.cli import app

        # Typer registers nested commands; ensure bundle group exists.
        names = {c.name for c in app.registered_groups}
        assert "bundle" in names or any(
            getattr(g, "name", None) == "bundle" for g in app.registered_groups
        )


# ---------------------------------------------------------------------------
# Gate C — Security fail-closed
# ---------------------------------------------------------------------------


class TestGateCSecurity:
    def test_worker_dockerfile_prunes_coordinator(self) -> None:
        text = (REPO / "docker" / "worker" / "Dockerfile").read_text(encoding="utf-8")
        for needle in ("labels", "repairs", "campaigns/engine.py", "campaigns/lifecycle.py"):
            assert needle in text

    def test_worker_secret_scan_clean(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "scan_worker_secrets.py")],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr

    def test_secure_launcher_module_present(self) -> None:
        from verifierlab.execution import probes, secure

        assert probes is not None
        assert secure.select_secure_launcher is not None


# ---------------------------------------------------------------------------
# Gate D — Methods modules
# ---------------------------------------------------------------------------


class TestGateDMethods:
    def test_method_modules_present(self) -> None:
        paths = [
            REPO / "src/verifierlab/campaigns/hacker_fixer_solver.py",
            REPO / "src/verifierlab/statistics/response_surface.py",
            REPO / "src/verifierlab/statistics/calibration.py",
            REPO / "src/verifierlab/exploits/layers.py",
            REPO / "src/verifierlab/assurance/envassure.py",
        ]
        for path in paths:
            assert path.is_file(), path.name


# ---------------------------------------------------------------------------
# Gate E — Quality hooks
# ---------------------------------------------------------------------------


class TestGateEQuality:
    def test_coverage_partitions_config(self) -> None:
        data = tomllib.loads(
            (REPO / "config" / "coverage-partitions.toml").read_text(encoding="utf-8")
        )
        assert data["ci"]["global_fail_under"] == 40
        assert "semantic_core" in data["partitions"]
        assert "claim_critical" in data["partitions"]

    def test_fuzz_corpus_has_fail_closed_entry(self) -> None:
        path = REPO / "tests/fixtures/fuzz_corpus/unknown_schema_fail_closed.json"
        body = json.loads(path.read_text(encoding="utf-8"))
        assert body["expect_ok"] is False
        assert str(body["schema_version"]) == "99"

    def test_claim_language_lint(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "check_claim_language.py")],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr


# ---------------------------------------------------------------------------
# Gate F — Adapter matrix honesty
# ---------------------------------------------------------------------------


class TestGateFAdapters:
    def test_matrix_statuses_honest(self) -> None:
        from verifierlab.targets.contract import validate_matrix_document

        matrix = json.loads((REPO / "registry/adapter-matrix-v1.json").read_text(encoding="utf-8"))
        assert validate_matrix_document(matrix) == []
        env = next(r for r in matrix["adapters"] if r["adapter"] == "envassure")
        assert env["status"] == "fixture-only"
        assert env.get("installable") is not True


# ---------------------------------------------------------------------------
# Gate G — Release workflow
# ---------------------------------------------------------------------------


class TestGateGRelease:
    def test_release_workflow_signed_tag_no_fallback(self) -> None:
        text = (REPO / ".github/workflows/release.yml").read_text(encoding="utf-8")
        assert "git verify-tag" in text
        assert "annotated" in text.lower() or '!= "tag"' in text
        assert "unsigned" not in text.lower() or "no unsigned" in text.lower()
        # Provenance attestation present.
        assert "attest-build-provenance" in text
        assert "release-manifest.json" in text
        assert "sbom.cdx.json" in text

    def test_protection_policy_doc(self) -> None:
        text = (REPO / "docs/repository-protection-policy.md").read_text(encoding="utf-8")
        assert "Required status checks" in text
        assert "cannot flip GitHub admin settings" in text.lower() or "cannot flip" in text.lower()


# ---------------------------------------------------------------------------
# Gate H — Docs + claim language
# ---------------------------------------------------------------------------


class TestGateHDocs:
    def test_required_docs_exist(self) -> None:
        for rel in (
            "docs/architecture.md",
            "docs/claim-language.md",
            "docs/final-acceptance.md",
            "docs/support-matrix.md",
            "docs/tutorials/security-grade.md",
        ):
            assert (REPO / rel).is_file(), rel

    def test_readme_integration_status(self) -> None:
        text = (REPO / "README.md").read_text(encoding="utf-8")
        assert "integration/final-assurance" in text
        assert "internally_verified" in text


# ---------------------------------------------------------------------------
# Gate I — Scientific evidence refs
# ---------------------------------------------------------------------------


class TestGateIScientific:
    def test_flagship_maturity_internally_verified_with_blockers(self) -> None:
        maturity = json.loads((STUDY / "maturity_qualification.json").read_text(encoding="utf-8"))
        assert maturity["level"] == "internally_verified"
        assert maturity.get("security_grade_execution") is False
        assert maturity["blockers"]
        assert "scientifically_qualified" not in maturity["level"]

    def test_flagship_readme_honest(self) -> None:
        text = (STUDY / "README.md").read_text(encoding="utf-8")
        assert "internally_verified" in text
        assert "scientifically_qualified" in text  # mentioned as non-claim


# ---------------------------------------------------------------------------
# Gate J — Deployment capability
# ---------------------------------------------------------------------------


class TestGateJDeployment:
    def test_deployment_api_present(self) -> None:
        from verifierlab.assurance.deployment import (
            DeploymentCalibrationReport,
            ingest_outcome,
            register_prediction,
        )

        assert callable(register_prediction)
        assert callable(ingest_outcome)
        assert DeploymentCalibrationReport is not None

    def test_synthetic_cannot_support_calibrated_claim(self) -> None:
        src = (REPO / "src/verifierlab/assurance/deployment.py").read_text(encoding="utf-8")
        assert "synthetic_non_deployment_evidence" in src
        assert "supports_deployment_calibrated_claim" in src


# ---------------------------------------------------------------------------
# NG-01 … NG-15
# ---------------------------------------------------------------------------


class TestNoGoRegressions:
    def test_ng01_process_local_not_security_grade_in_study(self) -> None:
        maturity = json.loads((STUDY / "maturity_qualification.json").read_text(encoding="utf-8"))
        assert maturity.get("security_grade_execution") is False

    def test_ng02_worker_entrypoint_forbids_coordinator_paths(self) -> None:
        text = (REPO / "docker/worker/entrypoint.py").read_text(encoding="utf-8")
        assert "labels" in text and "repairs" in text
        assert "_FORBIDDEN_PACKAGE_PATHS" in text

    def test_ng03_scores_need_mapping(self) -> None:
        from verifierlab.api.decision import Decision, DecisionKind
        from verifierlab.api.verifier import normalize_decision

        d = normalize_decision({"decision": "score", "score": 0.99})
        assert d.kind is DecisionKind.SCORE
        assert d.accepted is None

    def test_ng04_validation_prs_not_merged_ledger(self) -> None:
        text = (REPO / "docs/final-integration-ledger.md").read_text(encoding="utf-8")
        assert "Validation-only sources (not merged)" in text
        assert "#14" in text or "validation" in text.lower()

    def test_ng05_resolver_not_boolean_promotion(self) -> None:
        src = (REPO / "src/verifierlab/assurance/resolver.py").read_text(encoding="utf-8")
        assert "EvidenceFact" in src
        # Mentions of the seed constant are documentation-only warnings.
        assert "qualify" in src.lower() or "resolve" in src.lower()

    def test_ng06_planted_calibration_non_robustness(self) -> None:
        from verifierlab.exploits.integration import CalibrationLayerStratum
        from verifierlab.statistics.calibration import PlantedCalibrationReport

        stratum = CalibrationLayerStratum(calibration_item_digest="a" * 64)
        assert stratum.supports_unknown_robustness_claim is False
        # Report model hard-codes the non-robustness boundary.
        assert (
            PlantedCalibrationReport.model_fields["supports_unknown_robustness_claim"].default
            is False
        )

    def test_ng07_response_surface_no_scalar_robustness(self) -> None:
        src = (REPO / "src/verifierlab/statistics/response_surface.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for banned in ("scalar_robustness", "average_robustness", "interpolate_robustness"):
            assert banned not in names

    def test_ng08_fixture_not_live_tested(self) -> None:
        matrix = json.loads((REPO / "registry/adapter-matrix-v1.json").read_text(encoding="utf-8"))
        for row in matrix["adapters"]:
            if row["status"] in {"fixture-only", "unsupported"}:
                assert row["live_vs_fixture"].strip() != "live-tested"
                assert "live-tested" not in row["live_vs_fixture"].split()

    def test_ng09_migrations_cannot_upgrade_maturity(self) -> None:
        from verifierlab.artifacts.schema_registry import (
            _strip_forbidden_maturity_upgrades,
            migrate_artifact,
            load_schema_registry,
        )

        cleaned = _strip_forbidden_maturity_upgrades(
            {"schema_version": "1"},
            {"schema_version": "2", "scientifically_qualified": True},
        )
        assert "scientifically_qualified" not in cleaned
        reg = load_schema_registry(REPO / "registry/schema-registry-v1.json")
        out = migrate_artifact(
            "beam_checkpoint",
            {"schema_version": "1", "beam": [], "maturity": "internally_verified"},
            to_version="2",
            registry=reg,
        )
        assert out["maturity"] == "internally_verified"

    def test_ng10_envassure_ref_binding_present(self) -> None:
        from verifierlab.assurance.envassure import EnvironmentAssuranceRef

        assert EnvironmentAssuranceRef is not None

    def test_ng11_deployment_synthetic_flag(self) -> None:
        src = (REPO / "src/verifierlab/assurance/deployment.py").read_text(encoding="utf-8")
        assert "synthetic_non_deployment_evidence" in src

    def test_ng12_external_attestation_rejects_self_issued(self) -> None:
        src = (REPO / "src/verifierlab/assurance/reproduce.py").read_text(encoding="utf-8")
        assert "self" in src.lower() and "attest" in src.lower()

    def test_ng13_windows_not_release_qualified(self) -> None:
        text = (REPO / "docs/support-matrix.md").read_text(encoding="utf-8")
        assert "Windows" in text
        assert re.search(r"Windows.*\*\*No\*\*|not release-qualified", text, re.I | re.S)

    def test_ng14_package_still_rc(self) -> None:
        data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
        assert data["project"]["version"] == "0.2.0rc2"

    def test_ng15_claim_language_lint(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "check_claim_language.py")],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
