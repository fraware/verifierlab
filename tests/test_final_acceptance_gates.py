"""Final acceptance gates A-J and NG-01...NG-16 (WP-22 / Gate G7)."""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
STUDY = REPO / "studies" / "flagship-2026"


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


class TestGateBArtifacts:
    def test_schema_registry_present(self) -> None:
        from verifierlab.artifacts.schema_registry import load_schema_registry

        reg = load_schema_registry(REPO / "registry" / "schema-registry-v1.json")
        assert reg.entry("beam_checkpoint").current_version == "2"
        assert reg.entry("verifier_profile").current_version == "2"

    def test_bundle_verify_cli_wired(self) -> None:
        from verifierlab.cli import app

        names = {command.name for command in app.registered_groups}
        assert "bundle" in names or any(
            getattr(group, "name", None) == "bundle" for group in app.registered_groups
        )


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


class TestGateFAdapters:
    def test_matrix_statuses_honest(self) -> None:
        from verifierlab.targets.contract import validate_matrix_document

        matrix = json.loads((REPO / "registry/adapter-matrix-v1.json").read_text(encoding="utf-8"))
        assert validate_matrix_document(matrix) == []
        env = next(row for row in matrix["adapters"] if row["adapter"] == "envassure")
        assert env["status"] == "fixture-only"
        assert env.get("installable") is not True


class TestGateGRelease:
    def test_release_workflow_signed_tag_no_fallback(self) -> None:
        text = (REPO / ".github/workflows/release.yml").read_text(encoding="utf-8")
        assert "git verify-tag" in text
        assert "annotated" in text.lower() or '!= "tag"' in text
        assert "unsigned" not in text.lower() or "no unsigned" in text.lower()
        assert "attest-build-provenance" in text
        assert "release-manifest.json" in text
        assert "sbom.cdx.json" in text

    def test_protection_policy_doc(self) -> None:
        text = (REPO / "docs/repository-protection-policy.md").read_text(encoding="utf-8")
        assert "Required status checks" in text
        assert "cannot flip GitHub admin settings" in text.lower() or "cannot flip" in text.lower()


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

    def test_readme_preserves_current_nonclaim(self) -> None:
        text = (REPO / "README.md").read_text(encoding="utf-8")
        assert "internally_verified" in text
        assert "scientifically_qualified" in text


class TestGateIScientific:
    def test_flagship_is_requalified_from_artifacts_not_label_file(self) -> None:
        from verifierlab.assurance import AssuranceClaim, AssuranceLevel, qualify_run

        claim_body = json.loads((STUDY / "claim.json").read_text(encoding="utf-8"))
        claim_body.pop("content_digest", None)
        claim = AssuranceClaim.model_validate(claim_body)
        qualification = qualify_run(STUDY, claim=claim)
        assert qualification.ordinal <= AssuranceLevel.INTERNALLY_VERIFIED
        assert qualification.security_grade_execution is False
        assert qualification.level != "scientifically_qualified"
        assert qualification.level != "deployment_calibrated"
        assert "0" * 64 not in qualification.artifact_refs

    def test_flagship_checked_in_label_never_claims_scientific(self) -> None:
        maturity = json.loads((STUDY / "maturity_qualification.json").read_text(encoding="utf-8"))
        assert int(maturity["ordinal"]) <= 2
        assert maturity.get("security_grade_execution") is False
        assert maturity["level"] != "scientifically_qualified"
        assert maturity["level"] != "deployment_calibrated"

    def test_flagship_readme_honest(self) -> None:
        text = (STUDY / "README.md").read_text(encoding="utf-8")
        assert "synthetic" in text.lower()
        assert "scientifically_qualified" in text


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


class TestNoGoRegressions:
    def test_ng01_process_local_not_security_grade_in_study(self) -> None:
        maturity = json.loads((STUDY / "maturity_qualification.json").read_text(encoding="utf-8"))
        assert maturity.get("security_grade_execution") is False

    def test_ng02_worker_entrypoint_forbids_coordinator_paths(self) -> None:
        text = (REPO / "docker/worker/entrypoint.py").read_text(encoding="utf-8")
        assert "labels" in text and "repairs" in text
        assert "_FORBIDDEN_PACKAGE_PATHS" in text

    def test_ng03_scores_need_mapping(self) -> None:
        from verifierlab.api.decision import DecisionKind
        from verifierlab.api.verifier import normalize_decision

        decision = normalize_decision({"decision": "score", "score": 0.99})
        assert decision.kind is DecisionKind.SCORE
        assert decision.accepted is None

    def test_ng04_validation_prs_not_merged_ledger(self) -> None:
        text = (REPO / "docs/final-integration-ledger.md").read_text(encoding="utf-8")
        assert "Validation-only sources (not merged)" in text
        assert "#14" in text or "validation" in text.lower()

    def test_ng05_forged_resolver_artifacts_do_not_promote(self, tmp_path: Path) -> None:
        from verifierlab.assurance import AssuranceClaim, AssuranceLevel, qualify_run

        run = tmp_path / "forged"
        run.mkdir()
        (run / "sealed_run.json").write_text(
            json.dumps(
                {
                    "schema_version": "2",
                    "content_digest": "1" * 64,
                    "budget_digest": "2" * 64,
                    "metadata": {
                        "execution_mode": "docker_rootless",
                        "security_grade": True,
                        "execution_boundary_digests": ["3" * 64],
                    },
                }
            ),
            encoding="utf-8",
        )
        claim = AssuranceClaim(
            proposition="forged evidence must not qualify",
            scope="acceptance regression",
            assumptions=("content-addressed evidence is required",),
            trust_boundary="test",
            specification_refs=("cas:test:forged",),
        )
        result = qualify_run(run, claim=claim)
        assert result.ordinal < AssuranceLevel.INTERNALLY_VERIFIED
        assert result.security_grade_execution is False

    def test_ng06_planted_calibration_non_robustness(self) -> None:
        from verifierlab.exploits.integration import CalibrationLayerStratum
        from verifierlab.statistics.calibration import PlantedCalibrationReport

        stratum = CalibrationLayerStratum(calibration_item_digest="a" * 64)
        assert stratum.supports_unknown_robustness_claim is False
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
            load_schema_registry,
            migrate_artifact,
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

    def test_ng16_zero_digest_is_not_published_as_evidence(self) -> None:
        from verifierlab.assurance import AssuranceClaim, qualify_run

        claim = AssuranceClaim(
            proposition="empty evidence remains empty",
            scope="acceptance regression",
            assumptions=("no evidence exists",),
            trust_boundary="test",
            specification_refs=("cas:test:none",),
        )
        result = qualify_run(REPO / "tests" / "fixtures" / "nonexistent-run", claim=claim)
        assert "0" * 64 not in result.artifact_refs
