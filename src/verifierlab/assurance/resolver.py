"""Artifact-validated assurance qualification.

The public qualification path is:

``EvidenceResolver -> EvidenceFact -> AssuranceQualification``.

A maturity fact is true only when its supporting artifact can be parsed,
content-addressed, and cross-validated against the other artifacts that give
the fact meaning. Caller supplied boolean bags, arbitrary 64-character strings,
and field presence are never qualification evidence.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from verifierlab.artifacts.canonical import digest_of
from verifierlab.assurance.maturity import AssuranceClaim, AssuranceLevel

RESOLVER_VERSION = "2"
ZERO_DIGEST = "0" * 64

FactOutcome = Literal["true", "false", "indeterminate"]


def _valid_digest(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64 or value == ZERO_DIGEST:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _payload_without_content_digest(body: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in body.items() if key != "content_digest"}


def _wrapped_digest(body: dict[str, Any]) -> str:
    return digest_of(_payload_without_content_digest(body))


def _nested_digest_match(value: Any, target: str) -> dict[str, Any] | None:
    """Find a dictionary whose canonical digest equals ``target``."""
    if isinstance(value, dict):
        candidate = _payload_without_content_digest(value)
        try:
            if digest_of(candidate) == target:
                return candidate
        except (TypeError, ValueError):
            pass
        for child in value.values():
            found = _nested_digest_match(child, target)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _nested_digest_match(child, target)
            if found is not None:
                return found
    return None


class EvidenceFact(BaseModel):
    """One typed fact derived from validated evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    fact_id: str = Field(min_length=1)
    source_artifact_digest: str = Field(min_length=64, max_length=64)
    validator: str = Field(min_length=1)
    validator_version: str = Field(min_length=1)
    outcome: FactOutcome
    reasons: tuple[str, ...] = ()
    timestamp: float

    @property
    def digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))

    @property
    def is_true(self) -> bool:
        return self.outcome == "true"


class ExternalAssuranceAttestation(BaseModel):
    """External-review attestation verified against a configured trust root."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    attestation_id: str = Field(min_length=1)
    subject_digest: str = Field(min_length=64, max_length=64)
    claim_digest: str = Field(min_length=64, max_length=64)
    reviewer_id: str = Field(min_length=1)
    trust_root_id: str = Field(min_length=1)
    signature: str = Field(min_length=16)
    issued_at: float
    reconstruction_digest: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class AssuranceQualification(BaseModel):
    """Maturity decision bound to claim, facts, blockers, and evidence refs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    level: str
    ordinal: int
    blockers: tuple[str, ...] = ()
    satisfied: tuple[str, ...] = ()
    security_grade_execution: bool = False
    claim_digest: str = Field(min_length=64, max_length=64)
    facts_digest: str = Field(min_length=64, max_length=64)
    artifact_refs: tuple[str, ...] = ()
    fact_ids: tuple[str, ...] = ()
    resolver_version: str = RESOLVER_VERSION

    @property
    def digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def _fact(
    fact_id: str,
    *,
    source: str,
    validator: str,
    outcome: FactOutcome,
    reasons: tuple[str, ...] = (),
    timestamp: float | None = None,
) -> EvidenceFact:
    source_digest = source if _valid_digest(source) else digest_of(
        {"fact_id": fact_id, "missing_or_invalid_source": source}
    )
    return EvidenceFact(
        fact_id=fact_id,
        source_artifact_digest=source_digest,
        validator=validator,
        validator_version=RESOLVER_VERSION,
        outcome=outcome,
        reasons=reasons,
        timestamp=float(time.time() if timestamp is None else timestamp),
    )


class EvidenceResolver:
    """Derive assurance facts from validated immutable artifacts."""

    def __init__(
        self,
        run_or_study: Path,
        *,
        claim: AssuranceClaim,
        trust_roots: dict[str, str] | None = None,
        attestations: list[ExternalAssuranceAttestation] | None = None,
    ) -> None:
        self.root = Path(run_or_study)
        self.claim = claim
        self.trust_roots = dict(trust_roots or {})
        self.attestations = list(attestations or [])
        self._digest_cache: dict[str, dict[str, Any] | None] = {}

    def _verified_json(
        self,
        path: Path,
        *,
        require_content_digest: bool = True,
    ) -> tuple[dict[str, Any] | None, str | None, tuple[str, ...]]:
        body = _read_json(path)
        if body is None:
            return None, None, (f"missing_or_invalid_json:{path.name}",)
        if not require_content_digest:
            return body, digest_of(body), ()
        declared = body.get("content_digest")
        if not _valid_digest(declared):
            return body, None, (f"missing_or_invalid_content_digest:{path.name}",)
        computed = _wrapped_digest(body)
        if computed != declared:
            return body, str(declared), (f"content_digest_mismatch:{path.name}",)
        return body, str(declared), ()

    def _store_payload(self, target: str) -> dict[str, Any] | None:
        workspace = self.root.parent.parent
        store_root = workspace / "store"
        if not store_root.is_dir():
            return None
        try:
            from verifierlab.artifacts.cas import ContentAddressedStore

            payload = ContentAddressedStore(store_root).get_json(target)
        except (FileNotFoundError, KeyError, OSError, ValueError):
            return None
        if not isinstance(payload, dict) or digest_of(payload) != target:
            return None
        return payload

    def _resolve_digest_payload(self, target: Any) -> dict[str, Any] | None:
        """Resolve a digest to the actual canonical payload, never to its spelling."""
        if not _valid_digest(target):
            return None
        target_s = str(target)
        if target_s in self._digest_cache:
            return self._digest_cache[target_s]

        direct = self._store_payload(target_s)
        if direct is not None:
            self._digest_cache[target_s] = direct
            return direct

        for path in sorted(self.root.rglob("*.json")):
            body = _read_json(path)
            if body is None:
                continue
            declared = body.get("content_digest")
            if declared == target_s and _wrapped_digest(body) == target_s:
                payload = _payload_without_content_digest(body)
                self._digest_cache[target_s] = payload
                return payload
            nested = _nested_digest_match(body, target_s)
            if nested is not None:
                self._digest_cache[target_s] = nested
                return nested

        sealed = _read_json(self.root / "sealed_run.json") or {}
        campaign_digest = sealed.get("campaign_digest")
        if _valid_digest(campaign_digest):
            campaign = self._store_payload(str(campaign_digest))
            if campaign is not None:
                nested = _nested_digest_match(campaign, target_s)
                if nested is not None:
                    self._digest_cache[target_s] = nested
                    return nested

        self._digest_cache[target_s] = None
        return None

    def _budget_binding_valid(self, sealed: dict[str, Any], manifest: dict[str, Any]) -> bool:
        budget_digest = sealed.get("budget_digest")
        if not _valid_digest(budget_digest):
            return False
        freeze_bundle_digest = sealed.get("freeze_seal_bundle_digest")
        freeze_bundle = self._resolve_digest_payload(freeze_bundle_digest)
        if freeze_bundle is None or freeze_bundle.get("budget_digest") != budget_digest:
            return False
        meta = manifest.get("metadata") or {}
        source: Any = meta.get("budget") if isinstance(meta, dict) else None
        if source is None:
            source = manifest.get("ledger_digest")
        if source in (None, ""):
            return False
        return digest_of(source) == budget_digest

    def resolve_facts(self) -> list[EvidenceFact]:
        facts: list[EvidenceFact] = []
        facts.extend(self._lifecycle_facts())
        facts.extend(self._execution_facts())
        facts.extend(self._holdout_facts())
        facts.extend(self._stats_facts())
        facts.extend(self._envassure_facts())
        facts.extend(self._independence_facts())
        facts.extend(self._deployment_facts())
        return facts

    def qualify(self) -> AssuranceQualification:
        facts = self.resolve_facts()
        by_id = {fact.fact_id: fact for fact in facts}
        satisfied: list[str] = []
        blockers: list[str] = []

        def ok(fact_id: str) -> bool:
            fact = by_id.get(fact_id)
            return bool(fact and fact.is_true)

        if not ok("implementation_present"):
            return self._result(
                AssuranceLevel.NOT_IMPLEMENTED,
                facts,
                blockers=["implementation_missing"],
                satisfied=[],
            )
        satisfied.append("implementation_present")
        level = AssuranceLevel.IMPLEMENTED_UNVERIFIED

        internal = [
            "evidence_artifacts_bound",
            "immutable_artifacts_bound",
            "exact_budget_evidence",
            "lifecycle_freeze_adjudicate_release",
            "hidden_labels_outside_attack_plane",
        ]
        missing_internal = [name for name in internal if not ok(name)]
        if missing_internal:
            blockers.extend(missing_internal)
            return self._result(level, facts, blockers=blockers, satisfied=satisfied)
        satisfied.extend(internal)
        level = AssuranceLevel.INTERNALLY_VERIFIED

        if not ok("independent_review") or not ok("independent_reconstruction"):
            if not ok("independent_review"):
                blockers.append("independent_review_missing")
            if not ok("independent_reconstruction"):
                blockers.append("independent_reconstruction_missing")
            return self._result(level, facts, blockers=blockers, satisfied=satisfied)
        satisfied.extend(["independent_review", "independent_reconstruction"])
        level = AssuranceLevel.INDEPENDENTLY_VERIFIED

        scientific = [
            "security_grade_execution",
            "preregistered_study",
            "strong_attacker_budgeted",
            "hidden_holdout_sealed",
            "qualification_estimands_complete",
            "negative_results_preserved",
            "environment_assurance_determinate",
            "qualification_evidence_non_synthetic",
        ]
        missing_scientific = [name for name in scientific if not ok(name)]
        if missing_scientific:
            blockers.extend(missing_scientific)
            return self._result(level, facts, blockers=blockers, satisfied=satisfied)
        satisfied.extend(scientific)
        level = AssuranceLevel.SCIENTIFICALLY_QUALIFIED

        deployment = [
            "prospective_predictions_registered",
            "deployment_outcomes_collected",
            "calibration_analysis_complete",
            "applicability_regime_declared",
            "deployment_chronology_anchored",
            "deployment_not_synthetic",
        ]
        missing_deployment = [name for name in deployment if not ok(name)]
        if missing_deployment:
            blockers.extend(missing_deployment)
            return self._result(level, facts, blockers=blockers, satisfied=satisfied)
        satisfied.extend(deployment)
        return self._result(
            AssuranceLevel.DEPLOYMENT_CALIBRATED,
            facts,
            blockers=[],
            satisfied=satisfied,
        )

    def _result(
        self,
        level: AssuranceLevel,
        facts: list[EvidenceFact],
        *,
        blockers: list[str],
        satisfied: list[str],
    ) -> AssuranceQualification:
        facts_digest = digest_of([fact.model_dump(mode="json") for fact in facts])
        artifact_refs = tuple(
            sorted(
                {
                    fact.source_artifact_digest
                    for fact in facts
                    if fact.is_true and _valid_digest(fact.source_artifact_digest)
                }
            )
        )
        security = any(
            fact.fact_id == "security_grade_execution" and fact.is_true for fact in facts
        )
        return AssuranceQualification(
            level=level.label,
            ordinal=int(level),
            blockers=tuple(blockers),
            satisfied=tuple(satisfied),
            security_grade_execution=security,
            claim_digest=self.claim.digest,
            facts_digest=facts_digest,
            artifact_refs=artifact_refs,
            fact_ids=tuple(fact.fact_id for fact in facts),
            resolver_version=RESOLVER_VERSION,
        )

    def _lifecycle_facts(self) -> list[EvidenceFact]:
        manifest, manifest_digest, _ = self._verified_json(
            self.root / "manifest.json", require_content_digest=False
        )
        sealed, sealed_digest, sealed_errors = self._verified_json(self.root / "sealed_run.json")
        freeze, freeze_digest, freeze_errors = self._verified_json(self.root / "freeze.json")
        release, release_digest, release_errors = self._verified_json(self.root / "release.json")
        receipt, receipt_digest, receipt_errors = self._verified_json(
            self.root / "label_release_receipt.json"
        )

        has_impl = manifest is not None or sealed is not None
        source = sealed_digest or manifest_digest or digest_of({"root": str(self.root)})
        facts = [
            _fact(
                "implementation_present",
                source=source,
                validator="lifecycle.valid_manifest_or_sealed_run",
                outcome="true" if has_impl else "false",
                reasons=() if has_impl else ("no_manifest_or_sealed_run",),
            )
        ]

        errors = (*sealed_errors, *freeze_errors, *release_errors, *receipt_errors)
        cross_ok = bool(
            sealed
            and sealed_digest
            and freeze
            and freeze_digest
            and release
            and release_digest
            and receipt
            and receipt_digest
            and sealed.get("freeze_digest") == freeze_digest
            and receipt.get("sealed_run_digest") == sealed_digest
            and receipt.get("freeze_digest") == freeze_digest
        )
        chronology = receipt.get("chronology") if receipt else None
        if isinstance(chronology, dict) and chronology.get("release_tip_digest"):
            cross_ok = cross_ok and chronology.get("release_tip_digest") == release_digest

        facts.append(
            _fact(
                "evidence_artifacts_bound",
                source=sealed_digest or source,
                validator="lifecycle.content_and_cross_digest_validation",
                outcome="true" if cross_ok and not errors else "false",
                reasons=errors if errors else (() if cross_ok else ("lifecycle_cross_link_invalid",)),
            )
        )

        freeze_bundle_ok = False
        if sealed:
            freeze_bundle_digest = sealed.get("freeze_seal_bundle_digest")
            freeze_bundle = self._resolve_digest_payload(freeze_bundle_digest)
            freeze_bundle_ok = bool(
                freeze_bundle
                and freeze_bundle.get("run_id") == sealed.get("run_id")
                and freeze_bundle.get("campaign_digest") == sealed.get("campaign_digest")
                and freeze_bundle.get("budget_digest") == sealed.get("budget_digest")
            )
        immutable_ok = cross_ok and freeze_bundle_ok
        facts.append(
            _fact(
                "immutable_artifacts_bound",
                source=sealed_digest or source,
                validator="lifecycle.freeze_seal_bundle_binding",
                outcome="true" if immutable_ok else "false",
                reasons=() if immutable_ok else ("freeze_seal_bundle_unresolved_or_mismatched",),
            )
        )

        budget_ok = bool(sealed and manifest and self._budget_binding_valid(sealed, manifest))
        facts.append(
            _fact(
                "exact_budget_evidence",
                source=str(sealed.get("budget_digest")) if sealed else source,
                validator="lifecycle.derived_budget_binding",
                outcome="true" if budget_ok else "false",
                reasons=() if budget_ok else ("budget_digest_not_derived_from_bound_manifest",),
            )
        )

        lifecycle_ok = False
        if manifest and freeze_digest and release_digest and cross_ok:
            chain = [str(item) for item in (manifest.get("chain") or [])]
            lifecycle_ok = bool(
                manifest.get("lifecycle")
                in {"label_release", "triage", "stats", "repair", "disclosure"}
                and manifest.get("tip_digest") == release_digest
                and freeze_digest in chain
                and release_digest in chain
            )
        facts.append(
            _fact(
                "lifecycle_freeze_adjudicate_release",
                source=release_digest or source,
                validator="lifecycle.chain_and_tip_validation",
                outcome="true" if lifecycle_ok else "false",
                reasons=() if lifecycle_ok else ("lifecycle_chain_not_closed",),
            )
        )
        return facts

    def _execution_facts(self) -> list[EvidenceFact]:
        sealed, sealed_digest, sealed_errors = self._verified_json(self.root / "sealed_run.json")
        if sealed is None or sealed_digest is None or sealed_errors:
            return [
                _fact(
                    "security_grade_execution",
                    source=sealed_digest or "invalid-sealed-run",
                    validator="execution.boundary_payload_validation",
                    outcome="false",
                    reasons=sealed_errors or ("sealed_run_invalid",),
                )
            ]

        meta = sealed.get("metadata") or {}
        mode = str(meta.get("execution_mode") or meta.get("backend_kind") or "local_dev")
        declared_grade = bool(meta.get("security_grade"))
        boundary_digests = tuple(
            str(item)
            for item in (
                sealed.get("execution_boundary_digests")
                or meta.get("execution_boundary_digests")
                or []
            )
            if item
        )
        reasons: list[str] = []
        if mode not in {"docker_rootless", "microvm", "separate_host"}:
            reasons.append("non_security_grade_execution_mode")
        if not declared_grade:
            reasons.append("sealed_run_does_not_declare_security_grade")
        if not boundary_digests:
            reasons.append("execution_boundary_digests_missing")

        boundaries_ok = bool(boundary_digests)
        probe_digests: set[str] = set()
        if boundary_digests:
            from verifierlab.execution.container import ExecutionBoundaryManifest

            for boundary_digest in boundary_digests:
                payload = self._resolve_digest_payload(boundary_digest)
                if payload is None:
                    boundaries_ok = False
                    reasons.append(f"execution_boundary_unresolved:{boundary_digest[:12]}")
                    continue
                try:
                    boundary = ExecutionBoundaryManifest.model_validate(payload)
                except Exception:
                    boundaries_ok = False
                    reasons.append(f"execution_boundary_invalid:{boundary_digest[:12]}")
                    continue
                if boundary.content_digest() != boundary_digest:
                    boundaries_ok = False
                    reasons.append(f"execution_boundary_digest_mismatch:{boundary_digest[:12]}")
                if not boundary.security_grade or not boundary.policy_satisfied:
                    boundaries_ok = False
                    reasons.append(f"execution_boundary_not_security_grade:{boundary_digest[:12]}")
                if boundary.probe_report_digest:
                    probe_digests.add(boundary.probe_report_digest)
                else:
                    boundaries_ok = False
                    reasons.append(f"execution_boundary_probe_missing:{boundary_digest[:12]}")

        probes_ok = bool(probe_digests)
        if probe_digests:
            from verifierlab.execution.protocol import IsolationProbeReport

            for probe_digest in sorted(probe_digests):
                payload = self._resolve_digest_payload(probe_digest)
                if payload is None:
                    probes_ok = False
                    reasons.append(f"isolation_probe_unresolved:{probe_digest[:12]}")
                    continue
                try:
                    report = IsolationProbeReport.model_validate(payload)
                except Exception:
                    probes_ok = False
                    reasons.append(f"isolation_probe_invalid:{probe_digest[:12]}")
                    continue
                if report.content_digest() != probe_digest:
                    probes_ok = False
                    reasons.append(f"isolation_probe_digest_mismatch:{probe_digest[:12]}")
                if not (
                    report.ran_inside_executor
                    and not report.structural_only
                    and report.secret_sentinels_absent
                    and report.randomized_gt_paths_absent
                    and report.all_required_denied
                    and report.security_grade_eligible
                ):
                    probes_ok = False
                    reasons.append(f"isolation_probe_not_qualifying:{probe_digest[:12]}")
        else:
            reasons.append("isolation_probe_evidence_missing")

        grade = bool(
            declared_grade
            and mode in {"docker_rootless", "microvm", "separate_host"}
            and boundaries_ok
            and probes_ok
        )
        return [
            _fact(
                "security_grade_execution",
                source=sealed_digest,
                validator="execution.boundary_and_probe_payload_validation",
                outcome="true" if grade else "false",
                reasons=tuple(reasons),
            )
        ]

    def _holdout_facts(self) -> list[EvidenceFact]:
        sealed, sealed_digest, _ = self._verified_json(self.root / "sealed_run.json")
        receipt, receipt_digest, _ = self._verified_json(self.root / "label_release_receipt.json")
        source = receipt_digest or sealed_digest or digest_of({"holdout": str(self.root)})

        vault_commitments = self.root / "vault" / "commitments"
        labels_out = bool(receipt and receipt_digest and vault_commitments.is_dir())
        leaks: list[str] = []
        work_units = self.root / "work_units"
        if labels_out and work_units.is_dir():
            forbidden = {"gt_valid", "ground_truth", "ground_truth_ref", "hidden_label"}
            for path in sorted(work_units.glob("*.json")):
                body = _read_json(path) or {}
                for key in forbidden:
                    if body.get(key) is not None:
                        leaks.append(f"{path.name}:{key}")
        if leaks:
            labels_out = False

        custody_ok = False
        if sealed and _valid_digest(sealed.get("custody_digest")):
            custody = self._resolve_digest_payload(sealed.get("custody_digest"))
            custody_ok = custody is not None

        return [
            _fact(
                "hidden_labels_outside_attack_plane",
                source=source,
                validator="custody.vault_and_attack_plane_scan",
                outcome="true" if labels_out else "false",
                reasons=tuple(f"attack_plane_label_leak:{item}" for item in leaks)
                if leaks
                else (() if labels_out else ("validated_label_custody_evidence_missing",)),
            ),
            _fact(
                "hidden_holdout_sealed",
                source=str(sealed.get("custody_digest")) if sealed else source,
                validator="custody.digest_resolution",
                outcome="true" if custody_ok else "false",
                reasons=() if custody_ok else ("custody_digest_unresolved",),
            ),
        ]

    def _stats_facts(self) -> list[EvidenceFact]:
        sealed, sealed_digest, _ = self._verified_json(self.root / "sealed_run.json")
        source = sealed_digest or digest_of({"stats": str(self.root)})
        preregistration = None
        preregistration_digest: str | None = None
        if sealed and _valid_digest(sealed.get("preregistration_digest")):
            preregistration_digest = str(sealed["preregistration_digest"])
            preregistration = self._resolve_digest_payload(preregistration_digest)

        prereg_ok = False
        primary_ids: tuple[str, ...] = ()
        if preregistration is not None and preregistration_digest is not None:
            try:
                from verifierlab.config.preregistration import AnalysisPreregistration

                registration = AnalysisPreregistration.model_validate(preregistration)
                prereg_ok = registration.content_digest == preregistration_digest
                primary_ids = tuple(
                    item.estimand_id for item in registration.estimands if item.role == "primary"
                )
            except Exception:
                prereg_ok = False

        report = _read_json(self.root / "report" / "stats.json") or {}
        report_source = digest_of(report) if report else source
        registered = report.get("registered_estimands")
        complete = bool(prereg_ok and primary_ids and isinstance(registered, dict))
        if complete and isinstance(registered, dict):
            for estimand_id in primary_ids:
                item = registered.get(estimand_id)
                if not isinstance(item, dict):
                    complete = False
                    break
                result = item.get("result")
                if not isinstance(result, dict) or result.get("status") not in {
                    "estimated",
                    "indeterminate",
                }:
                    complete = False
                    break

        negative_results = bool(
            report
            and report.get("negative_results_preserved") is True
            and isinstance(report.get("censored"), dict)
        )

        manifest = _read_json(self.root / "manifest.json") or {}
        budgeted = bool(
            sealed
            and manifest
            and self._budget_binding_valid(sealed, manifest)
            and sealed.get("attacker_identity_digests")
        )

        synthetic_reasons: list[str] = []
        for candidate in (
            sealed or {},
            _read_json(self.root / "scientific_study_registration.json") or {},
            report,
            _read_json(self.root / "environment_assurance_ref.json") or {},
            _read_json(self.root / "envassure" / "environment_assurance_ref.json") or {},
        ):
            metadata = candidate.get("metadata") if isinstance(candidate, dict) else None
            if isinstance(metadata, dict) and (
                metadata.get("synthetic") is True or metadata.get("non_live") is True
            ):
                synthetic_reasons.append("synthetic_or_non_live_metadata")
            if isinstance(candidate, dict) and candidate.get("synthetic_non_deployment_evidence"):
                synthetic_reasons.append("synthetic_non_deployment_evidence")

        return [
            _fact(
                "preregistered_study",
                source=preregistration_digest or source,
                validator="stats.preregistration_payload",
                outcome="true" if prereg_ok else "false",
                reasons=() if prereg_ok else ("preregistration_digest_unresolved_or_invalid",),
            ),
            _fact(
                "strong_attacker_budgeted",
                source=str(sealed.get("budget_digest")) if sealed else source,
                validator="stats.attacker_identity_and_budget_binding",
                outcome="true" if budgeted else "false",
                reasons=() if budgeted else ("attacker_identity_or_exact_budget_evidence_missing",),
            ),
            _fact(
                "qualification_estimands_complete",
                source=report_source,
                validator="stats.registered_estimand_compilation",
                outcome="true" if complete else "false",
                reasons=() if complete else ("primary_estimands_not_executably_compiled",),
            ),
            _fact(
                "negative_results_preserved",
                source=report_source,
                validator="stats.explicit_negative_result_preservation",
                outcome="true" if negative_results else "false",
                reasons=() if negative_results else ("negative_result_preservation_not_proven",),
            ),
            _fact(
                "qualification_evidence_non_synthetic",
                source=report_source,
                validator="stats.synthetic_evidence_guard",
                outcome="false" if synthetic_reasons else "true",
                reasons=tuple(sorted(set(synthetic_reasons))),
            ),
        ]

    def _envassure_facts(self) -> list[EvidenceFact]:
        from verifierlab.assurance.envassure import (
            EnvironmentAssuranceRef,
            propagate_envassure_into_qualification,
            verify_frozen_envassure_bundle,
        )

        sealed, sealed_digest, _ = self._verified_json(self.root / "sealed_run.json")
        ref_path = self.root / "environment_assurance_ref.json"
        if not ref_path.is_file():
            ref_path = self.root / "envassure" / "environment_assurance_ref.json"
        ref_body = _read_json(ref_path)
        source = sealed_digest or digest_of({"envassure": str(self.root)})
        if ref_body is None:
            return [
                _fact(
                    "environment_assurance_determinate",
                    source=source,
                    validator="envassure.bundle_and_ref_validation",
                    outcome="false",
                    reasons=("environment_assurance_ref_missing",),
                )
            ]
        try:
            ref_payload = _payload_without_content_digest(ref_body)
            env_ref = EnvironmentAssuranceRef.model_validate(ref_payload)
        except Exception:
            return [
                _fact(
                    "environment_assurance_determinate",
                    source=source,
                    validator="envassure.bundle_and_ref_validation",
                    outcome="false",
                    reasons=("environment_assurance_ref_invalid",),
                )
            ]
        if ref_body.get("content_digest") is not None and ref_body.get("content_digest") != env_ref.digest:
            return [
                _fact(
                    "environment_assurance_determinate",
                    source=env_ref.digest,
                    validator="envassure.bundle_and_ref_validation",
                    outcome="false",
                    reasons=("environment_assurance_ref_digest_mismatch",),
                )
            ]
        if not sealed or sealed.get("environment_assurance_digest") != env_ref.digest:
            return [
                _fact(
                    "environment_assurance_determinate",
                    source=env_ref.digest,
                    validator="envassure.bundle_and_ref_validation",
                    outcome="false",
                    reasons=("sealed_run_environment_assurance_binding_mismatch",),
                )
            ]

        bundle_path = self.root / "envassure" / "frozen-evidence-bundle.json"
        if not bundle_path.is_file():
            bundle_path = self.root / "frozen-evidence-bundle.json"
        try:
            verified_ref = verify_frozen_envassure_bundle(
                bundle_path,
                expected_digest=env_ref.bundle_digest,
            )
        except (OSError, ValueError):
            return [
                _fact(
                    "environment_assurance_determinate",
                    source=env_ref.digest,
                    validator="envassure.bundle_and_ref_validation",
                    outcome="false",
                    reasons=("frozen_environment_assurance_bundle_invalid_or_missing",),
                )
            ]
        if verified_ref.digest != env_ref.digest:
            return [
                _fact(
                    "environment_assurance_determinate",
                    source=env_ref.digest,
                    validator="envassure.bundle_and_ref_validation",
                    outcome="false",
                    reasons=("environment_assurance_bundle_ref_mismatch",),
                )
            ]
        outcome, reasons = propagate_envassure_into_qualification(
            env_ref=env_ref,
            verifier_success=True,
        )
        return [
            _fact(
                "environment_assurance_determinate",
                source=env_ref.digest,
                validator="envassure.bundle_and_ref_validation",
                outcome=outcome,
                reasons=reasons,
            )
        ]

    def _independence_facts(self) -> list[EvidenceFact]:
        review_ok = False
        reconstruction_ok = False
        reasons: list[str] = []
        source = digest_of({"claim": self.claim.digest, "roots": sorted(self.trust_roots)})
        if not self.attestations:
            reasons.append("no_external_attestation")
        for attestation in self.attestations:
            try:
                verify_external_attestation(
                    attestation,
                    claim=self.claim,
                    trust_roots=self.trust_roots,
                    subject_digest=self._subject_digest(),
                )
            except ValueError as exc:
                reasons.append(str(exc))
                continue
            review_ok = True
            if attestation.reconstruction_digest and _valid_digest(attestation.reconstruction_digest):
                reconstruction_ok = True
        if review_ok and not reconstruction_ok:
            reasons.append("reconstruction_digest_missing_or_invalid")
        reason_tuple = tuple(reasons)
        return [
            _fact(
                "independent_review",
                source=source,
                validator="attestation.external_trust_root",
                outcome="true" if review_ok else "false",
                reasons=reason_tuple,
            ),
            _fact(
                "independent_reconstruction",
                source=source,
                validator="attestation.reconstruction",
                outcome="true" if reconstruction_ok else "false",
                reasons=reason_tuple,
            ),
        ]

    def _deployment_facts(self) -> list[EvidenceFact]:
        dep_root = self.root / "deployment"
        source = digest_of({"deployment": str(dep_root)})
        if not dep_root.is_dir():
            return self._empty_deployment_facts(source)

        predictions: list[Any] = []
        outcomes: list[Any] = []
        synthetic = False
        try:
            from verifierlab.assurance.deployment import (
                AppendOnlyChronologyStore,
                DeploymentCalibrationReport,
                DeploymentOutcomeRecord,
                DeploymentPredictionRegistration,
            )

            pred_dir = dep_root / "predictions"
            for path in sorted(pred_dir.glob("*.json")) if pred_dir.is_dir() else []:
                body, digest, errors = self._verified_json(path)
                if body is None or digest is None or errors:
                    continue
                record = DeploymentPredictionRegistration.model_validate(
                    _payload_without_content_digest(body)
                )
                if record.digest != digest:
                    continue
                predictions.append(record)
                synthetic = synthetic or record.synthetic_non_deployment_evidence

            out_dir = dep_root / "outcomes"
            for path in sorted(out_dir.glob("*.json")) if out_dir.is_dir() else []:
                body, digest, errors = self._verified_json(path)
                if body is None or digest is None or errors:
                    continue
                record = DeploymentOutcomeRecord.model_validate(
                    _payload_without_content_digest(body)
                )
                if record.digest != digest:
                    continue
                outcomes.append(record)
                synthetic = synthetic or record.synthetic_non_deployment_evidence

            events = AppendOnlyChronologyStore(dep_root / "chronology").events()
            event_digests = {event.digest for event in events}
            event_order = {event.event_id: index for index, event in enumerate(events)}
            chronology_ok = bool(events)
            for prediction in predictions:
                chronology_ok = chronology_ok and prediction.chronology_event_digest in event_digests
            for outcome in outcomes:
                chronology_ok = chronology_ok and outcome.chronology_event_digest in event_digests
                pred_event = f"pred-{outcome.prediction_id}"
                out_event = f"out-{outcome.outcome_id}"
                chronology_ok = chronology_ok and pred_event in event_order and out_event in event_order
                if pred_event in event_order and out_event in event_order:
                    chronology_ok = chronology_ok and event_order[pred_event] < event_order[out_event]

            report_body, report_digest, report_errors = self._verified_json(
                dep_root / "calibration_report.json"
            )
            report = None
            if report_body is not None and report_digest is not None and not report_errors:
                report = DeploymentCalibrationReport.model_validate(
                    _payload_without_content_digest(report_body)
                )
                if report.digest != report_digest:
                    report = None
                elif report.synthetic_non_deployment_evidence:
                    synthetic = True

            applicability = _read_json(dep_root / "applicability.json") or {}
            applicability_ok = bool(
                applicability.get("applicability_regime") or applicability.get("regime")
            )
            report_ok = bool(
                report
                and report.supports_deployment_calibrated_claim
                and report.n_matched > 0
                and report.n_outcomes > 0
                and report.n_predictions > 0
            )
            source = report_digest or (predictions[0].digest if predictions else source)
        except (OSError, ValueError, TypeError):
            return self._empty_deployment_facts(source)

        predictions_ok = bool(predictions) and chronology_ok
        outcomes_ok = bool(outcomes) and chronology_ok
        return [
            _fact(
                "prospective_predictions_registered",
                source=source,
                validator="deployment.validated_prediction_chronology",
                outcome="true" if predictions_ok else "false",
            ),
            _fact(
                "deployment_outcomes_collected",
                source=source,
                validator="deployment.validated_outcome_chronology",
                outcome="true" if outcomes_ok else "false",
            ),
            _fact(
                "calibration_analysis_complete",
                source=source,
                validator="deployment.validated_calibration_report",
                outcome="true" if report_ok else "false",
            ),
            _fact(
                "applicability_regime_declared",
                source=source,
                validator="deployment.applicability",
                outcome="true" if applicability_ok else "false",
            ),
            _fact(
                "deployment_chronology_anchored",
                source=source,
                validator="deployment.hash_chain_and_event_order",
                outcome="true" if chronology_ok else "false",
                reasons=() if chronology_ok else ("deployment_chronology_invalid",),
            ),
            _fact(
                "deployment_not_synthetic",
                source=source,
                validator="deployment.synthetic_guard",
                outcome="false" if synthetic else ("true" if predictions_ok else "false"),
                reasons=("synthetic_non_deployment_evidence",) if synthetic else (),
            ),
        ]

    def _empty_deployment_facts(self, source: str) -> list[EvidenceFact]:
        return [
            _fact(
                fact_id,
                source=source,
                validator=validator,
                outcome="false",
                reasons=("validated_deployment_evidence_missing",),
            )
            for fact_id, validator in (
                ("prospective_predictions_registered", "deployment.validated_prediction_chronology"),
                ("deployment_outcomes_collected", "deployment.validated_outcome_chronology"),
                ("calibration_analysis_complete", "deployment.validated_calibration_report"),
                ("applicability_regime_declared", "deployment.applicability"),
                ("deployment_chronology_anchored", "deployment.hash_chain_and_event_order"),
                ("deployment_not_synthetic", "deployment.synthetic_guard"),
            )
        ]

    def _subject_digest(self) -> str:
        _sealed, sealed_digest, errors = self._verified_json(self.root / "sealed_run.json")
        if sealed_digest is not None and not errors:
            return sealed_digest
        return digest_of({"root": str(self.root.resolve()), "validated_seal": False})


def verify_external_attestation(
    attestation: ExternalAssuranceAttestation,
    *,
    claim: AssuranceClaim,
    trust_roots: dict[str, str],
    subject_digest: str,
) -> None:
    """Verify an attestation and reject self-issued or wrong-subject evidence."""
    if attestation.claim_digest != claim.digest:
        raise ValueError("attestation claim_digest mismatch")
    if attestation.subject_digest != subject_digest:
        raise ValueError("attestation subject mismatch")
    root = trust_roots.get(attestation.trust_root_id)
    if root is None:
        raise ValueError("attestation trust root not configured")
    if attestation.reviewer_id in {"self", "local", "internal"} or (
        attestation.reviewer_id == attestation.trust_root_id
    ):
        raise ValueError("self-issued attestation rejected")
    expected = digest_of(
        {
            "attestation_id": attestation.attestation_id,
            "subject_digest": attestation.subject_digest,
            "claim_digest": attestation.claim_digest,
            "reviewer_id": attestation.reviewer_id,
            "trust_root_id": attestation.trust_root_id,
            "issued_at": attestation.issued_at,
            "reconstruction_digest": attestation.reconstruction_digest,
            "root": root,
        }
    )
    if attestation.signature != expected:
        raise ValueError("attestation signature verification failed")


def sign_external_attestation(
    *,
    attestation_id: str,
    subject_digest: str,
    claim: AssuranceClaim,
    reviewer_id: str,
    trust_root_id: str,
    trust_root_secret: str,
    reconstruction_digest: str | None = None,
    issued_at: float | None = None,
) -> ExternalAssuranceAttestation:
    """Build a correctly bound attestation for tests and external tools."""
    timestamp = float(time.time() if issued_at is None else issued_at)
    signature = digest_of(
        {
            "attestation_id": attestation_id,
            "subject_digest": subject_digest,
            "claim_digest": claim.digest,
            "reviewer_id": reviewer_id,
            "trust_root_id": trust_root_id,
            "issued_at": timestamp,
            "reconstruction_digest": reconstruction_digest,
            "root": trust_root_secret,
        }
    )
    return ExternalAssuranceAttestation(
        attestation_id=attestation_id,
        subject_digest=subject_digest,
        claim_digest=claim.digest,
        reviewer_id=reviewer_id,
        trust_root_id=trust_root_id,
        signature=signature,
        issued_at=timestamp,
        reconstruction_digest=reconstruction_digest,
    )


def qualify_run(
    run_or_study: Path | str,
    *,
    claim: AssuranceClaim | dict[str, Any] | Path | str,
    trust_roots: dict[str, str] | None = None,
    attestations: list[ExternalAssuranceAttestation] | None = None,
) -> AssuranceQualification:
    """Public qualification entry point using validated artifact evidence only."""
    root = Path(run_or_study)
    if isinstance(claim, str | Path):
        claim_path = Path(claim)
        claim_obj = AssuranceClaim.model_validate(
            json.loads(claim_path.read_text(encoding="utf-8"))
        )
    elif isinstance(claim, dict):
        claim_obj = AssuranceClaim.model_validate(claim)
    else:
        claim_obj = claim

    boolean_bag = root / "assurance_evidence_booleans.json"
    if boolean_bag.is_file():
        raise ValueError(
            "caller-supplied AssuranceEvidence boolean bags are not a qualification path; "
            "remove assurance_evidence_booleans.json and provide validated sealed artifacts"
        )
    return EvidenceResolver(
        root,
        claim=claim_obj,
        trust_roots=trust_roots,
        attestations=attestations,
    ).qualify()


__all__ = [
    "RESOLVER_VERSION",
    "AssuranceQualification",
    "EvidenceFact",
    "EvidenceResolver",
    "ExternalAssuranceAttestation",
    "qualify_run",
    "sign_external_attestation",
    "verify_external_attestation",
]
