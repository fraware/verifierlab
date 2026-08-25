"""Artifact-derived assurance qualification (WP-05).

Public qualification path: ``EvidenceResolver`` → typed ``EvidenceFact`` records
→ ``AssuranceQualification``. Caller-supplied boolean bags are not accepted.
The PR #10 module remains a policy seed only (``SEED_NOT_QUALIFICATION_PATH``).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from verifierlab.artifacts.canonical import digest_of
from verifierlab.assurance.maturity import AssuranceClaim, AssuranceLevel

RESOLVER_VERSION = "1"

FactOutcome = Literal["true", "false", "indeterminate"]


class EvidenceFact(BaseModel):
    """One typed fact derived from an immutable artifact."""

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
    """Signed independent-review attestation verified against external trust roots."""

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
    """Maturity decision bound to claim, facts, blockers, and artifact refs."""

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
    return EvidenceFact(
        fact_id=fact_id,
        source_artifact_digest=source if len(source) == 64 else digest_of({"ref": source}),
        validator=validator,
        validator_version=RESOLVER_VERSION,
        outcome=outcome,
        reasons=reasons,
        timestamp=float(time.time() if timestamp is None else timestamp),
    )


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _file_digest(path: Path) -> str:
    return digest_of(json.loads(path.read_text(encoding="utf-8")))


class EvidenceResolver:
    """Derive ``EvidenceFact`` records from a sealed run or study directory.

    Manual JSON with all-true booleans and no artifacts cannot qualify.
    """

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

    def resolve_facts(self) -> list[EvidenceFact]:
        facts: list[EvidenceFact] = []
        facts.extend(self._lifecycle_facts())
        facts.extend(self._execution_facts())
        facts.extend(self._holdout_facts())
        facts.extend(self._stats_facts())
        facts.extend(self._independence_facts())
        facts.extend(self._deployment_facts())
        return facts

    def qualify(self) -> AssuranceQualification:
        facts = self.resolve_facts()
        by_id = {f.fact_id: f for f in facts}
        satisfied: list[str] = []
        blockers: list[str] = []

        def ok(fid: str) -> bool:
            f = by_id.get(fid)
            return bool(f and f.is_true)

        # Cumulative gates — same ladder as the seed policy, artifact-derived.
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
        ]
        missing_sci = [name for name in scientific if not ok(name)]
        if missing_sci:
            blockers.extend(missing_sci)
            return self._result(level, facts, blockers=blockers, satisfied=satisfied)
        satisfied.extend(scientific)
        level = AssuranceLevel.SCIENTIFICALLY_QUALIFIED

        deployment = [
            "prospective_predictions_registered",
            "deployment_outcomes_collected",
            "calibration_analysis_complete",
            "applicability_regime_declared",
        ]
        missing_dep = [name for name in deployment if not ok(name)]
        if missing_dep:
            blockers.extend(missing_dep)
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
        facts_digest = digest_of([f.model_dump(mode="json") for f in facts])
        artifact_refs = tuple(
            sorted({f.source_artifact_digest for f in facts if f.source_artifact_digest})
        )
        security = any(f.fact_id == "security_grade_execution" and f.is_true for f in facts)
        return AssuranceQualification(
            level=level.label,
            ordinal=int(level),
            blockers=tuple(blockers),
            satisfied=tuple(satisfied),
            security_grade_execution=security,
            claim_digest=self.claim.digest,
            facts_digest=facts_digest,
            artifact_refs=artifact_refs,
            fact_ids=tuple(f.fact_id for f in facts),
            resolver_version=RESOLVER_VERSION,
        )

    def _lifecycle_facts(self) -> list[EvidenceFact]:
        facts: list[EvidenceFact] = []
        sealed = _read_json(self.root / "sealed_run.json")
        receipt = _read_json(self.root / "label_release_receipt.json")
        freeze = _read_json(self.root / "freeze.json")
        release = _read_json(self.root / "release.json")
        manifest = _read_json(self.root / "manifest.json")

        has_impl = bool(sealed or manifest)
        src = (
            str(sealed.get("content_digest"))
            if sealed and sealed.get("content_digest")
            else digest_of({"root": str(self.root)})
        )
        facts.append(
            _fact(
                "implementation_present",
                source=src,
                validator="lifecycle.sealed_or_manifest",
                outcome="true" if has_impl else "false",
                reasons=() if has_impl else ("no_sealed_run_or_manifest",),
            )
        )

        bound = bool(sealed and sealed.get("content_digest") and freeze)
        facts.append(
            _fact(
                "evidence_artifacts_bound",
                source=src,
                validator="lifecycle.artifact_presence",
                outcome="true" if bound else "false",
            )
        )
        facts.append(
            _fact(
                "immutable_artifacts_bound",
                source=src,
                validator="lifecycle.sealed_run_digest",
                outcome="true" if bound else "false",
            )
        )

        budget_ok = bool(sealed and sealed.get("budget_digest"))
        facts.append(
            _fact(
                "exact_budget_evidence",
                source=str(sealed.get("budget_digest") or src) if sealed else src,
                validator="lifecycle.budget_digest",
                outcome="true" if budget_ok else "false",
            )
        )

        life_ok = bool(freeze and release and receipt)
        facts.append(
            _fact(
                "lifecycle_freeze_adjudicate_release",
                source=str(receipt.get("content_digest") or src) if receipt else src,
                validator="lifecycle.freeze_adjudicate_release",
                outcome="true" if life_ok else "false",
                reasons=() if life_ok else ("missing_freeze_release_or_receipt",),
            )
        )
        return facts

    def _execution_facts(self) -> list[EvidenceFact]:
        sealed = _read_json(self.root / "sealed_run.json") or {}
        meta = sealed.get("metadata") or {}
        src = str(sealed.get("content_digest") or digest_of({"exec": str(self.root)}))
        mode = str(meta.get("execution_mode") or meta.get("backend_kind") or "local_dev")
        security_flag = bool(meta.get("security_grade"))
        # Rootful / local / process paths hard-cap security_grade to false.
        localish = mode in {"local_dev", "process", "process_local"} or not security_flag
        grade = (
            security_flag
            and not localish
            and mode
            in {
                "security_grade",
                "container_isolated",
                "microvm_isolated",
                "separate_host",
                "docker_rootless",
            }
        )
        reasons: list[str] = []
        if localish:
            reasons.append("rootful_or_local_execution_caps_security_grade")
        if not meta.get("execution_boundary_digests") and not sealed.get(
            "execution_boundary_digests"
        ):
            reasons.append("execution_boundary_missing")
            grade = False
        return [
            _fact(
                "security_grade_execution",
                source=src,
                validator="execution.boundary_and_mode",
                outcome="true" if grade else "false",
                reasons=tuple(reasons),
            )
        ]

    def _holdout_facts(self) -> list[EvidenceFact]:
        sealed = _read_json(self.root / "sealed_run.json") or {}
        custody = _read_json(self.root / "custody" / "hidden_split.json")
        src = str(
            sealed.get("custody_digest")
            or (custody or {}).get("content_digest")
            or digest_of({"holdout": str(self.root)})
        )
        holdout = bool(sealed.get("custody_digest") or custody)
        labels_out = bool(
            (self.root / "vault" / "private").is_dir()
            or sealed.get("vault_tip_digest")
            or (self.root / "label_release_receipt.json").is_file()
        )
        return [
            _fact(
                "hidden_labels_outside_attack_plane",
                source=src,
                validator="custody.hidden_labels",
                outcome="true" if labels_out else "false",
            ),
            _fact(
                "hidden_holdout_sealed",
                source=src,
                validator="custody.hidden_split",
                outcome="true" if holdout else "false",
                reasons=() if holdout else ("custody_digest_missing",),
            ),
        ]

    def _stats_facts(self) -> list[EvidenceFact]:
        sealed = _read_json(self.root / "sealed_run.json") or {}
        src = str(
            sealed.get("preregistration_digest") or sealed.get("content_digest") or ("0" * 64)
        )
        prereg = bool(sealed.get("preregistration_digest"))
        # Strong attacker / negatives / estimands: require sealed digests or report.
        report = _read_json(self.root / "report" / "stats.json") or {}
        negatives = True
        if report:
            # Fail if report drops censored/missing channels.
            negatives = "censored" in report or "missingness" in str(report)
        budgeted = bool(sealed.get("budget_digest"))
        estimands = bool(prereg) or bool(report.get("primary_estimands"))
        return [
            _fact(
                "preregistered_study",
                source=src,
                validator="stats.preregistration",
                outcome="true" if prereg else "false",
            ),
            _fact(
                "strong_attacker_budgeted",
                source=str(sealed.get("budget_digest") or src),
                validator="stats.budget",
                outcome="true" if budgeted else "false",
            ),
            _fact(
                "qualification_estimands_complete",
                source=src,
                validator="stats.estimands",
                outcome="true" if estimands else "false",
            ),
            _fact(
                "negative_results_preserved",
                source=src,
                validator="stats.negatives",
                outcome="true" if negatives else "false",
            ),
        ]

    def _independence_facts(self) -> list[EvidenceFact]:
        facts: list[EvidenceFact] = []
        review_ok = False
        recon_ok = False
        reasons: list[str] = []
        src = digest_of({"claim": self.claim.digest, "roots": sorted(self.trust_roots)})
        if not self.attestations:
            reasons.append("no_external_attestation")
        for att in self.attestations:
            try:
                verify_external_attestation(
                    att,
                    claim=self.claim,
                    trust_roots=self.trust_roots,
                    subject_digest=self._subject_digest(),
                )
                review_ok = True
                if att.reconstruction_digest:
                    recon_ok = True
            except ValueError as exc:
                reasons.append(str(exc))
        if review_ok and not recon_ok:
            reasons.append("reconstruction_digest_missing")
        facts.append(
            _fact(
                "independent_review",
                source=src,
                validator="attestation.external_trust_root",
                outcome="true" if review_ok else "false",
                reasons=tuple(reasons),
            )
        )
        facts.append(
            _fact(
                "independent_reconstruction",
                source=src,
                validator="attestation.reconstruction",
                outcome="true" if recon_ok else "false",
                reasons=tuple(reasons),
            )
        )
        return facts

    def _deployment_facts(self) -> list[EvidenceFact]:
        regs = (
            list((self.root / "registrations").glob("*.json"))
            if (self.root / "registrations").is_dir()
            else []
        )
        pred_regs = []
        for path in regs:
            if path.name.endswith(".payload.json"):
                continue
            body = _read_json(path) or {}
            if body.get("registration_kind") == "deployment_prediction":
                pred_regs.append(body)
        src = (
            digest_of({"regs": [r.get("content_digest") for r in pred_regs]})
            if pred_regs
            else ("0" * 64)
        )
        outcomes = (self.root / "deployment" / "outcomes.json").is_file()
        calib = (self.root / "deployment" / "calibration_report.json").is_file()
        appl = (self.root / "deployment" / "applicability.json").is_file()
        return [
            _fact(
                "prospective_predictions_registered",
                source=src,
                validator="deployment.prediction_registration",
                outcome="true" if pred_regs else "false",
            ),
            _fact(
                "deployment_outcomes_collected",
                source=src,
                validator="deployment.outcomes",
                outcome="true" if outcomes else "false",
            ),
            _fact(
                "calibration_analysis_complete",
                source=src,
                validator="deployment.calibration",
                outcome="true" if calib else "false",
            ),
            _fact(
                "applicability_regime_declared",
                source=src,
                validator="deployment.applicability",
                outcome="true" if appl else "false",
            ),
        ]

    def _subject_digest(self) -> str:
        sealed = _read_json(self.root / "sealed_run.json")
        if sealed and sealed.get("content_digest"):
            return str(sealed["content_digest"])
        return digest_of({"root": str(self.root.resolve())})


def verify_external_attestation(
    attestation: ExternalAssuranceAttestation,
    *,
    claim: AssuranceClaim,
    trust_roots: dict[str, str],
    subject_digest: str,
) -> None:
    """Verify attestation against external trust roots; reject self-issued / wrong subject."""
    if attestation.claim_digest != claim.digest:
        raise ValueError("attestation claim_digest mismatch")
    if attestation.subject_digest != subject_digest:
        raise ValueError("attestation subject mismatch")
    root = trust_roots.get(attestation.trust_root_id)
    if root is None:
        raise ValueError("attestation trust root not configured")
    # Self-issued: reviewer_id equals a local/self marker or trust root id collision.
    if attestation.reviewer_id in {"self", "local", "internal"} or attestation.reviewer_id == (
        attestation.trust_root_id
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
    """Helper to build a correctly signed attestation for tests / external tools."""
    ts = float(time.time() if issued_at is None else issued_at)
    signature = digest_of(
        {
            "attestation_id": attestation_id,
            "subject_digest": subject_digest,
            "claim_digest": claim.digest,
            "reviewer_id": reviewer_id,
            "trust_root_id": trust_root_id,
            "issued_at": ts,
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
        issued_at=ts,
        reconstruction_digest=reconstruction_digest,
    )


def qualify_run(
    run_or_study: Path | str,
    *,
    claim: AssuranceClaim | dict[str, Any] | Path | str,
    trust_roots: dict[str, str] | None = None,
    attestations: list[ExternalAssuranceAttestation] | None = None,
) -> AssuranceQualification:
    """Public qualification entry: artifact-derived facts only."""
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
    # Refuse pure boolean promotion payloads dropped beside the run.
    boolean_bag = root / "assurance_evidence_booleans.json"
    if boolean_bag.is_file():
        raise ValueError(
            "caller-supplied AssuranceEvidence boolean bags are not a qualification path; "
            "remove assurance_evidence_booleans.json and provide sealed artifacts"
        )
    resolver = EvidenceResolver(
        root,
        claim=claim_obj,
        trust_roots=trust_roots,
        attestations=attestations,
    )
    return resolver.qualify()


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
