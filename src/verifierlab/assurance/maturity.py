"""Evidence-derived assurance maturity.

A maturity label is an output of evidence checks, never a campaign setting.
This module intentionally caps process-local evidence below scientific
qualification even if every software-level check passes.
"""

from __future__ import annotations

from enum import IntEnum

from pydantic import BaseModel, ConfigDict, Field


class AssuranceLevel(IntEnum):
    NOT_IMPLEMENTED = 0
    IMPLEMENTED_UNVERIFIED = 1
    INTERNALLY_VERIFIED = 2
    INDEPENDENTLY_VERIFIED = 3
    SCIENTIFICALLY_QUALIFIED = 4
    DEPLOYMENT_CALIBRATED = 5

    @property
    def label(self) -> str:
        return {
            self.NOT_IMPLEMENTED: "not_implemented",
            self.IMPLEMENTED_UNVERIFIED: "implemented_unverified",
            self.INTERNALLY_VERIFIED: "internally_verified",
            self.INDEPENDENTLY_VERIFIED: "independently_verified",
            self.SCIENTIFICALLY_QUALIFIED: "scientifically_qualified",
            self.DEPLOYMENT_CALIBRATED: "deployment_calibrated",
        }[self]


class AssuranceEvidence(BaseModel):
    """Machine-checkable evidence predicates for a single assurance proposition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    implemented: bool = False
    internal_tests_passed: bool = False
    immutable_artifacts_bound: bool = False
    exact_budget_evidence: bool = False
    lifecycle_freeze_adjudicate_release: bool = False
    hidden_labels_outside_attack_plane: bool = False

    # Execution trust boundary. `process_local` is explicitly non-security-grade.
    execution_mode: str = "process_local"
    worker_no_network: bool = False
    worker_read_only_root: bool = False
    worker_no_secret_mounts: bool = False
    worker_non_root: bool = False
    adjudicator_separate_trust_domain: bool = False

    # Evidence beyond self-tests.
    independent_review: bool = False
    independent_reconstruction: bool = False
    preregistered_study: bool = False
    strong_attacker_budgeted: bool = False
    hidden_holdout_sealed: bool = False
    qualification_estimands_complete: bool = False
    negative_results_preserved: bool = False

    # Prospective evidence.
    prospective_predictions_registered_before_outcomes: bool = False
    deployment_outcomes_collected: bool = False
    calibration_analysis_complete: bool = False
    applicability_regime_declared: bool = False


class AssuranceQualification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    level: str
    ordinal: int
    blockers: tuple[str, ...] = ()
    satisfied: tuple[str, ...] = ()
    security_grade_execution: bool = False
    proposition: str = Field(min_length=1)


def _security_grade(e: AssuranceEvidence) -> bool:
    return (
        e.execution_mode in {"container_isolated", "microvm_isolated", "separate_host"}
        and e.worker_no_network
        and e.worker_read_only_root
        and e.worker_no_secret_mounts
        and e.worker_non_root
        and e.adjudicator_separate_trust_domain
        and e.hidden_labels_outside_attack_plane
    )


def qualify_assurance(
    evidence: AssuranceEvidence,
    *,
    proposition: str,
) -> AssuranceQualification:
    """Return the strongest level justified by the supplied evidence.

    Progression is monotone and cumulative: later levels require all earlier
    obligations. This prevents a strong external experiment from laundering a
    weak artifact chain, and prevents an impressive local test suite from being
    called scientific qualification.
    """
    satisfied: list[str] = []
    blockers: list[str] = []

    if not evidence.implemented:
        return AssuranceQualification(
            level=AssuranceLevel.NOT_IMPLEMENTED.label,
            ordinal=int(AssuranceLevel.NOT_IMPLEMENTED),
            blockers=("implementation_missing",),
            proposition=proposition,
        )
    satisfied.append("implementation_present")
    level = AssuranceLevel.IMPLEMENTED_UNVERIFIED

    internal_requirements = {
        "internal_tests_not_passed": evidence.internal_tests_passed,
        "artifacts_not_immutably_bound": evidence.immutable_artifacts_bound,
        "budget_evidence_missing": evidence.exact_budget_evidence,
        "lifecycle_not_closed": evidence.lifecycle_freeze_adjudicate_release,
        "hidden_label_plane_not_separated": evidence.hidden_labels_outside_attack_plane,
    }
    missing_internal = [name for name, ok in internal_requirements.items() if not ok]
    if missing_internal:
        blockers.extend(missing_internal)
        return AssuranceQualification(
            level=level.label,
            ordinal=int(level),
            blockers=tuple(blockers),
            satisfied=tuple(satisfied),
            security_grade_execution=_security_grade(evidence),
            proposition=proposition,
        )
    satisfied.extend(
        [
            "internal_tests_passed",
            "immutable_artifacts_bound",
            "exact_budget_evidence",
            "freeze_adjudicate_release_closed",
            "hidden_labels_outside_attack_plane",
        ]
    )
    level = AssuranceLevel.INTERNALLY_VERIFIED

    # Independent verification is a review/reconstruction property, not a local CI property.
    if not (evidence.independent_review and evidence.independent_reconstruction):
        if not evidence.independent_review:
            blockers.append("independent_review_missing")
        if not evidence.independent_reconstruction:
            blockers.append("independent_reconstruction_missing")
        return AssuranceQualification(
            level=level.label,
            ordinal=int(level),
            blockers=tuple(blockers),
            satisfied=tuple(satisfied),
            security_grade_execution=_security_grade(evidence),
            proposition=proposition,
        )
    satisfied.extend(["independent_review", "independent_reconstruction"])
    level = AssuranceLevel.INDEPENDENTLY_VERIFIED

    scientific_requirements = {
        "security_grade_execution_missing": _security_grade(evidence),
        "preregistered_study_missing": evidence.preregistered_study,
        "strong_attacker_budget_evidence_missing": evidence.strong_attacker_budgeted,
        "hidden_holdout_not_sealed": evidence.hidden_holdout_sealed,
        "qualification_estimands_incomplete": evidence.qualification_estimands_complete,
        "negative_results_not_preserved": evidence.negative_results_preserved,
    }
    missing_scientific = [name for name, ok in scientific_requirements.items() if not ok]
    if missing_scientific:
        blockers.extend(missing_scientific)
        return AssuranceQualification(
            level=level.label,
            ordinal=int(level),
            blockers=tuple(blockers),
            satisfied=tuple(satisfied),
            security_grade_execution=_security_grade(evidence),
            proposition=proposition,
        )
    satisfied.extend(
        [
            "security_grade_execution",
            "preregistered_study",
            "strong_attacker_budgeted",
            "hidden_holdout_sealed",
            "qualification_estimands_complete",
            "negative_results_preserved",
        ]
    )
    level = AssuranceLevel.SCIENTIFICALLY_QUALIFIED

    deployment_requirements = {
        "prospective_predictions_not_registered": evidence.prospective_predictions_registered_before_outcomes,
        "deployment_outcomes_missing": evidence.deployment_outcomes_collected,
        "calibration_analysis_incomplete": evidence.calibration_analysis_complete,
        "applicability_regime_missing": evidence.applicability_regime_declared,
    }
    missing_deployment = [name for name, ok in deployment_requirements.items() if not ok]
    if missing_deployment:
        blockers.extend(missing_deployment)
        return AssuranceQualification(
            level=level.label,
            ordinal=int(level),
            blockers=tuple(blockers),
            satisfied=tuple(satisfied),
            security_grade_execution=True,
            proposition=proposition,
        )

    satisfied.extend(
        [
            "prospective_predictions_registered",
            "deployment_outcomes_collected",
            "calibration_analysis_complete",
            "applicability_regime_declared",
        ]
    )
    level = AssuranceLevel.DEPLOYMENT_CALIBRATED
    return AssuranceQualification(
        level=level.label,
        ordinal=int(level),
        blockers=(),
        satisfied=tuple(satisfied),
        security_grade_execution=True,
        proposition=proposition,
    )


__all__ = [
    "AssuranceEvidence",
    "AssuranceLevel",
    "AssuranceQualification",
    "qualify_assurance",
]
