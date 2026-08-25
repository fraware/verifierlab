from verifierlab.assurance import SEED_NOT_QUALIFICATION_PATH, AssuranceClaim, AssuranceLevel
from verifierlab.assurance.maturity import (
    AssuranceEvidence,
    compile_maturity_policy_seed,
)


def _claim(
    *, proposition: str = "verifier remains valid under declared optimization regime"
) -> AssuranceClaim:
    return AssuranceClaim(
        proposition=proposition,
        scope="campaign family A; black-box access; query budget <= 1000",
        assumptions=(
            "hidden adjudication labels remain outside the attack plane",
            "declared verifier profile is immutable during the run",
        ),
        trust_boundary="isolated worker plane; separate adjudication trust domain",
        specification_refs=("cas:verifier-profile:abc123", "cas:campaign-spec:def456"),
    )


def _evidence(**overrides: object) -> AssuranceEvidence:
    values: dict[str, object] = {
        "implemented": True,
        "internal_tests_passed": True,
        "immutable_artifacts_bound": True,
        "exact_budget_evidence": True,
        "lifecycle_freeze_adjudicate_release": True,
        "hidden_labels_outside_attack_plane": True,
        "evidence_refs": ("cas:run-manifest:001", "cas:analysis:002"),
    }
    values.update(overrides)
    return AssuranceEvidence(**values)


def test_public_package_is_policy_seed_not_qualification_api() -> None:
    import verifierlab.assurance as assurance

    assert SEED_NOT_QUALIFICATION_PATH is True
    assert assurance.SEED_NOT_QUALIFICATION_PATH is True
    assert "qualify_assurance" not in assurance.__all__
    assert "AssuranceEvidence" not in assurance.__all__
    assert not hasattr(assurance, "qualify_assurance")


def test_not_implemented_is_explicit() -> None:
    result = compile_maturity_policy_seed(AssuranceEvidence(), claim=_claim())
    assert result.level == AssuranceLevel.NOT_IMPLEMENTED.label
    assert result.blockers == ("implementation_missing",)


def test_internal_verification_requires_evidence_references() -> None:
    result = compile_maturity_policy_seed(_evidence(evidence_refs=()), claim=_claim())
    assert result.level == AssuranceLevel.IMPLEMENTED_UNVERIFIED.label
    assert "evidence_references_missing" in result.blockers


def test_missing_independent_evidence_caps_at_internal() -> None:
    result = compile_maturity_policy_seed(_evidence(), claim=_claim())
    assert result.level == AssuranceLevel.INTERNALLY_VERIFIED.label
    assert "independent_review_missing" in result.blockers
    assert "independent_reconstruction_missing" in result.blockers


def test_process_local_execution_cannot_be_scientifically_qualified() -> None:
    result = compile_maturity_policy_seed(
        _evidence(
            independent_review=True,
            independent_reconstruction=True,
            preregistered_study=True,
            strong_attacker_budgeted=True,
            hidden_holdout_sealed=True,
            qualification_estimands_complete=True,
            negative_results_preserved=True,
        ),
        claim=_claim(),
    )
    assert result.level == AssuranceLevel.INDEPENDENTLY_VERIFIED.label
    assert result.security_grade_execution is False
    assert "security_grade_execution_missing" in result.blockers


def test_security_grade_preregistered_evidence_reaches_scientific_level() -> None:
    result = compile_maturity_policy_seed(
        _evidence(
            execution_mode="container_isolated",
            worker_no_network=True,
            worker_read_only_root=True,
            worker_no_secret_mounts=True,
            worker_non_root=True,
            adjudicator_separate_trust_domain=True,
            independent_review=True,
            independent_reconstruction=True,
            preregistered_study=True,
            strong_attacker_budgeted=True,
            hidden_holdout_sealed=True,
            qualification_estimands_complete=True,
            negative_results_preserved=True,
        ),
        claim=_claim(),
    )
    assert result.level == AssuranceLevel.SCIENTIFICALLY_QUALIFIED.label
    assert result.security_grade_execution is True
    assert "prospective_predictions_not_registered" in result.blockers


def test_deployment_calibrated_requires_prospective_outcome_chain() -> None:
    result = compile_maturity_policy_seed(
        _evidence(
            execution_mode="microvm_isolated",
            worker_no_network=True,
            worker_read_only_root=True,
            worker_no_secret_mounts=True,
            worker_non_root=True,
            adjudicator_separate_trust_domain=True,
            independent_review=True,
            independent_reconstruction=True,
            preregistered_study=True,
            strong_attacker_budgeted=True,
            hidden_holdout_sealed=True,
            qualification_estimands_complete=True,
            negative_results_preserved=True,
            prospective_predictions_registered_before_outcomes=True,
            deployment_outcomes_collected=True,
            calibration_analysis_complete=True,
            applicability_regime_declared=True,
        ),
        claim=_claim(),
    )
    assert result.level == AssuranceLevel.DEPLOYMENT_CALIBRATED.label
    assert result.blockers == ()


def test_qualification_is_bound_to_exact_claim_and_evidence() -> None:
    evidence = _evidence()
    first = compile_maturity_policy_seed(evidence, claim=_claim(proposition="claim A"))
    second = compile_maturity_policy_seed(evidence, claim=_claim(proposition="claim B"))
    assert first.claim_digest != second.claim_digest
    assert first.evidence_digest == second.evidence_digest
    assert first.digest != second.digest

    changed_evidence = _evidence(evidence_refs=("cas:run-manifest:other",))
    third = compile_maturity_policy_seed(changed_evidence, claim=_claim(proposition="claim A"))
    assert first.claim_digest == third.claim_digest
    assert first.evidence_digest != third.evidence_digest
    assert first.digest != third.digest
