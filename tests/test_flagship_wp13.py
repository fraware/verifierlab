"""WP-13 flagship study artifact contracts."""

from __future__ import annotations

import json

from verifierlab.assurance.flagship import STUDY_DIR, build_flagship_study
from verifierlab.assurance.maturity import AssuranceClaim
from verifierlab.assurance.resolver import qualify_run
from verifierlab.assurance.study import ScientificStudyRegistration
from verifierlab.config.preregistration import AnalysisPreregistration


def test_flagship_study_builds_and_caps_maturity() -> None:
    summary = build_flagship_study(force=True)
    assert STUDY_DIR.is_dir()
    assert (STUDY_DIR / "README.md").is_file()
    assert (STUDY_DIR / "scientific_study_registration.json").is_file()
    assert (STUDY_DIR / "claim_table.json").is_file()
    assert (STUDY_DIR / "preregistration.json").is_file()
    assert (STUDY_DIR / "security_grade_attempt.json").is_file()

    reg = ScientificStudyRegistration.model_validate(
        {
            k: v
            for k, v in json.loads(
                (STUDY_DIR / "scientific_study_registration.json").read_text(encoding="utf-8")
            ).items()
            if k != "content_digest"
        }
    )
    assert set(reg.partition_digests) >= {
        "discovery",
        "clean_regression",
        "repair_holdout",
        "final_sealed_evaluation",
        "transfer_corpus",
        "planted_calibration",
    }
    assert len(reg.primary_estimand_ids) == 8

    prereg = AnalysisPreregistration.model_validate(
        {
            k: v
            for k, v in json.loads(
                (STUDY_DIR / "preregistration.json").read_text(encoding="utf-8")
            ).items()
            if k != "content_digest"
        }
    )
    primary_ids = {e.estimand_id for e in prereg.estimands if e.role == "primary"}
    assert primary_ids == set(reg.primary_estimand_ids)

    claim = AssuranceClaim.model_validate(
        {
            k: v
            for k, v in json.loads((STUDY_DIR / "claim.json").read_text(encoding="utf-8")).items()
            if k != "content_digest"
        }
    )
    q = qualify_run(STUDY_DIR, claim=claim)
    # Host cannot claim security_grade; scientific qualification blocked prospectively.
    assert q.security_grade_execution is False
    assert q.level == "internally_verified"
    assert "independent_review_missing" in q.blockers
    assert summary["maturity_level"] == q.level

    claim_table = json.loads((STUDY_DIR / "claim_table.json").read_text(encoding="utf-8"))
    assert claim_table["maturity_level"] == "internally_verified"
    assert "security_grade_execution" in claim_table["prospective_scientific_blockers"]
    planted = json.loads((STUDY_DIR / "partitions.json").read_text(encoding="utf-8"))
    assert planted["pooling_policy"]["supports_unknown_robustness_claim"] is False


def test_flagship_readme_states_claim_boundary() -> None:
    build_flagship_study(force=True)
    text = (STUDY_DIR / "README.md").read_text(encoding="utf-8")
    assert "internally_verified" in text
    assert "security_grade" in text
    assert "NOT** independent" in text or "NOT independent" in text
