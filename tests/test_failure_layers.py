"""Evidence-linked failure-layer attribution tests."""

from __future__ import annotations

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.exploits import (
    FAILURE_LAYER_DESCRIPTIONS,
    FailureLayer,
    FailureLayerAssessment,
    attributed_failure_layer,
    indeterminate_failure_layer,
    mixed_failure_layers,
)

EXPLOIT = digest_of("exploit-case")
EVIDENCE = (digest_of("declared-spec"), digest_of("execution-trace"))


def test_single_layer_attribution_binds_proposition_and_evidence() -> None:
    assessment = attributed_failure_layer(
        exploit_case_digest=EXPLOIT,
        layer=FailureLayer.IMPLEMENTATION,
        proposition="The verifier accepted a case forbidden by its declared executable contract.",
        basis=("declared_spec_comparison",),
        evidence_digests=EVIDENCE,
        assumptions=(
            "The declared contract digest is the contract governing this verifier version.",
        ),
    )
    assert assessment.status == "attributed"
    assert assessment.layers == (FailureLayer.IMPLEMENTATION,)
    assert assessment.qualification_grade is False
    assert "declared executable contract" in FAILURE_LAYER_DESCRIPTIONS[FailureLayer.IMPLEMENTATION]

    changed = assessment.model_copy(
        update={
            "proposition": "A distinct causal proposition supported by the same evidence.",
        }
    )
    assert assessment.content_digest != changed.content_digest


def test_specification_layer_is_distinct_from_implementation_layer() -> None:
    implementation = attributed_failure_layer(
        exploit_case_digest=EXPLOIT,
        layer=FailureLayer.IMPLEMENTATION,
        proposition="Executable behavior deviates from the declared verifier contract.",
        basis=("declared_spec_comparison",),
        evidence_digests=EVIDENCE,
    )
    specification = attributed_failure_layer(
        exploit_case_digest=EXPLOIT,
        layer=FailureLayer.SPECIFICATION,
        proposition="The verifier implements its rubric, but the rubric omits an intended validity condition.",
        basis=("specification_adequacy_review",),
        evidence_digests=EVIDENCE,
    )
    assert implementation.layers != specification.layers
    assert implementation.content_digest != specification.content_digest


def test_environment_ontology_layer_requires_environment_semantics_evidence() -> None:
    assessment = attributed_failure_layer(
        exploit_case_digest=EXPLOIT,
        layer=FailureLayer.ENVIRONMENT_ONTOLOGY,
        proposition="The task representation omits an operational state needed by the intended claim.",
        basis=("environment_semantics_review",),
        evidence_digests=(digest_of("environment-semantics-audit"),),
    )
    assert assessment.layers == (FailureLayer.ENVIRONMENT_ONTOLOGY,)
    assert "representation" in FAILURE_LAYER_DESCRIPTIONS[FailureLayer.ENVIRONMENT_ONTOLOGY]


def test_mixed_attribution_preserves_multiple_causal_layers() -> None:
    assessment = mixed_failure_layers(
        exploit_case_digest=EXPLOIT,
        layers=(FailureLayer.SPECIFICATION, FailureLayer.ENVIRONMENT_ONTOLOGY),
        proposition="The written criterion and environment model jointly omit the operative condition.",
        basis=("specification_adequacy_review", "environment_semantics_review"),
        evidence_digests=EVIDENCE,
    )
    assert assessment.status == "mixed"
    assert assessment.layers == (
        FailureLayer.SPECIFICATION,
        FailureLayer.ENVIRONMENT_ONTOLOGY,
    )


def test_indeterminate_attribution_records_evidence_without_asserting_layer() -> None:
    assessment = indeterminate_failure_layer(
        exploit_case_digest=EXPLOIT,
        proposition="Available artifacts do not distinguish implementation failure from rubric inadequacy.",
        basis=("cross_boundary_analysis",),
        evidence_digests=(digest_of("partial-evidence"),),
    )
    assert assessment.status == "indeterminate"
    assert assessment.layers == ()
    assert assessment.qualification_grade is False


def test_invalid_status_layer_shapes_fail_closed() -> None:
    common = {
        "exploit_case_digest": EXPLOIT,
        "proposition": "Fixture proposition.",
        "basis": ("cross_boundary_analysis",),
        "evidence_digests": EVIDENCE,
    }
    with pytest.raises(ValueError, match="exactly one"):
        FailureLayerAssessment.model_validate(
            {
                **common,
                "status": "attributed",
                "layers": (FailureLayer.IMPLEMENTATION, FailureLayer.SPECIFICATION),
            }
        )
    with pytest.raises(ValueError, match="at least two"):
        FailureLayerAssessment.model_validate(
            {
                **common,
                "status": "mixed",
                "layers": (FailureLayer.IMPLEMENTATION,),
            }
        )
    with pytest.raises(ValueError, match="cannot assert"):
        FailureLayerAssessment.model_validate(
            {
                **common,
                "status": "indeterminate",
                "layers": (FailureLayer.IMPLEMENTATION,),
            }
        )
    with pytest.raises(ValueError, match="unique"):
        FailureLayerAssessment.model_validate(
            {
                **common,
                "status": "mixed",
                "layers": (FailureLayer.SPECIFICATION, FailureLayer.SPECIFICATION),
            }
        )


def test_evidence_and_proposition_are_mandatory() -> None:
    with pytest.raises(ValueError):
        FailureLayerAssessment(
            exploit_case_digest=EXPLOIT,
            status="attributed",
            layers=(FailureLayer.IMPLEMENTATION,),
            proposition="",
            basis=("declared_spec_comparison",),
            evidence_digests=EVIDENCE,
        )
    with pytest.raises(ValueError):
        FailureLayerAssessment(
            exploit_case_digest=EXPLOIT,
            status="attributed",
            layers=(FailureLayer.IMPLEMENTATION,),
            proposition="Fixture proposition.",
            basis=("declared_spec_comparison",),
            evidence_digests=(),
        )
