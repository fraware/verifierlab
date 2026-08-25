"""WP-11: failure layers, novelty routing, taxonomy separation."""

from __future__ import annotations

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.exploits import (
    ExploitClass,
    FailureLayer,
    attributed_failure_layer,
    bind_taxonomy_and_layer,
    build_exploit_case,
    compile_failure_layer_report_section,
    compile_novelty_corpus_index,
    map_exploit_class_to_failure_layer,
    refuse_automatic_class_to_layer,
    route_novelty_fingerprint,
)
from verifierlab.exploits.integration import (
    CalibrationLayerStratum,
    attach_failure_layers_to_report_payload,
    repair_stratum_from_assessment,
)
from verifierlab.minimization import minimize_exploit


def test_no_automatic_class_to_layer_map() -> None:
    with pytest.raises(ValueError, match="no automatic"):
        map_exploit_class_to_failure_layer(ExploitClass.UNAUTHORIZED_ACTION)
    with pytest.raises(ValueError, match="no automatic"):
        refuse_automatic_class_to_layer(ExploitClass.RUBRIC_GAMING)


def test_taxonomy_and_layer_require_explicit_binding() -> None:
    assessment = attributed_failure_layer(
        exploit_case_digest=digest_of("case"),
        layer=FailureLayer.IMPLEMENTATION,
        proposition="Verifier accepted a case forbidden by its declared contract.",
        basis=("declared_spec_comparison",),
        evidence_digests=(digest_of("trace"),),
    )
    binding = bind_taxonomy_and_layer(
        exploit_class=ExploitClass.UNAUTHORIZED_ACTION,
        assessment=assessment,
    )
    assert binding.automatic_class_to_layer_map is False
    assert binding.failure_layer_assessment is not None


def test_minimization_preserves_public_accept_and_intent() -> None:
    traj = {
        "steps": [
            {"op": "noop"},
            {"op": "refund", "amount": 200, "user_id": "eve"},
            {"op": "noop"},
        ]
    }

    def verifier(t: dict) -> bool:
        steps = t.get("steps") or []
        return any(s.get("op") == "refund" and int(s.get("amount", 0)) > 100 for s in steps)

    def is_valid(t: dict) -> bool:
        steps = t.get("steps") or []
        return not any(s.get("user_id") == "eve" and int(s.get("amount", 0)) > 100 for s in steps)

    result = minimize_exploit(traj, verifier=verifier, is_valid=is_valid)
    assert result["preservation"]["classic_predicate_holds"] is True
    assert result["preservation"]["public_accept_preserved"] is True
    assert result["preservation"]["hidden_invalid_preserved"] is True
    assert len(result["minimized_steps"]) <= len(traj["steps"])


def test_novelty_routing_strict_blocks_attack_to_holdout() -> None:
    case = build_exploit_case(
        unit_id="u1",
        trajectory={"steps": [{"op": "refund", "amount": 200, "user_id": "eve"}]},
        cohort="optimized",
        access_model="black-box",
    )
    with pytest.raises(ValueError, match="strict_no_cross_plane"):
        route_novelty_fingerprint(
            case,
            source_plane="attack",
            destination="holdout",
            leakage_policy="strict_no_cross_plane",
        )
    decision = route_novelty_fingerprint(
        case,
        source_plane="attack",
        destination="holdout",
        leakage_policy="explicit_custody_transfer",
        custody_transfer_digest=digest_of("custody-xfer"),
    )
    index = compile_novelty_corpus_index(
        index_id="nov1",
        decisions=[decision],
        leakage_policy="explicit_custody_transfer",
    )
    assert case.novelty_fingerprint in index.holdout_fingerprints


def test_report_and_repair_calibration_strata_integration() -> None:
    assessment = attributed_failure_layer(
        exploit_case_digest=digest_of("case-2"),
        layer=FailureLayer.SPECIFICATION,
        proposition="Rubric omits an intended authorization condition.",
        basis=("specification_adequacy_review",),
        evidence_digests=(digest_of("rubric"),),
    )
    section = compile_failure_layer_report_section([assessment])
    payload = attach_failure_layers_to_report_payload({"run_id": "r1"}, section)
    assert payload["failure_layers_digest"] == section.content_digest
    stratum = repair_stratum_from_assessment(
        repair_candidate_digest=digest_of("repair"),
        assessment=assessment,
    )
    assert stratum.layers == (FailureLayer.SPECIFICATION,)
    calib = CalibrationLayerStratum(
        calibration_item_digest=digest_of("planted"),
        layer_assessment_digest=assessment.content_digest,
        layers=(FailureLayer.IMPLEMENTATION,),
    )
    assert calib.supports_unknown_robustness_claim is False
