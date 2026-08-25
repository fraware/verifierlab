"""Regression tests for the repair/fresh-reattack qualification boundary."""

from __future__ import annotations

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.repairs.canonical_evidence import CanonicalFreshRunEvidence
from verifierlab.repairs.compare import (
    _run_development_fresh_attack,
    _validate_canonical_fresh_evidence,
)


def test_runtime_bound_search_is_refused_by_repair_helper() -> None:
    with pytest.raises(ValueError, match="canonical campaign runtime/broker"):
        _run_development_fresh_attack(
            strategy_name="beam",
            config={},
            verifier=lambda _trajectory: True,
            is_valid=lambda _trajectory: False,
            episodes=1,
            seeds=[],
            budget_queries=1,
            build_trajectory=None,
            holdout_forbidden=[],
        )


def test_development_helper_keeps_one_strategy_across_episodes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = 0

    class FakeStrategy:
        def __init__(self) -> None:
            self.i = 0
            self.feedback = 0

        def propose(self) -> dict[str, object]:
            self.i += 1
            return {"op": "probe", "nonce": self.i}

        def observe(self, _feedback: dict[str, object]) -> None:
            self.feedback += 1

    strategy = FakeStrategy()

    def fake_create(_name: str, _config: dict[str, object]) -> FakeStrategy:
        nonlocal created
        created += 1
        return strategy

    monkeypatch.setattr("verifierlab.repairs.compare.create_strategy", fake_create)
    rows, ledger = _run_development_fresh_attack(
        strategy_name="structured_fuzz",
        config={"max_steps": 1},
        verifier=lambda _trajectory: True,
        is_valid=lambda _trajectory: False,
        episodes=3,
        seeds=[17],
        budget_queries=3,
        build_trajectory=None,
        holdout_forbidden=[],
    )

    assert created == 1
    assert len(rows) == 3
    assert strategy.feedback == 3
    assert ledger["persistent_strategy"] is True
    assert ledger["qualification_grade"] is False


def _canonical_evidence(
    *,
    rows: list[dict[str, object]],
    profile_digest: str,
    repair_candidate_digest: str,
    budget: int = 100,
    holdout_isolated: bool = True,
    execution_security_grade: bool = True,
    fresh_attacker_established: bool = True,
    blockers: tuple[str, ...] = (),
) -> CanonicalFreshRunEvidence:
    return CanonicalFreshRunEvidence(
        run_id="fresh-run",
        release_tip_digest="1" * 64,
        sealed_run_digest="2" * 64,
        campaign_digest="3" * 64,
        verifier_profile_digest=profile_digest,
        ledger_digest="4" * 64,
        split_manifest_digest="5" * 64,
        results_digest=digest_of(rows),
        repair_candidate_digest=repair_candidate_digest,
        budget_limit_queries=budget,
        queries_used=min(10, budget),
        holdout_unit_ids=("u1",),
        sealed_holdout_work_digests=("6" * 64,),
        execution_boundary_digests=("7" * 64,),
        labels_released=True,
        holdout_isolated=holdout_isolated,
        execution_security_grade=execution_security_grade,
        fresh_attacker_established=fresh_attacker_established,
        qualification_blockers=blockers,
    )


def test_canonical_fresh_evidence_binds_results_profile_budget_and_candidate() -> None:
    rows = [
        {
            "unit_id": "u1",
            "cohort": "fresh_attack",
            "verifier_accepted": True,
            "gt_valid": False,
        }
    ]
    profile_digest = "8" * 64
    candidate_digest = "9" * 64
    evidence = _canonical_evidence(
        rows=rows,
        profile_digest=profile_digest,
        repair_candidate_digest=candidate_digest,
    )
    failures = _validate_canonical_fresh_evidence(
        evidence,
        results=rows,
        new_profile_digest=profile_digest,
        minimum_budget=100,
        repair_candidate_digest=candidate_digest,
    )
    assert failures == []


def test_canonical_fresh_evidence_fails_closed_on_rebinding_and_blockers() -> None:
    rows = [{"unit_id": "u1", "cohort": "fresh_attack"}]
    evidence = _canonical_evidence(
        rows=rows,
        profile_digest="a" * 64,
        repair_candidate_digest="b" * 64,
        budget=9,
        holdout_isolated=False,
        execution_security_grade=False,
        fresh_attacker_established=False,
        blockers=("execution_not_security_grade:u1",),
    ).model_copy(update={"results_digest": "c" * 64})
    failures = _validate_canonical_fresh_evidence(
        evidence,
        results=rows,
        new_profile_digest="d" * 64,
        minimum_budget=10,
        repair_candidate_digest="e" * 64,
    )
    assert set(failures) == {
        "canonical_fresh_results_digest_mismatch",
        "canonical_fresh_verifier_profile_mismatch",
        "canonical_repair_candidate_mismatch",
        "canonical_fresh_budget_smaller_than_required",
        "canonical_holdout_not_isolated",
        "canonical_execution_not_security_grade",
        "canonical_attacker_not_fresh",
        "canonical_evidence_has_blockers",
    }
