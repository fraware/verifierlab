"""Regression tests for the repair/fresh-reattack qualification boundary."""

from __future__ import annotations

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.repairs.compare import (
    FreshAttackProvenance,
    _run_development_fresh_attack,
    _validate_fresh_provenance,
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


def test_development_helper_keeps_one_strategy_across_episodes(monkeypatch: pytest.MonkeyPatch) -> None:
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


def test_fresh_provenance_binds_results_profile_and_budget() -> None:
    rows = [
        {
            "unit_id": "u1",
            "cohort": "fresh_attack",
            "verifier_accepted": True,
            "gt_valid": False,
        }
    ]
    provenance = FreshAttackProvenance(
        attack_engine="campaign_engine",
        run_digest="sha256:canonical-run",
        results_digest=digest_of(rows),
        verifier_profile_digest="sha256:new-profile",
        budget_queries=100,
        holdout_isolated=True,
        fresh_attacker=True,
    )
    failures = _validate_fresh_provenance(
        provenance,
        results=rows,
        new_profile_digest="sha256:new-profile",
        minimum_budget=100,
    )
    assert failures == []


def test_fresh_provenance_fails_closed_on_rebinding() -> None:
    rows = [{"unit_id": "u1", "cohort": "fresh_attack"}]
    provenance = FreshAttackProvenance(
        attack_engine="campaign_engine",
        run_digest="sha256:canonical-run",
        results_digest="sha256:wrong-results",
        verifier_profile_digest="sha256:wrong-profile",
        budget_queries=9,
        holdout_isolated=False,
        fresh_attacker=False,
    )
    failures = _validate_fresh_provenance(
        provenance,
        results=rows,
        new_profile_digest="sha256:new-profile",
        minimum_budget=10,
    )
    assert set(failures) == {
        "fresh_results_digest_mismatch",
        "fresh_verifier_profile_mismatch",
        "fresh_budget_smaller_than_required",
        "fresh_holdout_not_isolated",
        "attacker_not_fresh",
    }
