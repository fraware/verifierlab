"""WP-10: H/F/S qualification — holdout opacity, failed patches, fresh envelope."""

from __future__ import annotations

from typing import Any, Literal

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.campaigns.hacker_fixer_solver import (
    AgentProgramSpec,
    AttackExecution,
    FixerExecution,
    FixerInvocation,
    HackerFixerSolverPlan,
    HackerFixerStoppingRule,
    HackerInstantiationContext,
    HackerInvocation,
    SealedRepairHoldout,
    SolverExecution,
    SolverInvocation,
    VerifierCandidateBinding,
    assert_fixer_cannot_see_holdout,
    assert_fresh_attack_envelope,
    run_hacker_fixer_solver,
)
from verifierlab.execution.attacker_state import make_attacker_state_envelope
from verifierlab.repairs.candidate import RepairCandidateBinding


def _agent(
    role: Literal["hacker", "fixer", "solver"],
    name: str,
    *,
    model: str | None = None,
) -> AgentProgramSpec:
    kwargs: dict[str, Any] = {}
    if model is not None:
        kwargs.update(model_id=model, model_version="2026-08")
    return AgentProgramSpec(
        role=role,
        implementation_ref=f"tests.agents:{name}",
        version="1",
        configuration_digest=digest_of({"name": name}),
        capability_tags=("deterministic-fixture",),
        **kwargs,
    )


def _plan(**overrides: Any) -> HackerFixerSolverPlan:
    body: dict[str, Any] = {
        "experiment_id": "hfs-wp10",
        "initial_verifier_profile_digest": digest_of("verifier-v1"),
        "hacker": _agent("hacker", "hacker", model="model-h"),
        "fixer": _agent("fixer", "fixer", model="model-f"),
        "solver": _agent("solver", "solver", model="model-s"),
        "access_model": "black-box",
        "attack_family": "structured_reward_hack",
        "pre_attack_budget_queries": 4,
        "post_attack_budget_queries": 4,
        "solver_budget_queries": 3,
        "solver_suite_digest": digest_of("clean-suite-v1"),
        "seed": 19,
        "comparison_mode": "equal_budget",
        "sealed_repair_holdout": SealedRepairHoldout(
            holdout_commitment_digest=digest_of("holdout-commitment"),
            custody_digest=digest_of("custody"),
        ).model_dump(mode="json"),
        "stopping_rule": HackerFixerStoppingRule(
            max_rounds=2,
            registration_digest=digest_of("stop-rule"),
        ).model_dump(mode="json"),
    }
    body.update(overrides)
    return HackerFixerSolverPlan.model_validate(body)


class _Session:
    def __init__(
        self,
        spec: AgentProgramSpec,
        context: HackerInstantiationContext,
        *,
        instance_id: str,
        parent_checkpoint_digest: str | None = None,
        envelope_digest: str | None = None,
    ) -> None:
        self.spec = spec
        self.context = context
        self.instance_id = instance_id
        self.parent_checkpoint_digest = parent_checkpoint_digest
        self.envelope_digest = envelope_digest
        self.initial_state_digest = digest_of(
            {"instance_id": instance_id, "phase": context.phase, "anchor": context.anchor_digest}
        )

    def run(self, invocation: HackerInvocation) -> AttackExecution:
        result_digests = tuple(
            digest_of({"instance": self.instance_id, "phase": invocation.phase, "query": index})
            for index in range(invocation.budget_queries)
        )
        return AttackExecution(
            phase=invocation.phase,
            attacker_spec_digest=self.spec.content_digest,
            instance_id=self.instance_id,
            initialized_after_digest=self.context.anchor_digest,
            initial_state_digest=self.initial_state_digest,
            parent_checkpoint_digest=self.parent_checkpoint_digest,
            terminal_state_digest=digest_of(result_digests),
            budget_queries=invocation.budget_queries,
            queries_used=len(result_digests),
            result_digests=result_digests,
            attacker_state_envelope_digest=self.envelope_digest,
        )


def _fixer(spec: AgentProgramSpec, invocation: FixerInvocation) -> FixerExecution:
    candidate = VerifierCandidateBinding(
        candidate_id="candidate-v2",
        verifier_profile_digest=digest_of("verifier-v2"),
        artifact_digest=digest_of("verifier-v2-artifact"),
        parent_verifier_profile_digest=invocation.initial_verifier_profile_digest,
        repair_input_digest=invocation.content_digest,
    )
    return FixerExecution(
        fixer_spec_digest=spec.content_digest,
        invocation_digest=invocation.content_digest,
        repair_artifact_digest=digest_of("repair-patch"),
        candidate=candidate,
    )


def _solver(
    spec: AgentProgramSpec,
    invocation: SolverInvocation,
    *,
    clean_pass: bool = True,
    frr_collapse: bool = False,
) -> SolverExecution:
    result_digests = tuple(
        digest_of({"suite": invocation.suite_digest, "query": index})
        for index in range(invocation.budget_queries)
    )
    return SolverExecution(
        solver_spec_digest=spec.content_digest,
        invocation_digest=invocation.content_digest,
        candidate_digest=invocation.candidate_digest,
        suite_digest=invocation.suite_digest,
        budget_queries=invocation.budget_queries,
        queries_used=len(result_digests),
        result_digests=result_digests,
        clean_pass=clean_pass,
        frr_collapse_detected=frr_collapse,
    )


def test_fixer_never_sees_sealed_repair_holdout() -> None:
    holdout = SealedRepairHoldout(
        holdout_commitment_digest=digest_of("secret-holdout"),
        custody_digest=digest_of("custody"),
    )
    clean = FixerInvocation(
        initial_verifier_profile_digest=digest_of("v1"),
        pre_attack_execution_digest=digest_of("pre"),
        pre_attack_results_digest=digest_of("results"),
        fixer_spec_digest=digest_of("fixer"),
    )
    assert_fixer_cannot_see_holdout(clean, holdout)
    leaked = FixerInvocation(
        initial_verifier_profile_digest=holdout.holdout_commitment_digest,
        pre_attack_execution_digest=digest_of("pre"),
        pre_attack_results_digest=digest_of("results"),
        fixer_spec_digest=digest_of("fixer"),
    )
    with pytest.raises(ValueError, match="fixer_saw_sealed_repair_holdout"):
        assert_fixer_cannot_see_holdout(leaked, holdout)


def test_equal_budget_rejects_stronger_distinct_post_hacker() -> None:
    with pytest.raises(ValueError, match="separate coordinate"):
        _plan(post_repair_hacker=_agent("hacker", "stronger", model="model-h-plus"))


def test_failed_patch_preserved_and_stops() -> None:
    plan = _plan()
    counter = 0

    def factory(spec: AgentProgramSpec, context: HackerInstantiationContext) -> _Session:
        nonlocal counter
        counter += 1
        return _Session(spec, context, instance_id=f"h-{counter}")

    def failing_fixer(spec: AgentProgramSpec, invocation: FixerInvocation) -> FixerExecution:
        base = _fixer(spec, invocation)
        return base.model_copy(
            update={"patch_succeeded": False, "failure_reasons": ("does_not_compile",)}
        )

    artifact = run_hacker_fixer_solver(
        plan,
        hacker_factory=factory,
        fixer_runner=failing_fixer,
        solver_runner=lambda s, i: _solver(s, i),
    )
    assert artifact.post_attack is None
    assert len(artifact.failed_patches) == 1
    assert artifact.failed_patches[0].failure_reasons == ("does_not_compile",)
    assert artifact.stopping_decision == "stop_failed_patch"


def test_successful_patch_without_frr_collapse() -> None:
    plan = _plan()
    counter = 0

    def factory(spec: AgentProgramSpec, context: HackerInstantiationContext) -> _Session:
        nonlocal counter
        counter += 1
        return _Session(spec, context, instance_id=f"h-{counter}")

    artifact = run_hacker_fixer_solver(
        plan,
        hacker_factory=factory,
        fixer_runner=_fixer,
        solver_runner=lambda s, i: _solver(s, i, clean_pass=True, frr_collapse=False),
    )
    assert artifact.solver.frr_collapse_detected is False
    assert artifact.solver.clean_pass is True
    assert artifact.post_attack is not None
    assert artifact.failed_patches == ()


def test_overfitting_fixer_caught_by_fresh_attacker_binding() -> None:
    """Overfit repair: solver looks clean but fresh reattack uses RepairCandidateBinding."""
    plan = _plan()
    profile_v1 = digest_of("verifier-v1")
    profile_v2 = digest_of("verifier-v2")
    binding = RepairCandidateBinding(
        campaign_id="overfit",
        old_verifier_profile_digest=profile_v1,
        new_verifier_profile_digest=profile_v2,
        regression_corpus_digest=digest_of("regression"),
        holdout_corpus_digest=digest_of("holdout-corpus"),
        required_minimum_query_budget=4,
    )
    counter = 0
    seen_anchors: list[str] = []

    def factory(spec: AgentProgramSpec, context: HackerInstantiationContext) -> _Session:
        nonlocal counter
        counter += 1
        seen_anchors.append(context.anchor_digest)
        return _Session(spec, context, instance_id=f"h-{counter}")

    artifact = run_hacker_fixer_solver(
        plan,
        hacker_factory=factory,
        fixer_runner=_fixer,
        solver_runner=lambda s, i: _solver(s, i, clean_pass=True),
        repair_candidate_binding=binding,
    )
    assert artifact.repair_candidate_binding is not None
    assert artifact.post_attack is not None
    assert artifact.post_attack.initialized_after_digest == binding.content_digest
    assert binding.content_digest in seen_anchors


def test_fresh_attack_envelope_required_null_parent() -> None:
    envelope = make_attacker_state_envelope(
        opaque_payload=b"fresh-state",
        strategy_identity_digest=digest_of("strategy"),
        program_identity_digest=digest_of("program"),
        attack_mode="fresh_attack",
        campaign_digest=digest_of("campaign"),
        run_digest=digest_of("run"),
        round_index=0,
        runtime_identity_digest=digest_of("runtime"),
        branch_id="post-repair",
        lineage_index=0,
        parent_state_digest=None,
    )
    assert_fresh_attack_envelope(envelope)
    bad = make_attacker_state_envelope(
        opaque_payload=b"persist",
        strategy_identity_digest=digest_of("strategy"),
        program_identity_digest=digest_of("program"),
        attack_mode="persistent_attack",
        campaign_digest=digest_of("campaign"),
        run_digest=digest_of("run"),
        round_index=1,
        runtime_identity_digest=digest_of("runtime"),
        branch_id="post-repair",
        lineage_index=1,
        parent_state_digest=envelope.content_digest,
    )
    with pytest.raises(ValueError, match="fresh_attack"):
        assert_fresh_attack_envelope(bad)


def test_frr_collapse_preserved_as_failed_patch() -> None:
    plan = _plan()
    counter = 0

    def factory(spec: AgentProgramSpec, context: HackerInstantiationContext) -> _Session:
        nonlocal counter
        counter += 1
        return _Session(spec, context, instance_id=f"h-{counter}")

    artifact = run_hacker_fixer_solver(
        plan,
        hacker_factory=factory,
        fixer_runner=_fixer,
        solver_runner=lambda s, i: _solver(s, i, clean_pass=False, frr_collapse=True),
    )
    assert any("frr_collapse" in r.failure_reasons[0] for r in artifact.failed_patches)
    assert artifact.post_attack is not None  # still runs fresh attack; stopping flags failure
