"""Protocol tests for strictly ordered hacker/fixer/solver experiments."""

from __future__ import annotations

from typing import Any

import pytest

from verifierlab.artifacts.canonical import digest_of
from verifierlab.campaigns.hacker_fixer_solver import (
    AgentProgramSpec,
    AttackExecution,
    FixerExecution,
    FixerInvocation,
    HackerFixerSolverPlan,
    HackerInstantiationContext,
    HackerInvocation,
    SolverExecution,
    SolverInvocation,
    VerifierCandidateBinding,
    run_hacker_fixer_solver,
)


def _agent(role: str, name: str, *, model: str | None = None) -> AgentProgramSpec:
    kwargs: dict[str, Any] = {}
    if model is not None:
        kwargs.update(model_id=model, model_version="2026-08")
    return AgentProgramSpec(
        role=role,
        implementation_ref=f"tests.agents:{name}",
        version="1",
        configuration_digest=digest_of({"name": name, "temperature": 0}),
        capability_tags=("deterministic-fixture",),
        **kwargs,
    )


def _plan(**overrides: Any) -> HackerFixerSolverPlan:
    body: dict[str, Any] = {
        "experiment_id": "hfs-fixture",
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
    ) -> None:
        self.spec = spec
        self.context = context
        self.instance_id = instance_id
        self.parent_checkpoint_digest = parent_checkpoint_digest
        self.initial_state_digest = digest_of(
            {
                "instance_id": instance_id,
                "phase": context.phase,
                "anchor": context.anchor_digest,
            }
        )

    def run(self, invocation: HackerInvocation) -> AttackExecution:
        result_digests = tuple(
            digest_of(
                {
                    "instance": self.instance_id,
                    "phase": invocation.phase,
                    "query": index,
                }
            )
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


def _solver(spec: AgentProgramSpec, invocation: SolverInvocation) -> SolverExecution:
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
    )


def test_protocol_orders_repair_before_fresh_reattack() -> None:
    plan = _plan()
    events: list[str] = []
    counter = 0

    def factory(spec: AgentProgramSpec, context: HackerInstantiationContext) -> _Session:
        nonlocal counter
        if context.phase == "post_repair":
            assert events == ["pre_factory", "pre_run", "fixer", "solver"]
            assert context.previous_instance_id == "hacker-1"
            events.append("post_factory")
        else:
            events.append("pre_factory")
        counter += 1
        session = _Session(spec, context, instance_id=f"hacker-{counter}")
        original_run = session.run

        def run(invocation: HackerInvocation) -> AttackExecution:
            events.append("pre_run" if invocation.phase == "pre_repair" else "post_run")
            return original_run(invocation)

        session.run = run  # type: ignore[method-assign]
        return session

    def fixer(spec: AgentProgramSpec, invocation: FixerInvocation) -> FixerExecution:
        events.append("fixer")
        return _fixer(spec, invocation)

    def solver(spec: AgentProgramSpec, invocation: SolverInvocation) -> SolverExecution:
        events.append("solver")
        return _solver(spec, invocation)

    artifact = run_hacker_fixer_solver(
        plan,
        hacker_factory=factory,
        fixer_runner=fixer,
        solver_runner=solver,
    )

    assert events == ["pre_factory", "pre_run", "fixer", "solver", "post_factory", "post_run"]
    assert artifact.pre_attack.instance_id != artifact.post_attack.instance_id
    assert artifact.pre_attack.budget_queries == artifact.post_attack.budget_queries == 4
    assert artifact.post_attack.initialized_after_digest == artifact.repair.candidate.content_digest
    assert artifact.post_attack.parent_checkpoint_digest is None
    assert artifact.qualification_grade is False
    assert artifact.claim_boundary == "protocol_ordering_and_public_execution_receipts_only"


def test_protocol_rejects_reused_post_repair_runtime_instance() -> None:
    plan = _plan()

    def factory(spec: AgentProgramSpec, context: HackerInstantiationContext) -> _Session:
        return _Session(spec, context, instance_id="same-instance")

    with pytest.raises(ValueError, match="fresh runtime instance"):
        run_hacker_fixer_solver(
            plan,
            hacker_factory=factory,
            fixer_runner=_fixer,
            solver_runner=_solver,
        )


def test_protocol_rejects_post_repair_checkpoint_inheritance() -> None:
    plan = _plan()
    count = 0

    def factory(spec: AgentProgramSpec, context: HackerInstantiationContext) -> _Session:
        nonlocal count
        count += 1
        return _Session(
            spec,
            context,
            instance_id=f"instance-{count}",
            parent_checkpoint_digest=(digest_of("old-state") if context.phase == "post_repair" else None),
        )

    with pytest.raises(ValueError, match="must not inherit"):
        run_hacker_fixer_solver(
            plan,
            hacker_factory=factory,
            fixer_runner=_fixer,
            solver_runner=_solver,
        )


def test_equal_budget_plan_rejects_asymmetric_attack_budgets() -> None:
    with pytest.raises(ValueError, match="identical pre/post"):
        _plan(post_attack_budget_queries=5)


def test_escalating_plan_allows_stronger_post_hacker_and_higher_budget() -> None:
    stronger = _agent("hacker", "stronger-hacker", model="model-h-plus")
    plan = _plan(
        comparison_mode="escalating",
        post_attack_budget_queries=7,
        post_repair_hacker=stronger,
    )
    counter = 0

    def factory(spec: AgentProgramSpec, context: HackerInstantiationContext) -> _Session:
        nonlocal counter
        counter += 1
        return _Session(spec, context, instance_id=f"instance-{counter}")

    artifact = run_hacker_fixer_solver(
        plan,
        hacker_factory=factory,
        fixer_runner=_fixer,
        solver_runner=_solver,
    )
    assert artifact.pre_attack.attacker_spec_digest == plan.hacker.content_digest
    assert artifact.post_attack.attacker_spec_digest == stronger.content_digest
    assert artifact.pre_attack.budget_queries == 4
    assert artifact.post_attack.budget_queries == 7


def test_escalating_plan_rejects_weaker_post_budget() -> None:
    with pytest.raises(ValueError, match="post budget >= pre"):
        _plan(
            comparison_mode="escalating",
            pre_attack_budget_queries=5,
            post_attack_budget_queries=4,
        )


def test_protocol_rejects_solver_candidate_mismatch() -> None:
    plan = _plan()
    count = 0

    def factory(spec: AgentProgramSpec, context: HackerInstantiationContext) -> _Session:
        nonlocal count
        count += 1
        return _Session(spec, context, instance_id=f"instance-{count}")

    def wrong_solver(spec: AgentProgramSpec, invocation: SolverInvocation) -> SolverExecution:
        receipt = _solver(spec, invocation)
        return receipt.model_copy(update={"candidate_digest": digest_of("wrong-candidate")})

    with pytest.raises(ValueError, match="wrong repair candidate"):
        run_hacker_fixer_solver(
            plan,
            hacker_factory=factory,
            fixer_runner=_fixer,
            solver_runner=wrong_solver,
        )


def test_agent_role_and_model_binding_fail_closed() -> None:
    with pytest.raises(ValueError, match="role='hacker'"):
        _plan(hacker=_agent("solver", "wrong-role"))
    with pytest.raises(ValueError, match="supplied together"):
        AgentProgramSpec(
            role="hacker",
            implementation_ref="tests:h",
            version="1",
            model_id="model-only",
            configuration_digest=digest_of("cfg"),
        )


def test_attack_execution_rejects_budget_overrun_and_count_mismatch() -> None:
    common = {
        "phase": "pre_repair",
        "attacker_spec_digest": digest_of("attacker"),
        "instance_id": "i1",
        "initialized_after_digest": digest_of("anchor"),
        "initial_state_digest": digest_of("initial"),
        "terminal_state_digest": digest_of("terminal"),
        "budget_queries": 1,
        "result_digests": (digest_of("r1"),),
    }
    with pytest.raises(ValueError, match="exceeded"):
        AttackExecution(**common, queries_used=2)
    with pytest.raises(ValueError, match="number of result digests"):
        AttackExecution(**common, queries_used=0)


def test_artifact_digest_is_deterministic() -> None:
    plan = _plan()

    def run_once() -> str:
        count = 0

        def factory(spec: AgentProgramSpec, context: HackerInstantiationContext) -> _Session:
            nonlocal count
            count += 1
            return _Session(spec, context, instance_id=f"instance-{count}")

        artifact = run_hacker_fixer_solver(
            plan,
            hacker_factory=factory,
            fixer_runner=_fixer,
            solver_runner=_solver,
        )
        return artifact.content_digest

    assert run_once() == run_once()
