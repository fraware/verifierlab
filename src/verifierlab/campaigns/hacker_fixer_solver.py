"""Machine-checkable hacker/fixer/solver experiment orchestration.

This module enforces ordering, role binding, attack-budget comparability, and
fresh post-repair attacker instantiation. It deliberately does not adjudicate
hidden ground truth and therefore cannot, by itself, establish scientific
qualification. Canonical hidden-label adjudication remains a separate trust
boundary.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import AccessModel

AgentRole = Literal["hacker", "fixer", "solver"]
AttackPhase = Literal["pre_repair", "post_repair"]
ComparisonMode = Literal["equal_budget", "escalating"]


class AgentProgramSpec(BaseModel):
    """Immutable identity for one experimental agent program/model binding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: AgentRole
    implementation_ref: str = Field(min_length=1)
    version: str = Field(min_length=1)
    model_id: str | None = None
    model_version: str | None = None
    configuration_digest: str = Field(min_length=1)
    capability_tags: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _validate_model_binding(self) -> AgentProgramSpec:
        if (self.model_id is None) != (self.model_version is None):
            raise ValueError("model_id and model_version must be supplied together")
        if any(not tag.strip() for tag in self.capability_tags):
            raise ValueError("capability_tags must be non-empty strings")
        return self

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class VerifierCandidateBinding(BaseModel):
    """Content binding for the repaired verifier candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str = Field(min_length=1)
    verifier_profile_digest: str = Field(min_length=1)
    artifact_digest: str = Field(min_length=1)
    parent_verifier_profile_digest: str = Field(min_length=1)
    repair_input_digest: str = Field(min_length=1)

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class HackerFixerSolverPlan(BaseModel):
    """Frozen experimental plan for one attack/repair/solve/reattack round."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    experiment_id: str = Field(min_length=1)
    initial_verifier_profile_digest: str = Field(min_length=1)
    hacker: AgentProgramSpec
    fixer: AgentProgramSpec
    solver: AgentProgramSpec
    post_repair_hacker: AgentProgramSpec | None = None
    access_model: AccessModel
    attack_family: str = Field(min_length=1)
    pre_attack_budget_queries: int = Field(gt=0)
    post_attack_budget_queries: int = Field(gt=0)
    solver_budget_queries: int = Field(gt=0)
    solver_suite_digest: str = Field(min_length=1)
    seed: int = 0
    comparison_mode: ComparisonMode = "equal_budget"
    require_fresh_post_repair_hacker: Literal[True] = True
    freshness_policy: Literal["new_instance_no_checkpoint"] = "new_instance_no_checkpoint"

    @model_validator(mode="after")
    def _validate_roles_and_budgets(self) -> HackerFixerSolverPlan:
        if self.hacker.role != "hacker":
            raise ValueError("hacker program must declare role='hacker'")
        if self.fixer.role != "fixer":
            raise ValueError("fixer program must declare role='fixer'")
        if self.solver.role != "solver":
            raise ValueError("solver program must declare role='solver'")
        if self.post_repair_hacker is not None and self.post_repair_hacker.role != "hacker":
            raise ValueError("post_repair_hacker must declare role='hacker'")
        if self.comparison_mode == "equal_budget":
            if self.pre_attack_budget_queries != self.post_attack_budget_queries:
                raise ValueError("equal_budget comparison requires identical pre/post query budgets")
        elif self.post_attack_budget_queries < self.pre_attack_budget_queries:
            raise ValueError("escalating comparison requires post budget >= pre budget")
        return self

    @property
    def resolved_post_repair_hacker(self) -> AgentProgramSpec:
        return self.post_repair_hacker or self.hacker

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class HackerInstantiationContext(BaseModel):
    """Anchor supplied to a hacker factory at instantiation time."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    phase: AttackPhase
    anchor_digest: str = Field(min_length=1)
    previous_instance_id: str | None = None


class HackerInvocation(BaseModel):
    """Bound request passed to one freshly instantiated hacker session."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    phase: AttackPhase
    verifier_profile_digest: str = Field(min_length=1)
    attacker_spec_digest: str = Field(min_length=1)
    access_model: AccessModel
    attack_family: str = Field(min_length=1)
    budget_queries: int = Field(gt=0)
    seed: int
    anchor_digest: str = Field(min_length=1)

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class AttackExecution(BaseModel):
    """Public attack-plane execution receipt; hidden labels are intentionally absent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    phase: AttackPhase
    attacker_spec_digest: str = Field(min_length=1)
    instance_id: str = Field(min_length=1)
    initialized_after_digest: str = Field(min_length=1)
    initial_state_digest: str = Field(min_length=1)
    parent_checkpoint_digest: str | None = None
    terminal_state_digest: str = Field(min_length=1)
    budget_queries: int = Field(gt=0)
    queries_used: int = Field(ge=0)
    result_digests: tuple[str, ...]

    @model_validator(mode="after")
    def _within_budget(self) -> AttackExecution:
        if self.queries_used > self.budget_queries:
            raise ValueError("attack execution exceeded declared query budget")
        if self.queries_used != len(self.result_digests):
            raise ValueError("queries_used must equal number of result digests")
        if any(not value for value in self.result_digests):
            raise ValueError("result digests must be non-empty")
        return self

    @property
    def results_digest(self) -> str:
        return digest_of(self.result_digests)

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class FixerInvocation(BaseModel):
    """Public evidence given to the fixer after the first attack phase."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    initial_verifier_profile_digest: str = Field(min_length=1)
    pre_attack_execution_digest: str = Field(min_length=1)
    pre_attack_results_digest: str = Field(min_length=1)
    fixer_spec_digest: str = Field(min_length=1)

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class FixerExecution(BaseModel):
    """Receipt for one repair operation and its candidate binding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    fixer_spec_digest: str = Field(min_length=1)
    invocation_digest: str = Field(min_length=1)
    repair_artifact_digest: str = Field(min_length=1)
    candidate: VerifierCandidateBinding

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class SolverInvocation(BaseModel):
    """Bound clean-solve evaluation request for the repaired verifier."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_digest: str = Field(min_length=1)
    verifier_profile_digest: str = Field(min_length=1)
    solver_spec_digest: str = Field(min_length=1)
    suite_digest: str = Field(min_length=1)
    budget_queries: int = Field(gt=0)

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class SolverExecution(BaseModel):
    """Public solver-plane receipt used to detect repair regressions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    solver_spec_digest: str = Field(min_length=1)
    invocation_digest: str = Field(min_length=1)
    candidate_digest: str = Field(min_length=1)
    suite_digest: str = Field(min_length=1)
    budget_queries: int = Field(gt=0)
    queries_used: int = Field(ge=0)
    result_digests: tuple[str, ...]

    @model_validator(mode="after")
    def _within_budget(self) -> SolverExecution:
        if self.queries_used > self.budget_queries:
            raise ValueError("solver execution exceeded declared query budget")
        if self.queries_used != len(self.result_digests):
            raise ValueError("queries_used must equal number of result digests")
        return self

    @property
    def results_digest(self) -> str:
        return digest_of(self.result_digests)

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class HackerSession(Protocol):
    """Runtime attack session. Factories may back this with local or model-based agents."""

    instance_id: str
    initial_state_digest: str
    parent_checkpoint_digest: str | None

    def run(self, invocation: HackerInvocation) -> AttackExecution: ...


HackerFactory = Callable[[AgentProgramSpec, HackerInstantiationContext], HackerSession]
FixerRunner = Callable[[AgentProgramSpec, FixerInvocation], FixerExecution]
SolverRunner = Callable[[AgentProgramSpec, SolverInvocation], SolverExecution]


class HackerFixerSolverArtifact(BaseModel):
    """Immutable round artifact. Qualification is intentionally unavailable here."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    plan: HackerFixerSolverPlan
    pre_attack: AttackExecution
    repair: FixerExecution
    solver: SolverExecution
    post_attack: AttackExecution
    qualification_grade: Literal[False] = False
    claim_boundary: Literal[
        "protocol_ordering_and_public_execution_receipts_only"
    ] = "protocol_ordering_and_public_execution_receipts_only"

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def _validate_attack_execution(
    execution: AttackExecution,
    *,
    invocation: HackerInvocation,
    session: HackerSession,
) -> None:
    if execution.phase != invocation.phase:
        raise ValueError("attack execution phase does not match invocation")
    if execution.attacker_spec_digest != invocation.attacker_spec_digest:
        raise ValueError("attack execution is bound to the wrong attacker spec")
    if execution.instance_id != session.instance_id:
        raise ValueError("attack execution instance_id does not match instantiated session")
    if execution.initial_state_digest != session.initial_state_digest:
        raise ValueError("attack execution initial state does not match instantiated session")
    if execution.parent_checkpoint_digest != session.parent_checkpoint_digest:
        raise ValueError("attack execution checkpoint lineage does not match instantiated session")
    if execution.initialized_after_digest != invocation.anchor_digest:
        raise ValueError("attack execution was not initialized after the required anchor")
    if execution.budget_queries != invocation.budget_queries:
        raise ValueError("attack execution budget differs from the frozen plan")


def run_hacker_fixer_solver(
    plan: HackerFixerSolverPlan,
    *,
    hacker_factory: HackerFactory,
    fixer_runner: FixerRunner,
    solver_runner: SolverRunner,
) -> HackerFixerSolverArtifact:
    """Execute one strictly ordered attack -> repair -> solve -> fresh reattack round.

    The post-repair hacker factory is invoked only after the repair candidate is
    content-bound. Reusing the pre-repair instance or inheriting its checkpoint
    is rejected. Hidden-label adjudication is outside this protocol.
    """
    pre_context = HackerInstantiationContext(
        phase="pre_repair",
        anchor_digest=plan.content_digest,
    )
    pre_session = hacker_factory(plan.hacker, pre_context)
    pre_invocation = HackerInvocation(
        phase="pre_repair",
        verifier_profile_digest=plan.initial_verifier_profile_digest,
        attacker_spec_digest=plan.hacker.content_digest,
        access_model=plan.access_model,
        attack_family=plan.attack_family,
        budget_queries=plan.pre_attack_budget_queries,
        seed=plan.seed,
        anchor_digest=plan.content_digest,
    )
    pre_execution = pre_session.run(pre_invocation)
    _validate_attack_execution(pre_execution, invocation=pre_invocation, session=pre_session)

    fixer_invocation = FixerInvocation(
        initial_verifier_profile_digest=plan.initial_verifier_profile_digest,
        pre_attack_execution_digest=pre_execution.content_digest,
        pre_attack_results_digest=pre_execution.results_digest,
        fixer_spec_digest=plan.fixer.content_digest,
    )
    repair = fixer_runner(plan.fixer, fixer_invocation)
    if repair.fixer_spec_digest != plan.fixer.content_digest:
        raise ValueError("fixer execution is bound to the wrong fixer spec")
    if repair.invocation_digest != fixer_invocation.content_digest:
        raise ValueError("fixer execution is bound to the wrong invocation")
    if repair.candidate.parent_verifier_profile_digest != plan.initial_verifier_profile_digest:
        raise ValueError("repair candidate parent verifier binding is incorrect")
    if repair.candidate.repair_input_digest != fixer_invocation.content_digest:
        raise ValueError("repair candidate is not bound to the fixer input")

    solver_invocation = SolverInvocation(
        candidate_digest=repair.candidate.content_digest,
        verifier_profile_digest=repair.candidate.verifier_profile_digest,
        solver_spec_digest=plan.solver.content_digest,
        suite_digest=plan.solver_suite_digest,
        budget_queries=plan.solver_budget_queries,
    )
    solver = solver_runner(plan.solver, solver_invocation)
    if solver.solver_spec_digest != plan.solver.content_digest:
        raise ValueError("solver execution is bound to the wrong solver spec")
    if solver.invocation_digest != solver_invocation.content_digest:
        raise ValueError("solver execution is bound to the wrong invocation")
    if solver.candidate_digest != repair.candidate.content_digest:
        raise ValueError("solver execution evaluated the wrong repair candidate")
    if solver.suite_digest != plan.solver_suite_digest:
        raise ValueError("solver execution evaluated the wrong clean suite")
    if solver.budget_queries != plan.solver_budget_queries:
        raise ValueError("solver execution budget differs from the frozen plan")

    post_spec = plan.resolved_post_repair_hacker
    post_context = HackerInstantiationContext(
        phase="post_repair",
        anchor_digest=repair.candidate.content_digest,
        previous_instance_id=pre_session.instance_id,
    )
    post_session = hacker_factory(post_spec, post_context)
    if post_session.instance_id == pre_session.instance_id:
        raise ValueError("post-repair hacker must be a fresh runtime instance")
    if post_session.parent_checkpoint_digest is not None:
        raise ValueError("post-repair hacker must not inherit a prior attacker checkpoint")

    post_invocation = HackerInvocation(
        phase="post_repair",
        verifier_profile_digest=repair.candidate.verifier_profile_digest,
        attacker_spec_digest=post_spec.content_digest,
        access_model=plan.access_model,
        attack_family=plan.attack_family,
        budget_queries=plan.post_attack_budget_queries,
        seed=plan.seed + 1,
        anchor_digest=repair.candidate.content_digest,
    )
    post_execution = post_session.run(post_invocation)
    _validate_attack_execution(post_execution, invocation=post_invocation, session=post_session)

    return HackerFixerSolverArtifact(
        plan=plan,
        pre_attack=pre_execution,
        repair=repair,
        solver=solver,
        post_attack=post_execution,
    )


__all__ = [
    "AgentProgramSpec",
    "AttackExecution",
    "FixerExecution",
    "FixerInvocation",
    "HackerFixerSolverArtifact",
    "HackerFixerSolverPlan",
    "HackerInstantiationContext",
    "HackerInvocation",
    "HackerSession",
    "SolverExecution",
    "SolverInvocation",
    "VerifierCandidateBinding",
    "run_hacker_fixer_solver",
]
