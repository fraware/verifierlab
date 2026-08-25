"""Attack portfolio registry, strength calibration boundary, and family fixtures (WP-09)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import AccessModel
from verifierlab.attacks.identity import AttackBudgetContract, AttackIdentity, build_attack_identity
from verifierlab.attacks.registry import list_strategies

# Honest depth limitations for the current portfolio (not marketing claims).
PORTFOLIO_DEPTH_LIMITATIONS: tuple[str, ...] = (
    "Random/structured/coverage fuzzing are shallow schema-guided searches; they do not "
    "establish adaptive adversary robustness without security-grade execution and sealed holdout.",
    "Best-of-N and beam search meter candidate evaluations when a broker is bound; brokerless "
    "unit paths do not count as scientific attack evidence.",
    "Evolutionary and tabular RL attackers are local-search baselines with limited state; they "
    "are not substitute for model-capable adaptive attack under declared access models.",
    "metamorphic_search probes invariance under registered transforms only; invalid transforms "
    "never count as verifier failures.",
    "exploit_transfer replays a fixed corpus and is non-adaptive; discovery and held-out corpora "
    "must remain disjoint.",
    "Planted-calibration strength measurements support instrument sensitivity/FPR only and are "
    "hard-coded as not supporting unknown-robustness claims.",
    "Model-capable plugins require explicit provider extras; the in-tree fixture is not a live "
    "model attacker.",
)

ACCESS_MODELS_COMPLETE: tuple[str, ...] = tuple(m.value for m in AccessModel)

FamilyGuardKind = Literal["vulnerable_fixture", "clean_always_reject"]


class AttackFamilyGuard(BaseModel):
    """Per-family capability/guard fixture binding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    family: str = Field(min_length=1)
    kind: FamilyGuardKind
    trajectory: dict[str, Any]
    expected_public_accept: bool | None
    notes: str = Field(min_length=1)

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class StrengthCalibrationBoundary(BaseModel):
    """Hard separation between planted strength calibration and unknown robustness."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    calibration_run_digest: str = Field(min_length=1)
    planted_pack_digest: str = Field(min_length=1)
    supports_unknown_robustness_claim: Literal[False] = False
    claim_boundary: Literal["planted_strength_calibration_not_unknown_robustness"] = (
        "planted_strength_calibration_not_unknown_robustness"
    )
    reasons: tuple[str, ...] = (
        "Strength is measured on known planted packs only.",
        "Unknown-adversary robustness requires separate sealed holdout attack evidence.",
    )

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class AttackPortfolioManifest(BaseModel):
    """Registered attack portfolio for a campaign / study."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    portfolio_id: str = Field(min_length=1)
    identities: tuple[AttackIdentity, ...] = Field(min_length=1)
    access_models: tuple[str, ...] = Field(min_length=1)
    family_guards: tuple[AttackFamilyGuard, ...] = ()
    strength_calibration: StrengthCalibrationBoundary | None = None
    depth_limitations: tuple[str, ...] = PORTFOLIO_DEPTH_LIMITATIONS
    qualification_grade: Literal[False] = False

    @model_validator(mode="after")
    def _validate_portfolio(self) -> AttackPortfolioManifest:
        names = {identity.strategy_name for identity in self.identities}
        known = set(list_strategies())
        # model_fixture is a plugin, not necessarily in strategy registry.
        known = known | {"model_fixture"}
        unknown = names - known
        if unknown:
            raise ValueError(f"portfolio references unknown strategies: {sorted(unknown)}")
        for access in self.access_models:
            if access not in ACCESS_MODELS_COMPLETE:
                raise ValueError(f"unknown access model in portfolio: {access}")
        digests = [identity.content_digest for identity in self.identities]
        if len(digests) != len(set(digests)):
            raise ValueError("portfolio AttackIdentity digests must be unique")
        if (
            self.strength_calibration is not None
            and self.strength_calibration.supports_unknown_robustness_claim is not False
        ):
            raise ValueError("strength calibration cannot support unknown robustness")
        return self

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def default_family_guards() -> tuple[AttackFamilyGuard, ...]:
    """One vulnerable fixture + one clean/always-reject guard per core family."""
    families = (
        "ordinary",
        "random_fuzz",
        "structured_fuzz",
        "coverage_fuzz",
        "evolutionary",
        "best_of_n",
        "beam",
        "rl_tabular",
        "metamorphic_search",
        "exploit_transfer",
    )
    guards: list[AttackFamilyGuard] = []
    for family in families:
        guards.append(
            AttackFamilyGuard(
                family=family,
                kind="vulnerable_fixture",
                trajectory={
                    "steps": [
                        {
                            "op": "refund",
                            "amount": 200,
                            "user_id": "eve",
                            "token": "expired",
                            "pack_theme": "integrity-auth",
                        }
                    ]
                },
                expected_public_accept=True,
                notes=f"{family}: planted unauthorized refund must be detectable as capability probe.",
            )
        )
        guards.append(
            AttackFamilyGuard(
                family=family,
                kind="clean_always_reject",
                trajectory={
                    "steps": [
                        {
                            "op": "refund",
                            "amount": 10,
                            "user_id": "alice",
                            "token": "valid",
                        }
                    ]
                },
                expected_public_accept=False,
                notes=(
                    f"{family}: clean authorized refund is a always-reject guard when the "
                    "fixture verifier is configured to reject all; otherwise documents baseline."
                ),
            )
        )
    return tuple(guards)


def build_default_portfolio(
    *,
    portfolio_id: str,
    seed: int = 0,
    max_queries: int = 32,
    access_models: tuple[str, ...] = ("black-box", "gray-box"),
    include_strength_calibration: bool = False,
    planted_pack_digest: str | None = None,
    calibration_run_digest: str | None = None,
) -> AttackPortfolioManifest:
    """Construct a digest-bound portfolio covering registered attack families."""
    budget = AttackBudgetContract(max_queries=max_queries, max_candidate_evals=max_queries * 4)
    strategies = [
        ("ordinary", "1", "shallow_search"),
        ("random_fuzz", "1", "shallow_search"),
        ("structured_fuzz", "1", "budgeted_search"),
        ("coverage_fuzz", "1", "budgeted_search"),
        ("evolutionary", "1", "budgeted_search"),
        ("best_of_n", "1", "budgeted_search"),
        ("beam", "1", "budgeted_search"),
        ("rl_tabular", "1", "budgeted_search"),
        ("metamorphic_search", "1", "budgeted_search"),
        ("exploit_transfer", "1", "transfer_replay"),
    ]
    identities: list[AttackIdentity] = []
    for name, version, depth in strategies:
        for access in access_models:
            identities.append(
                build_attack_identity(
                    strategy_name=name,
                    strategy_version=version,
                    source_digest=digest_of(f"verifierlab.attacks:{name}"),
                    configuration={"seed": seed, "strategy": name, "access": access},
                    seed=seed,
                    access_model=access,
                    budget=budget,
                    depth=depth,  # type: ignore[arg-type]
                    supports_unknown_robustness_claim=False,
                )
            )
    strength = None
    if include_strength_calibration:
        if not planted_pack_digest or not calibration_run_digest:
            raise ValueError(
                "strength calibration requires planted_pack_digest and calibration_run_digest"
            )
        strength = StrengthCalibrationBoundary(
            calibration_run_digest=calibration_run_digest,
            planted_pack_digest=planted_pack_digest,
        )
    return AttackPortfolioManifest(
        portfolio_id=portfolio_id,
        identities=tuple(identities),
        access_models=access_models,
        family_guards=default_family_guards(),
        strength_calibration=strength,
    )


class CandidateEvalMeter(BaseModel):
    """Per-attacker meter for every candidate evaluation (WP-09)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    attacker_identity_digest: str = Field(min_length=1)
    candidate_evals: int = Field(ge=0)
    verifier_queries: int = Field(ge=0)
    budget_queries: int = Field(gt=0)
    budget_candidate_evals: int | None = None

    @model_validator(mode="after")
    def _within_budget(self) -> CandidateEvalMeter:
        if self.verifier_queries > self.budget_queries:
            raise ValueError("verifier_queries exceed AttackBudgetContract.max_queries")
        if (
            self.budget_candidate_evals is not None
            and self.candidate_evals > self.budget_candidate_evals
        ):
            raise ValueError("candidate_evals exceed AttackBudgetContract.max_candidate_evals")
        return self

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def record_candidate_eval(
    *,
    identity: AttackIdentity,
    candidate_evals: int,
    verifier_queries: int,
) -> CandidateEvalMeter:
    """Build a fail-closed meter snapshot for one attacker identity."""
    return CandidateEvalMeter(
        attacker_identity_digest=identity.content_digest,
        candidate_evals=candidate_evals,
        verifier_queries=verifier_queries,
        budget_queries=identity.budget.max_queries,
        budget_candidate_evals=identity.budget.max_candidate_evals,
    )


__all__ = [
    "ACCESS_MODELS_COMPLETE",
    "PORTFOLIO_DEPTH_LIMITATIONS",
    "AttackFamilyGuard",
    "AttackPortfolioManifest",
    "CandidateEvalMeter",
    "StrengthCalibrationBoundary",
    "build_default_portfolio",
    "default_family_guards",
    "record_candidate_eval",
]
