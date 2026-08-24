"""Immutable verifier profile digests and explicit decision semantics."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from verifierlab.api.decision import Decision, DecisionKind
from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import AccessModel, DecisionSpace, VerifierSpec


class ScoreDecisionMapping(BaseModel):
    """Content-addressed mapping from a numeric score to accept/reject.

    Numeric scores have no universal meaning. A mapping is therefore part of
    the verifier profile and its digest rather than an implicit library rule.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    operator: Literal["ge", "gt", "le", "lt"]
    threshold: float
    scale: str | None = None
    rationale: str | None = None

    def accepts(self, score: float) -> bool:
        if self.operator == "ge":
            return score >= self.threshold
        if self.operator == "gt":
            return score > self.threshold
        if self.operator == "le":
            return score <= self.threshold
        return score < self.threshold

    def apply(self, decision: Decision) -> Decision:
        """Apply only to unresolved score decisions; explicit decisions win."""
        if decision.kind is not DecisionKind.SCORE or decision.accepted is not None:
            return decision
        if decision.score is None:
            return decision
        accepted = self.accepts(float(decision.score))
        return decision.model_copy(
            update={
                "kind": DecisionKind.ACCEPT if accepted else DecisionKind.REJECT,
                "accepted": accepted,
                "components": {
                    **dict(decision.components),
                    "score_decision_mapping": self.model_dump(mode="json"),
                },
            }
        )


def _mapping_from_config(config: dict[str, Any]) -> ScoreDecisionMapping | None:
    payload = config.get("decision_mapping")
    if payload is None:
        return None
    if isinstance(payload, ScoreDecisionMapping):
        return payload
    return ScoreDecisionMapping.model_validate(payload)


def _default_applicability(
    *,
    decision_space: DecisionSpace,
    access_model: AccessModel | str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "decision_space": (
            decision_space.value if isinstance(decision_space, DecisionSpace) else str(decision_space)
        ),
        "target_kinds": ["python", "native"],
        "requires_hidden_labels": False,
    }
    if access_model is not None:
        payload["declared_access_model"] = (
            access_model.value if isinstance(access_model, AccessModel) else str(access_model)
        )
    if extra:
        payload.update(extra)
    return payload


def _default_access_surface(*, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "inputs": ["trajectory", "observation"],
        "may_read_hidden_labels": False,
        "may_import_label_vault": False,
        "may_read_ground_truth": False,
        "stdout_protocol": "json_decision",
    }
    if extra:
        payload.update(extra)
    return payload


class VerifierProfile(BaseModel):
    """Immutable description of a verifier under evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "2"
    name: str
    implementation_digest: str
    config_digest: str
    rubric_digest: str | None = None
    decision_space: DecisionSpace = DecisionSpace.BINARY
    decision_mapping: ScoreDecisionMapping | None = None
    decision_semantics: dict[str, Any] = Field(default_factory=dict)
    applicability: dict[str, Any] = Field(default_factory=dict)
    access_surface: dict[str, Any] = Field(default_factory=dict)
    limitations: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)

    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))

    def normalize_score_decision(self, decision: Decision) -> Decision:
        """Apply the profile mapping, leaving unmapped scores indeterminate."""
        if self.decision_mapping is None:
            return decision
        return self.decision_mapping.apply(decision)

    @classmethod
    def from_spec(
        cls,
        spec: VerifierSpec,
        *,
        config: dict[str, Any] | None = None,
        rubric: dict[str, Any] | None = None,
        applicability: dict[str, Any] | None = None,
        access_surface: dict[str, Any] | None = None,
        decision_mapping: ScoreDecisionMapping | dict[str, Any] | None = None,
    ) -> VerifierProfile:
        cfg = dict(config or {})
        mapping = (
            decision_mapping
            if isinstance(decision_mapping, ScoreDecisionMapping)
            else ScoreDecisionMapping.model_validate(decision_mapping)
            if decision_mapping is not None
            else _mapping_from_config(cfg)
        )
        return cls(
            name=spec.name,
            implementation_digest=spec.callable_digest,
            config_digest=digest_of(cfg),
            rubric_digest=digest_of(rubric) if rubric is not None else None,
            decision_space=spec.decision_space,
            decision_mapping=mapping,
            decision_semantics={
                "status_set": ["accept", "reject", "abstain", "indeterminate", "error"],
                "fail_closed": True,
                "numeric_scores_imply_acceptance": mapping is not None,
                "score_mapping": mapping.model_dump(mode="json") if mapping is not None else None,
            },
            applicability=_default_applicability(
                decision_space=spec.decision_space,
                access_model=spec.access_model,
                extra=applicability,
            ),
            access_surface=_default_access_surface(extra=access_surface),
            limitations=tuple(spec.limitations),
            metadata=dict(spec.metadata),
        )

    @classmethod
    def for_callable(
        cls,
        fn: Any,
        *,
        name: str | None = None,
        config: dict[str, Any] | None = None,
        limitations: list[str] | None = None,
        applicability: dict[str, Any] | None = None,
        access_surface: dict[str, Any] | None = None,
        decision_mapping: ScoreDecisionMapping | dict[str, Any] | None = None,
    ) -> VerifierProfile:
        """Build a profile from a callable (decorated or plain)."""
        from verifierlab.api.verifier import get_verifier_spec

        cfg = dict(config or {})
        try:
            spec = get_verifier_spec(fn)
            return cls.from_spec(
                spec,
                config=cfg,
                applicability=applicability,
                access_surface=access_surface,
                decision_mapping=decision_mapping,
            )
        except AttributeError:
            pass
        module = getattr(fn, "__module__", "<unknown>")
        qualname = getattr(fn, "__qualname__", getattr(fn, "__name__", "verifier"))
        impl = digest_of({"module": module, "qualname": qualname})
        mapping = (
            decision_mapping
            if isinstance(decision_mapping, ScoreDecisionMapping)
            else ScoreDecisionMapping.model_validate(decision_mapping)
            if decision_mapping is not None
            else _mapping_from_config(cfg)
        )
        return cls(
            name=name or qualname,
            implementation_digest=impl,
            config_digest=digest_of(cfg),
            limitations=tuple(limitations or []),
            decision_mapping=mapping,
            decision_semantics={
                "status_set": ["accept", "reject", "abstain", "indeterminate", "error"],
                "fail_closed": True,
                "numeric_scores_imply_acceptance": mapping is not None,
                "score_mapping": mapping.model_dump(mode="json") if mapping is not None else None,
            },
            applicability=_default_applicability(
                decision_space=DecisionSpace.BINARY,
                extra=applicability,
            ),
            access_surface=_default_access_surface(extra=access_surface),
        )


__all__ = ["ScoreDecisionMapping", "VerifierProfile"]
