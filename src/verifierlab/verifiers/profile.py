"""Immutable verifier profile digests and decision semantics."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import AccessModel, DecisionSpace, VerifierSpec


def _default_applicability(
    *,
    decision_space: DecisionSpace,
    access_model: AccessModel | str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Public applicability contract: where this verifier may be mounted."""
    payload: dict[str, Any] = {
        "decision_space": (
            decision_space.value
            if isinstance(decision_space, DecisionSpace)
            else str(decision_space)
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
    """Public access-surface contract: what the verifier invocation may touch."""
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
    """Immutable description of a verifier under evaluation.

    Profiles are content-addressed: mutating any field yields a new digest.
    Public contract fields: digests, applicability, and access_surface.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1"
    name: str
    implementation_digest: str
    config_digest: str
    rubric_digest: str | None = None
    decision_space: DecisionSpace = DecisionSpace.BINARY
    decision_semantics: dict[str, Any] = Field(default_factory=dict)
    applicability: dict[str, Any] = Field(default_factory=dict)
    access_surface: dict[str, Any] = Field(default_factory=dict)
    limitations: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)

    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))

    @classmethod
    def from_spec(
        cls,
        spec: VerifierSpec,
        *,
        config: dict[str, Any] | None = None,
        rubric: dict[str, Any] | None = None,
        applicability: dict[str, Any] | None = None,
        access_surface: dict[str, Any] | None = None,
    ) -> VerifierProfile:
        cfg = dict(config or {})
        return cls(
            name=spec.name,
            implementation_digest=spec.callable_digest,
            config_digest=digest_of(cfg),
            rubric_digest=digest_of(rubric) if rubric is not None else None,
            decision_space=spec.decision_space,
            decision_semantics={
                "status_set": ["accept", "reject", "abstain", "indeterminate", "error"],
                "fail_closed": True,
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
    ) -> VerifierProfile:
        """Build a profile from a callable (decorated or plain)."""
        from verifierlab.api.verifier import get_verifier_spec

        try:
            spec = get_verifier_spec(fn)
            return cls.from_spec(
                spec,
                config=config,
                applicability=applicability,
                access_surface=access_surface,
            )
        except AttributeError:
            pass
        module = getattr(fn, "__module__", "<unknown>")
        qualname = getattr(fn, "__qualname__", getattr(fn, "__name__", "verifier"))
        impl = digest_of({"module": module, "qualname": qualname})
        return cls(
            name=name or qualname,
            implementation_digest=impl,
            config_digest=digest_of(dict(config or {})),
            limitations=tuple(limitations or []),
            decision_semantics={
                "status_set": ["accept", "reject", "abstain", "indeterminate", "error"],
                "fail_closed": True,
            },
            applicability=_default_applicability(
                decision_space=DecisionSpace.BINARY,
                extra=applicability,
            ),
            access_surface=_default_access_surface(extra=access_surface),
        )
