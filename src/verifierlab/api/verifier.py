"""``@verifier`` decorator producing :class:`VerifierSpec`."""

from __future__ import annotations

import inspect
import textwrap
from collections.abc import Callable
from functools import wraps
from typing import Any, ParamSpec, TypeVar, overload

from verifierlab.api.decision import Decision
from verifierlab.artifacts.canonical import digest_of, sha256_digest
from verifierlab.artifacts.records import (
    AbstentionBehavior,
    AccessModel,
    DecisionSpace,
    SideEffects,
    SourceLocation,
    VerifierSpec,
)

P = ParamSpec("P")
R = TypeVar("R")

_REGISTRY: dict[str, VerifierSpec] = {}


def _callable_source_digest(fn: Callable[..., Any]) -> tuple[SourceLocation, str]:
    try:
        source = textwrap.dedent(inspect.getsource(fn))
    except (OSError, TypeError):
        source = f"{fn.__module__}:{fn.__qualname__}"
    source_digest = sha256_digest(source.encode("utf-8"))
    try:
        lineno = inspect.getsourcelines(fn)[1]
    except (OSError, TypeError):
        lineno = None
    try:
        filename = inspect.getsourcefile(fn) or inspect.getfile(fn)
    except TypeError:
        filename = "<unknown>"
    location = SourceLocation(
        module=fn.__module__,
        qualname=fn.__qualname__,
        filename=filename,
        lineno=lineno,
        source_digest=source_digest,
    )
    # Digest identity of the callable: module, qualname, and source body.
    callable_digest = digest_of(
        {
            "module": fn.__module__,
            "qualname": fn.__qualname__,
            "source_digest": source_digest,
        }
    )
    return location, callable_digest


@overload
def verifier(fn: Callable[P, R]) -> Callable[P, R]: ...


@overload
def verifier(
    *,
    name: str | None = None,
    decision_space: DecisionSpace | str = DecisionSpace.BINARY,
    input_schema: dict[str, Any] | None = None,
    output_schema: dict[str, Any] | None = None,
    stochastic: bool = False,
    allowed_exceptions: list[str] | None = None,
    score_range: tuple[float, float] | list[float] | None = None,
    abstention: AbstentionBehavior | str = AbstentionBehavior.UNSUPPORTED,
    timeout_s: float | None = None,
    side_effects: SideEffects | str = SideEffects.NONE,
    external_resources: list[str] | None = None,
    version: str = "0.0.0",
    access_model: AccessModel | str = AccessModel.BLACK_BOX,
    limitations: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]: ...


def verifier(
    fn: Callable[P, R] | None = None,
    *,
    name: str | None = None,
    decision_space: DecisionSpace | str = DecisionSpace.BINARY,
    input_schema: dict[str, Any] | None = None,
    output_schema: dict[str, Any] | None = None,
    stochastic: bool = False,
    allowed_exceptions: list[str] | None = None,
    score_range: tuple[float, float] | list[float] | None = None,
    abstention: AbstentionBehavior | str = AbstentionBehavior.UNSUPPORTED,
    timeout_s: float | None = None,
    side_effects: SideEffects | str = SideEffects.NONE,
    external_resources: list[str] | None = None,
    version: str = "0.0.0",
    access_model: AccessModel | str = AccessModel.BLACK_BOX,
    limitations: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> Callable[P, R] | Callable[[Callable[P, R]], Callable[P, R]]:
    """Mark a plain-Python callable as a VerifierLab verifier.

    Attaches a :class:`VerifierSpec` on ``__verifier_spec__`` and registers it
    under ``module:qualname``. New verifiers must declare ``input_schema`` and
    ``output_schema`` (or set ``metadata["legacy_contract"]=True`` during the
    one-release migration window).
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        location, callable_digest = _callable_source_digest(func)
        space = (
            decision_space
            if isinstance(decision_space, DecisionSpace)
            else DecisionSpace(decision_space)
        )
        abst = (
            abstention
            if isinstance(abstention, AbstentionBehavior)
            else AbstentionBehavior(abstention)
        )
        sides = side_effects if isinstance(side_effects, SideEffects) else SideEffects(side_effects)
        access = (
            access_model if isinstance(access_model, AccessModel) else AccessModel(access_model)
        )
        range_tuple: tuple[float, float] | None = None
        if score_range is not None:
            range_tuple = (float(score_range[0]), float(score_range[1]))
        spec = VerifierSpec(
            name=name or func.__qualname__,
            source=location,
            callable_digest=callable_digest,
            decision_space=space,
            input_schema=input_schema,
            output_schema=output_schema,
            stochastic=stochastic,
            allowed_exceptions=list(allowed_exceptions or []),
            score_range=range_tuple,
            abstention=abst,
            timeout_s=timeout_s,
            side_effects=sides,
            external_resources=list(external_resources or []),
            version=version,
            access_model=access,
            limitations=list(limitations or []),
            metadata=dict(metadata or {}),
        )
        key = f"{func.__module__}:{func.__qualname__}"
        _REGISTRY[key] = spec

        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            return func(*args, **kwargs)

        wrapper.__verifier_spec__ = spec  # type: ignore[attr-defined]
        return wrapper

    if fn is not None:
        return decorator(fn)
    return decorator


def get_verifier_spec(fn: Callable[..., Any]) -> VerifierSpec:
    """Return the :class:`VerifierSpec` attached to ``fn``."""
    spec = getattr(fn, "__verifier_spec__", None)
    if not isinstance(spec, VerifierSpec):
        raise AttributeError(f"{fn!r} is not a @verifier-decorated callable")
    return spec


def normalize_decision(value: Any) -> Decision:
    return Decision.from_raw(value)


def list_registered_verifiers() -> dict[str, VerifierSpec]:
    return dict(_REGISTRY)
