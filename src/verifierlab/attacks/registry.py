"""Attack strategy registry and discovery."""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from typing import Any, TypeVar

from verifierlab.api.protocols import AttackStrategy

T = TypeVar("T", bound=type)

_REGISTRY: dict[str, type] = {}


def register(name: str) -> Callable[[T], T]:
    """Decorator to register an attack strategy class under ``name``."""

    def decorator(cls: T) -> T:
        _REGISTRY[name] = cls
        return cls

    return decorator


def get_strategy_class(name: str) -> type:
    if name not in _REGISTRY:
        # Import built-ins lazily so registration side-effects run.
        from verifierlab.attacks import (
            coverage,
            evolutionary,
            exploit_transfer,
            fuzzing,
            inference,
            metamorphic_search,
            ordinary,
            rl,
        )

        _ = (
            coverage,
            evolutionary,
            exploit_transfer,
            fuzzing,
            inference,
            metamorphic_search,
            ordinary,
            rl,
        )
    if name not in _REGISTRY:
        known = ", ".join(sorted(_REGISTRY)) or "(none)"
        raise KeyError(f"unknown attack strategy {name!r}; known: {known}")
    return _REGISTRY[name]


def create_strategy(name: str, config: dict[str, Any] | None = None) -> AttackStrategy:
    cls = get_strategy_class(name)
    instance: AttackStrategy = cls()
    instance.initialize(dict(config or {}))
    return instance


def list_strategies() -> list[str]:
    # Force registration.
    with contextlib.suppress(KeyError):
        get_strategy_class("__force_load__")
    return sorted(_REGISTRY)


__all__ = [
    "create_strategy",
    "get_strategy_class",
    "list_strategies",
    "register",
]
