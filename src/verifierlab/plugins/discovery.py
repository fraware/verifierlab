"""Plugin entry-point discovery via ``verifierlab.plugins`` group."""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any


def discover_plugins(group: str = "verifierlab.plugins") -> dict[str, Any]:
    """Load entry points registered under ``group``.

    Returns a mapping of plugin name → loaded object. Failures are skipped
    with the name mapped to the exception instance for diagnostics.
    """
    found: dict[str, Any] = {}
    eps = entry_points()
    # Prefer select() (3.10+); fall back to mapping API on older runtimes.
    select = getattr(eps, "select", None)
    if callable(select):
        selected = list(select(group=group))
    else:
        get = getattr(eps, "get", None)
        selected = list(get(group, ())) if callable(get) else []
    for ep in selected:
        try:
            found[ep.name] = ep.load()
        except Exception as exc:
            found[ep.name] = exc
    return found
