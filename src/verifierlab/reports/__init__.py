"""Report builders with cycle-free package exports."""

from __future__ import annotations

from typing import Any

from verifierlab.reports.metrics import (
    AccessModelPoolError,
    CohortMetrics,
    MetricsIngestError,
    MetricsReport,
    compute_metrics,
    compute_metrics_iter,
)

_LAZY_HTML_EXPORTS = frozenset({"build_report", "iter_work_unit_rows"})


def __getattr__(name: str) -> Any:
    if name in _LAZY_HTML_EXPORTS:
        from verifierlab.reports import html

        return getattr(html, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | _LAZY_HTML_EXPORTS)


__all__ = [
    "AccessModelPoolError",
    "CohortMetrics",
    "MetricsIngestError",
    "MetricsReport",
    "build_report",
    "compute_metrics",
    "compute_metrics_iter",
    "iter_work_unit_rows",
]
