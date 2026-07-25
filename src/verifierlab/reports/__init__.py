"""Report builders."""

from __future__ import annotations

from verifierlab.reports.html import build_report, iter_work_unit_rows
from verifierlab.reports.metrics import (
    AccessModelPoolError,
    CohortMetrics,
    MetricsReport,
    compute_metrics,
    compute_metrics_iter,
)

__all__ = [
    "AccessModelPoolError",
    "CohortMetrics",
    "MetricsReport",
    "build_report",
    "compute_metrics",
    "compute_metrics_iter",
    "iter_work_unit_rows",
]
