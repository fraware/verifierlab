"""Launcher protocol helpers."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class WorkUnitExecutor(Protocol):
    def execute(self, work_unit: dict[str, Any]) -> dict[str, Any]: ...
