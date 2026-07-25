"""Plugin template: campaign launcher."""

from __future__ import annotations

import uuid
from typing import Any


class ExampleLauncher:
    def __init__(self) -> None:
        self._jobs: dict[str, dict[str, Any]] = {}

    def submit(self, work_unit: dict[str, Any]) -> str:
        handle = work_unit.get("unit_id") or str(uuid.uuid4())
        self._jobs[handle] = {"status": "done", "work_unit": work_unit, "result": {"unit_id": handle}}
        return handle

    def status(self, handle: str) -> str:
        return self._jobs[handle]["status"]

    def collect(self, handle: str) -> dict[str, Any]:
        return self._jobs[handle]["result"]

    def cancel(self, handle: str) -> None:
        self._jobs[handle]["status"] = "cancelled"
