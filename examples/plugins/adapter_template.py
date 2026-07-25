"""Plugin template: environment adapter."""

from __future__ import annotations

from typing import Any


class ExampleAdapter:
    """Copy this module and register via ``verifierlab.plugins`` entry point."""

    name = "example_adapter"

    def capture_config(self) -> dict[str, Any]:
        return {"framework": "example", "version": "0.0.1"}

    def reset(self, *, seed: int) -> dict[str, Any]:
        return {"seed": seed}

    def step(self, action: dict[str, Any]) -> dict[str, Any]:
        return {"observation": {}, "reward": 0.0, "resources": {"steps": 1}}

    def finalize(self) -> dict[str, Any]:
        return {"schema_version": "1", "steps": []}

    def map_timeout(self, exc: Exception) -> dict[str, Any]:
        return {"status": "timeout", "error": str(exc)}


def factory() -> ExampleAdapter:
    return ExampleAdapter()
