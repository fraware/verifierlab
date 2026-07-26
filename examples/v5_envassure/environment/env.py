from __future__ import annotations

from typing import Any


def make_env(**_kwargs: Any) -> Any:
    from verifierlab.targets.envassure_adapter import EnvAssureAdapter
    return EnvAssureAdapter(fixture=True, max_steps=4)
