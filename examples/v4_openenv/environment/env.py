from __future__ import annotations

from typing import Any


def make_env(**_kwargs: Any) -> Any:
    from verifierlab.targets.openenv_adapter import OpenEnvAdapter
    return OpenEnvAdapter(max_steps=4)
