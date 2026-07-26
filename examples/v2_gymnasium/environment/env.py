from __future__ import annotations

from typing import Any


def make_env(**_kwargs: Any) -> Any:
    from verifierlab.targets.gym_adapter import GymnasiumEnvironment
    return GymnasiumEnvironment.tiny_discrete(max_steps=4)
