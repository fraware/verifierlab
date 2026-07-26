"""External trainer adapters (RLlib and protocol helpers)."""

from __future__ import annotations

from verifierlab.trainers.rllib_adapter import (
    RLlibPPOAdapter,
    ray_rllib_available,
    require_ray_rllib,
)

__all__ = [
    "RLlibPPOAdapter",
    "ray_rllib_available",
    "require_ray_rllib",
]
