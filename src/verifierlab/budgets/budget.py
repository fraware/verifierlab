"""Multi-dimension budget limits and overrun policy."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class OverrunPolicy(str, Enum):
    STOP = "stop"
    RECORD = "record"


class Budget(BaseModel):
    """Campaign resource limits across dimensions (VALAB-04).

    ``max_queries`` caps broker verifier invocations (alias documented and
    asserted equivalent at the broker). ``max_candidates`` meters candidate
    generations under BoN/beam. ``max_compute_units`` is an explicit compute
    meter; ``max_cost_usd`` remains the cost / compute-units-where-available
    dimension.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "2"
    max_queries: int | None = Field(default=None, ge=0)
    max_steps: int | None = Field(default=None, ge=0)
    max_tokens: int | None = Field(default=None, ge=0)
    max_wall_time_s: float | None = Field(default=None, ge=0)
    max_cost_usd: float | None = Field(default=None, ge=0)
    max_candidates: int | None = Field(default=None, ge=0)
    max_compute_units: float | None = Field(default=None, ge=0)
    overrun_policy: OverrunPolicy = OverrunPolicy.STOP

    @model_validator(mode="after")
    def _at_least_one_limit(self) -> Budget:
        limits = (
            self.max_queries,
            self.max_steps,
            self.max_tokens,
            self.max_wall_time_s,
            self.max_cost_usd,
            self.max_candidates,
            self.max_compute_units,
        )
        if all(v is None for v in limits):
            raise ValueError("Budget must specify at least one dimension limit")
        return self

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
