"""Multi-dimension budget limits and overrun policy."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class OverrunPolicy(str, Enum):
    STOP = "stop"
    RECORD = "record"


class Budget(BaseModel):
    """Campaign resource limits across dimensions."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1"
    max_queries: int | None = Field(default=None, ge=0)
    max_steps: int | None = Field(default=None, ge=0)
    max_tokens: int | None = Field(default=None, ge=0)
    max_wall_time_s: float | None = Field(default=None, ge=0)
    max_cost_usd: float | None = Field(default=None, ge=0)
    overrun_policy: OverrunPolicy = OverrunPolicy.STOP

    @model_validator(mode="after")
    def _at_least_one_limit(self) -> Budget:
        limits = (
            self.max_queries,
            self.max_steps,
            self.max_tokens,
            self.max_wall_time_s,
            self.max_cost_usd,
        )
        if all(v is None for v in limits):
            raise ValueError("Budget must specify at least one dimension limit")
        return self

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
