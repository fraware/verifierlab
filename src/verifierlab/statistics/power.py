"""Digest-bound power / sample-size planning (WP-06)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from verifierlab.artifacts.canonical import digest_of
from verifierlab.statistics.intervals import power_binomial, sample_size_for_power


class PowerPlan(BaseModel):
    """Preregistered power analysis bound into study identity by digest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    estimand_id: str = Field(min_length=1)
    sampling_unit: Literal["task", "environment"] = "task"
    p0: float = Field(ge=0.0, le=1.0)
    p1: float = Field(ge=0.0, le=1.0)
    alpha: float = Field(gt=0.0, lt=1.0, default=0.05)
    target_power: float = Field(gt=0.0, lt=1.0, default=0.8)
    planned_n_units: int | None = Field(default=None, ge=1)

    @property
    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


def evaluate_power_plan(plan: PowerPlan, *, observed_n_units: int) -> dict[str, Any]:
    """Evaluate power at the planned sampling-unit count.

    Underpowered primary analyses must surface ``indeterminate`` status for
    maturity blockers — never silent success.
    """
    required = sample_size_for_power(
        p0=plan.p0, p1=plan.p1, power=plan.target_power, alpha=plan.alpha
    )
    required_n = int(required.get("n") or required.get("sample_size") or 0)
    achieved = power_binomial(p0=plan.p0, p1=plan.p1, n=max(1, observed_n_units), alpha=plan.alpha)
    power = float(achieved.get("power") or 0.0)
    underpowered = observed_n_units < required_n or power < plan.target_power
    return {
        "power_plan_digest": plan.content_digest,
        "estimand_id": plan.estimand_id,
        "sampling_unit": plan.sampling_unit,
        "observed_n_units": observed_n_units,
        "required_n_units": required_n,
        "achieved_power": power,
        "target_power": plan.target_power,
        "underpowered": underpowered,
        "status": "indeterminate" if underpowered else "powered",
        "maturity_blocker": "primary_estimand_underpowered" if underpowered else None,
    }


__all__ = ["PowerPlan", "evaluate_power_plan"]
