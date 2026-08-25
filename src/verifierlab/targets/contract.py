"""Shared adapter contract version (WP-16).

All adapters that participate in the publishable matrix must exercise the
same decision-normalization, timeout/error taxonomy, hidden-label isolation,
and version-reporting surfaces. Fixture-only evidence never upgrades a
status to live-tested.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from verifierlab.artifacts.canonical import digest_of

AdapterMatrixStatus = Literal[
    "live-tested",
    "protocol-reference-tested",
    "fixture-only",
    "unsupported",
]

ALLOWED_MATRIX_STATUSES: frozenset[str] = frozenset(
    {
        "live-tested",
        "protocol-reference-tested",
        "fixture-only",
        "unsupported",
    }
)

# Surfaces every conforming adapter must report against.
CONTRACT_SURFACES: tuple[str, ...] = (
    "decision_normalization",
    "timeout_error_taxonomy",
    "hidden_label_isolation",
    "version_reporting",
)


class AdapterContractVersion(BaseModel):
    """Immutable shared adapter contract identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    contract_id: str = "verifierlab.adapter.contract"
    major: int = 1
    minor: int = 0
    surfaces: tuple[str, ...] = CONTRACT_SURFACES
    notes: str = (
        "Shared by native and optional adapters. "
        "Fixture evidence cannot be labeled live-tested."
    )

    def content_digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))

    def as_report(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "version": f"{self.major}.{self.minor}",
            "schema_version": self.schema_version,
            "surfaces": list(self.surfaces),
            "digest": self.content_digest(),
        }


# Singleton current contract - bump minor when additive; major when breaking.
ADAPTER_CONTRACT_V1 = AdapterContractVersion()


class AdapterMatrixHonestyError(ValueError):
    """Raised when matrix rows violate live-vs-fixture honesty rules."""


def assert_matrix_row_honesty(row: dict[str, Any]) -> None:
    """Fail closed if a fixture/unsupported row is labeled live."""
    status = str(row.get("status") or "")
    if status not in ALLOWED_MATRIX_STATUSES:
        raise AdapterMatrixHonestyError(
            f"adapter {row.get('adapter')!r}: status {status!r} not in "
            f"{sorted(ALLOWED_MATRIX_STATUSES)}"
        )
    live_vs = str(row.get("live_vs_fixture") or "").lower()
    if status in {"fixture-only", "unsupported"} and (
        "live-tested" in live_vs or live_vs == "live"
    ):
        raise AdapterMatrixHonestyError(
            f"adapter {row.get('adapter')!r}: status={status} cannot claim live evidence"
        )
    # EnvAssure must remain non-live until installable.
    if row.get("adapter") == "envassure":
        if status == "live-tested":
            raise AdapterMatrixHonestyError(
                "envassure cannot be live-tested until the package is installable"
            )
        if row.get("installable") is True and status == "fixture-only":
            # Allow upgrade path once marked installable; still require live tests.
            pass
        elif row.get("installable") is not True and status not in {
            "fixture-only",
            "unsupported",
        }:
            raise AdapterMatrixHonestyError(
                "envassure must be fixture-only or unsupported while not installable"
            )


def validate_matrix_document(matrix: dict[str, Any]) -> list[str]:
    """Return honesty/schema errors for a matrix document (empty = ok)."""
    errors: list[str] = []
    adapters = matrix.get("adapters")
    if not isinstance(adapters, list) or not adapters:
        return ["matrix must contain a non-empty adapters list"]
    contract = matrix.get("adapter_contract") or {}
    if str(contract.get("version") or "") != f"{ADAPTER_CONTRACT_V1.major}.{ADAPTER_CONTRACT_V1.minor}":
        errors.append(
            f"adapter_contract.version must be "
            f"{ADAPTER_CONTRACT_V1.major}.{ADAPTER_CONTRACT_V1.minor}"
        )
    seen_live = False
    seen_non_live = False
    for row in adapters:
        if not isinstance(row, dict):
            errors.append("adapter row must be an object")
            continue
        try:
            assert_matrix_row_honesty(row)
        except AdapterMatrixHonestyError as exc:
            errors.append(str(exc))
        status = str(row.get("status") or "")
        if status == "live-tested":
            seen_live = True
        if status in {"fixture-only", "unsupported", "protocol-reference-tested"}:
            seen_non_live = True
    if not seen_live:
        errors.append("matrix must include at least one live-tested adapter")
    if not seen_non_live:
        errors.append("matrix must document at least one non-live path")
    return errors


__all__ = [
    "ADAPTER_CONTRACT_V1",
    "ALLOWED_MATRIX_STATUSES",
    "CONTRACT_SURFACES",
    "AdapterContractVersion",
    "AdapterMatrixHonestyError",
    "AdapterMatrixStatus",
    "assert_matrix_row_honesty",
    "validate_matrix_document",
]
