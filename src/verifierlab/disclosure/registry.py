"""Disclosure registry states (§25.1), severity, embargo workflow."""

from __future__ import annotations

import json
import time
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import Field

from verifierlab.artifacts.records import ArtifactBase


class DisclosureState(str, Enum):
    DRAFT = "draft"
    TRIAGED = "triaged"
    EMBARGOED = "embargoed"
    SHARED_PRIVATE = "shared_private"
    PUBLIC_SUMMARY = "public_summary"
    PUBLIC_FULL = "public_full"
    DECLINED = "declined"
    EXPIRED = "expired"


_ALLOWED: dict[DisclosureState, set[DisclosureState]] = {
    DisclosureState.DRAFT: {DisclosureState.TRIAGED, DisclosureState.DECLINED},
    DisclosureState.TRIAGED: {
        DisclosureState.EMBARGOED,
        DisclosureState.SHARED_PRIVATE,
        DisclosureState.PUBLIC_SUMMARY,
        DisclosureState.DECLINED,
    },
    DisclosureState.EMBARGOED: {
        DisclosureState.SHARED_PRIVATE,
        DisclosureState.PUBLIC_SUMMARY,
        DisclosureState.EXPIRED,
        DisclosureState.DECLINED,
    },
    DisclosureState.SHARED_PRIVATE: {
        DisclosureState.PUBLIC_SUMMARY,
        DisclosureState.PUBLIC_FULL,
        DisclosureState.EMBARGOED,
    },
    DisclosureState.PUBLIC_SUMMARY: {DisclosureState.PUBLIC_FULL},
    DisclosureState.PUBLIC_FULL: set(),
    DisclosureState.DECLINED: set(),
    DisclosureState.EXPIRED: {DisclosureState.PUBLIC_SUMMARY, DisclosureState.DECLINED},
}


class DisclosureRecord(ArtifactBase):
    disclosure_id: str
    exploit_id: str
    state: DisclosureState = DisclosureState.DRAFT
    severity: str = "medium"
    embargo_until: float | None = None
    private_detail_ref: str | None = None
    public_summary: str | None = None
    history: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DisclosureRegistry:
    """Filesystem registry for disclosure workflow."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, disclosure_id: str) -> Path:
        return self.root / f"{disclosure_id}.json"

    def create(
        self,
        *,
        disclosure_id: str,
        exploit_id: str,
        severity: str = "medium",
        private_detail_ref: str | None = None,
    ) -> DisclosureRecord:
        rec = DisclosureRecord(
            disclosure_id=disclosure_id,
            exploit_id=exploit_id,
            severity=severity,
            private_detail_ref=private_detail_ref,
            history=[{"ts": time.time(), "state": DisclosureState.DRAFT.value}],
        )
        self._save(rec)
        return rec

    def get(self, disclosure_id: str) -> DisclosureRecord:
        return DisclosureRecord.model_validate_json(
            self._path(disclosure_id).read_text(encoding="utf-8")
        )

    def transition(
        self,
        disclosure_id: str,
        new_state: DisclosureState,
        *,
        public_summary: str | None = None,
        embargo_until: float | None = None,
    ) -> DisclosureRecord:
        rec = self.get(disclosure_id)
        allowed = _ALLOWED[rec.state]
        if new_state not in allowed:
            raise ValueError(f"cannot transition {rec.state.value} → {new_state.value}")
        rec.state = new_state
        if public_summary is not None:
            rec.public_summary = public_summary
        if embargo_until is not None:
            rec.embargo_until = embargo_until
        rec.history.append({"ts": time.time(), "state": new_state.value})
        self._save(rec)
        return rec

    def public_view(self, disclosure_id: str) -> dict[str, Any]:
        rec = self.get(disclosure_id)
        if rec.state in {DisclosureState.PUBLIC_SUMMARY, DisclosureState.PUBLIC_FULL}:
            view = {
                "disclosure_id": rec.disclosure_id,
                "state": rec.state.value,
                "severity": rec.severity,
                "public_summary": rec.public_summary,
            }
            if rec.state == DisclosureState.PUBLIC_FULL:
                view["exploit_id"] = rec.exploit_id
            return view
        return {
            "disclosure_id": rec.disclosure_id,
            "state": rec.state.value,
            "severity": rec.severity,
            "public_summary": None,
        }

    def _save(self, rec: DisclosureRecord) -> None:
        self._path(rec.disclosure_id).write_text(
            json.dumps(rec.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
