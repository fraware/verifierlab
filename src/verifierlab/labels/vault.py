"""Local label vault: commit, access audit, no labels in worker payloads."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from verifierlab.artifacts.canonical import digest_of


class LabelVault:
    """Filesystem-backed vault separating commitments from sealed labels."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "commitments").mkdir(exist_ok=True)
        (self.root / "labels").mkdir(exist_ok=True)
        self._audit_path = self.root / "access_audit.jsonl"
        self._frozen = False
        self._released = False

    @property
    def frozen(self) -> bool:
        return self._frozen or (self.root / "FROZEN").is_file()

    @property
    def released(self) -> bool:
        return self._released or (self.root / "RELEASED").is_file()

    def _audit(self, event: str, **fields: Any) -> None:
        row = {"ts": time.time(), "event": event, **fields}
        with self._audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    def commit(self, trajectory: dict[str, Any], label: dict[str, Any]) -> str:
        if self.frozen:
            raise RuntimeError("post-freeze label injection rejected")
        commitment = digest_of({"schema_version": "1", "trajectory": trajectory, "label": label})
        (self.root / "commitments" / f"{commitment}.json").write_text(
            json.dumps({"commitment": commitment, "trajectory_digest": digest_of(trajectory)}, indent=2)
            + "\n",
            encoding="utf-8",
        )
        # Labels stored sealed; workers must never receive this path.
        (self.root / "labels" / f"{commitment}.json").write_text(
            json.dumps(label, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self._audit("commit", commitment=commitment)
        return commitment

    def freeze(self) -> None:
        (self.root / "FROZEN").write_text("1\n", encoding="utf-8")
        self._frozen = True
        self._audit("freeze")

    def release(self) -> None:
        if not self.frozen:
            raise RuntimeError("cannot release labels before freeze")
        (self.root / "RELEASED").write_text("1\n", encoding="utf-8")
        self._released = True
        self._audit("release")

    def get_label(self, commitment: str, *, role: str = "analyst") -> dict[str, Any]:
        if not self.released:
            self._audit("label_denied", commitment=commitment, role=role, reason="not_released")
            raise PermissionError("labels sealed until release after freeze")
        path = self.root / "labels" / f"{commitment}.json"
        if not path.is_file():
            raise KeyError(commitment)
        self._audit("label_read", commitment=commitment, role=role)
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return data

    def worker_payload(self, commitment: str) -> dict[str, Any]:
        """Return worker-safe payload: commitment only, never labels."""
        return {"commitment": commitment, "label": None}

    def audit_log(self) -> list[dict[str, Any]]:
        if not self._audit_path.is_file():
            return []
        return [
            json.loads(line)
            for line in self._audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
