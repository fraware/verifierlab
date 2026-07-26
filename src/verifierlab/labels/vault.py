"""Label vault v2: salted HMAC commitments, encrypted labels, role ACL, audit chain."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from typing import Any

from verifierlab.artifacts.canonical import canonical_dumps, digest_of
from verifierlab.labels.keyring import (
    VaultKeyring,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    generate_keyring,
    load_keyring,
)

# Roles allowed to read sealed labels after release.
_LABEL_READ_ROLES = frozenset({"analyst", "adjudicator", "coordinator", "auditor"})
# Roles that may commit / freeze / release.
_ADMIN_ROLES = frozenset({"adjudicator", "coordinator"})
# Roles that may read private_holdout plaintext (never attack plane).
_PRIVATE_HOLDOUT_ROLES = frozenset({"adjudicator", "coordinator", "auditor"})
# Attack-plane roles explicitly denied private holdout.
_ATTACK_ROLES = frozenset({"attacker", "worker", "attack", "strategy"})


class LabelVault:
    """Filesystem-backed vault with cryptographic sealing (VAL-R04 / VALAB-06).

    Commitments are HMAC-SHA256 over ``(trajectory || nonce || label_digest)``
    using the commit key held only on the coordinator/adjudicator. Labels are
    AES-GCM encrypted at rest. Audit events are hash-chained.

    ``private_holdout`` labels live under ``vault/private/`` and are unreachable
    via attack-plane roles even after release.
    """

    def __init__(
        self,
        root: Path,
        *,
        keyring: VaultKeyring | None = None,
        keyring_dir: Path | None = None,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "commitments").mkdir(exist_ok=True)
        (self.root / "labels").mkdir(exist_ok=True)
        (self.root / "private").mkdir(exist_ok=True)
        (self.root / "private" / "labels").mkdir(exist_ok=True)
        (self.root / "records").mkdir(exist_ok=True)
        self._audit_path = self.root / "access_audit.jsonl"
        kr_dir = keyring_dir or (self.root / "keys")
        self.keyring = keyring or load_keyring(kr_dir)
        self._frozen = False
        self._released = False
        self._audit_tip = self._load_audit_tip()
        self._tier_index: dict[str, str] = self._load_tier_index()

    @classmethod
    def open(
        cls,
        root: Path,
        *,
        workspace: Path | None = None,
    ) -> LabelVault:
        """Open a vault; prefer workspace keyring when provided."""
        if workspace is not None:
            from verifierlab.labels.keyring import ensure_workspace_keyring

            return cls(root, keyring=ensure_workspace_keyring(workspace))
        return cls(root)

    @property
    def frozen(self) -> bool:
        return self._frozen or (self.root / "FROZEN").is_file()

    @property
    def released(self) -> bool:
        return self._released or (self.root / "RELEASED").is_file()

    @property
    def audit_tip(self) -> str:
        """Current audit-chain tip digest (never plaintext labels)."""
        return self._audit_tip

    def _load_audit_tip(self) -> str:
        if not self._audit_path.is_file():
            return "0" * 64
        tip = "0" * 64
        for line in self._audit_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            tip = str(row.get("event_digest") or tip)
        return tip

    def _tier_index_path(self) -> Path:
        return self.root / "records" / "label_tiers.json"

    def _load_tier_index(self) -> dict[str, str]:
        path = self._tier_index_path()
        if not path.is_file():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        return {str(k): str(v) for k, v in (data.get("tiers") or {}).items()}

    def _save_tier_index(self) -> None:
        path = self._tier_index_path()
        path.write_text(
            json.dumps({"schema_version": "1", "tiers": self._tier_index}, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )

    def _label_path(self, commitment: str, *, tier: str | None = None) -> Path:
        resolved = tier or self._tier_index.get(commitment)
        if resolved == "private_holdout":
            return self.root / "private" / "labels" / f"{commitment}.json"
        return self.root / "labels" / f"{commitment}.json"

    def _audit(self, event: str, **fields: Any) -> str:
        prev = self._audit_tip
        body = {"ts": time.time(), "event": event, "prev_digest": prev, **fields}
        event_digest = digest_of(body)
        row = {**body, "event_digest": event_digest}
        with self._audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
        self._audit_tip = event_digest
        return event_digest

    def _commitment_mac(
        self,
        *,
        trajectory: dict[str, Any],
        nonce: str,
        label_digest: str,
    ) -> str:
        payload = canonical_dumps(
            {
                "schema_version": "2",
                "trajectory": trajectory,
                "nonce": nonce,
                "label_digest": label_digest,
            }
        )
        return hmac.new(self.keyring.commit_key, payload, hashlib.sha256).hexdigest()

    def commit(
        self,
        trajectory: dict[str, Any],
        label: dict[str, Any],
        *,
        role: str = "adjudicator",
        external_commitment: str | None = None,
        nonce: str | None = None,
        label_tier: str = "development",
    ) -> str:
        """Seal an encrypted label under a salted HMAC commitment.

        ``external_commitment`` may bind to a worker-emitted trajectory
        commitment id (digest of traj+coordinator nonce without label).
        ``label_tier=private_holdout`` quarantines ciphertext under
        ``vault/private/`` (VALAB-06).
        """
        if role in _ATTACK_ROLES:
            self._audit("commit_denied", role=role, reason="attack_plane")
            raise PermissionError(f"role {role!r} cannot commit labels")
        if role not in _ADMIN_ROLES:
            self._audit("commit_denied", role=role, reason="role")
            raise PermissionError(f"role {role!r} cannot commit labels")
        if self.released:
            raise RuntimeError("post-release label injection rejected")
        # After freeze, only the adjudicator may seal labels (VAL-R03/R04).
        if self.frozen and role != "adjudicator":
            raise RuntimeError("post-freeze label injection rejected")
        if self.frozen and role == "adjudicator":
            pass  # allowed sealed write

        from verifierlab.artifacts.records import LabelTier

        try:
            tier = LabelTier(label_tier)
        except ValueError as exc:
            raise ValueError(f"unknown label_tier: {label_tier!r}") from exc

        record_nonce = nonce or secrets.token_hex(16)
        label_digest = digest_of(label)
        commitment = self._commitment_mac(
            trajectory=trajectory,
            nonce=record_nonce,
            label_digest=label_digest,
        )
        plaintext = canonical_dumps(label)
        aad = commitment.encode("utf-8")
        bundle = aes_gcm_encrypt(self.keyring.decrypt_key, plaintext, aad=aad)

        commit_rec = {
            "schema_version": "2",
            "commitment": commitment,
            "nonce": record_nonce,
            "trajectory_digest": digest_of(trajectory),
            "label_digest": label_digest,
            "external_commitment": external_commitment,
            "mac_alg": "HMAC-SHA256",
            "label_tier": tier.value,
        }
        (self.root / "commitments" / f"{commitment}.json").write_text(
            json.dumps(commit_rec, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        label_rec = {
            "schema_version": "2",
            "commitment": commitment,
            "encryption": bundle,
            "external_commitment": external_commitment,
            "label_tier": tier.value,
        }
        label_path = self._label_path(commitment, tier=tier.value)
        label_path.parent.mkdir(parents=True, exist_ok=True)
        label_path.write_text(
            json.dumps(label_rec, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self._tier_index[commitment] = tier.value
        self._save_tier_index()
        self._audit(
            "commit",
            commitment=commitment,
            role=role,
            external_commitment=external_commitment,
            label_tier=tier.value,
        )
        return commitment

    def freeze(self, *, role: str = "coordinator") -> str:
        if role not in _ADMIN_ROLES:
            raise PermissionError(f"role {role!r} cannot freeze vault")
        if self.frozen:
            return self._audit("freeze_idempotent", role=role)
        (self.root / "FROZEN").write_text("1\n", encoding="utf-8")
        self._frozen = True
        record = {
            "schema_version": "2",
            "kind": "freeze",
            "ts": time.time(),
            "role": role,
            "prev_audit": self._audit_tip,
        }
        record_digest = digest_of(record)
        record["record_digest"] = record_digest
        (self.root / "records" / f"freeze-{record_digest[:16]}.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return self._audit("freeze", role=role, record_digest=record_digest)

    def release(self, *, role: str = "coordinator") -> str:
        if role not in _ADMIN_ROLES:
            raise PermissionError(f"role {role!r} cannot release vault")
        if not self.frozen:
            raise RuntimeError("cannot release labels before freeze")
        if self.released:
            return self._audit("release_idempotent", role=role)
        (self.root / "RELEASED").write_text("1\n", encoding="utf-8")
        self._released = True
        record = {
            "schema_version": "2",
            "kind": "release",
            "ts": time.time(),
            "role": role,
            "prev_audit": self._audit_tip,
        }
        record_digest = digest_of(record)
        record["record_digest"] = record_digest
        (self.root / "records" / f"release-{record_digest[:16]}.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return self._audit("release", role=role, record_digest=record_digest)

    def get_label(self, commitment: str, *, role: str = "analyst") -> dict[str, Any]:
        if role in _ATTACK_ROLES:
            self._audit("label_denied", commitment=commitment, role=role, reason="attack_plane")
            raise PermissionError(f"role {role!r} cannot read labels (attack plane)")
        if role not in _LABEL_READ_ROLES:
            self._audit("label_denied", commitment=commitment, role=role, reason="role")
            raise PermissionError(f"role {role!r} cannot read labels")
        if not self.released:
            self._audit("label_denied", commitment=commitment, role=role, reason="not_released")
            raise PermissionError("labels sealed until release after freeze")
        tier = self._tier_index.get(commitment)
        if tier == "private_holdout" and role not in _PRIVATE_HOLDOUT_ROLES:
            self._audit(
                "label_denied",
                commitment=commitment,
                role=role,
                reason="private_holdout",
            )
            raise PermissionError(f"role {role!r} cannot read private_holdout labels (VALAB-06)")
        path = self._label_path(commitment)
        if not path.is_file():
            raise KeyError(commitment)
        sealed = json.loads(path.read_text(encoding="utf-8"))
        if "encryption" in sealed:
            aad = commitment.encode("utf-8")
            plaintext = aes_gcm_decrypt(self.keyring.decrypt_key, sealed["encryption"], aad=aad)
            data: dict[str, Any] = json.loads(plaintext.decode("utf-8"))
        else:
            # Legacy plaintext (should not appear in v2 writes).
            data = {k: v for k, v in sealed.items() if k not in {"encryption", "schema_version"}}
        data["label_tier"] = tier or sealed.get("label_tier") or "development"
        self._audit("label_read", commitment=commitment, role=role, label_tier=data["label_tier"])
        return data

    def find_by_external(self, external_commitment: str) -> str | None:
        """Return vault commitment id bound to a worker trajectory commitment."""
        for path in (self.root / "commitments").glob("*.json"):
            rec = json.loads(path.read_text(encoding="utf-8"))
            if rec.get("external_commitment") == external_commitment:
                return str(rec["commitment"])
        return None

    def worker_payload(self, commitment: str) -> dict[str, Any]:
        """Return worker-safe payload: commitment only, never labels or keys."""
        return {"commitment": commitment, "label": None}

    def audit_log(self) -> list[dict[str, Any]]:
        if not self._audit_path.is_file():
            return []
        return [
            json.loads(line)
            for line in self._audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def verify_audit_chain(self) -> list[str]:
        """Return mismatch messages if the hash chain is broken (empty = ok)."""
        errors: list[str] = []
        prev = "0" * 64
        for i, row in enumerate(self.audit_log()):
            expected_prev = row.get("prev_digest")
            if expected_prev != prev:
                errors.append(f"audit[{i}]: prev_digest mismatch")
            body = {k: v for k, v in row.items() if k != "event_digest"}
            if digest_of(body) != row.get("event_digest"):
                errors.append(f"audit[{i}]: event_digest mismatch")
            prev = str(row.get("event_digest") or prev)
        return errors

    def offline_guess_fails(
        self,
        trajectory: dict[str, Any],
        *,
        commitment: str,
        trials: int = 64,
    ) -> bool:
        """Return True if offline Boolean commitment guessing fails.

        Models an adversary *without* the commit key: unsalted v1 digests and
        HMAC guesses under random keys must not collide with the sealed MAC.
        """
        for valid in (True, False):
            label = {"valid": valid}
            # Unsalted v1-style commitment (traj+label) — must not match.
            v1 = digest_of({"schema_version": "1", "trajectory": trajectory, "label": label})
            if v1 == commitment:
                return False
            # Plain traj+valid bit.
            plain = digest_of({"trajectory": trajectory, "valid": valid})
            if plain == commitment:
                return False
            label_digest = digest_of(label)
            for _ in range(trials):
                wrong_key = secrets.token_bytes(32)
                guess_nonce = secrets.token_hex(16)
                payload = canonical_dumps(
                    {
                        "schema_version": "2",
                        "trajectory": trajectory,
                        "nonce": guess_nonce,
                        "label_digest": label_digest,
                    }
                )
                guess = hmac.new(wrong_key, payload, hashlib.sha256).hexdigest()
                if guess == commitment:
                    return False
        return True


def fresh_ephemeral_vault(root: Path) -> LabelVault:
    """Create a vault with a freshly generated keyring (tests)."""
    kr = generate_keyring(root / "keys")
    return LabelVault(root, keyring=kr)
