"""File-backed vault keyring with separated key roles."""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KeyRole = Literal["commit", "decrypt", "sign"]

_ROLE_FILES: dict[KeyRole, str] = {
    "commit": "commit.key",
    "decrypt": "decrypt.key",
    "sign": "sign.key",
}


@dataclass(frozen=True)
class VaultKeyring:
    """Separated commit / decrypt / sign keys for the label vault."""

    root: Path
    commit_key: bytes
    decrypt_key: bytes
    sign_key: bytes

    def key_for(self, role: KeyRole) -> bytes:
        if role == "commit":
            return self.commit_key
        if role == "decrypt":
            return self.decrypt_key
        if role == "sign":
            return self.sign_key
        raise ValueError(f"unknown key role: {role}")


def _restrict_mode(path: Path) -> None:
    with contextlib.suppress(OSError):
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def generate_keyring(root: Path) -> VaultKeyring:
    """Create a new keyring directory with 32-byte keys per role."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    keys: dict[KeyRole, bytes] = {}
    for role, filename in _ROLE_FILES.items():
        key = secrets.token_bytes(32)
        path = root / filename
        path.write_bytes(key)
        _restrict_mode(path)
        keys[role] = key
    meta = root / "keyring.json"
    meta.write_text(
        json.dumps({"schema_version": "1", "roles": list(_ROLE_FILES)}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    _restrict_mode(meta)
    return VaultKeyring(
        root=root,
        commit_key=keys["commit"],
        decrypt_key=keys["decrypt"],
        sign_key=keys["sign"],
    )


def load_keyring(root: Path) -> VaultKeyring:
    """Load an existing keyring; honor ``VALAB_VAULT_KEYRING`` override."""
    override = os.environ.get("VALAB_VAULT_KEYRING")
    root = Path(override) if override else Path(root)
    if not root.is_dir():
        return generate_keyring(root)
    missing = [f for f in _ROLE_FILES.values() if not (root / f).is_file()]
    if missing:
        return generate_keyring(root)
    return VaultKeyring(
        root=root,
        commit_key=(root / _ROLE_FILES["commit"]).read_bytes(),
        decrypt_key=(root / _ROLE_FILES["decrypt"]).read_bytes(),
        sign_key=(root / _ROLE_FILES["sign"]).read_bytes(),
    )


def ensure_workspace_keyring(workspace: Path) -> VaultKeyring:
    """Return the workspace-scoped vault keyring (create if absent)."""
    return load_keyring(Path(workspace) / "keys" / "vault")


def aes_gcm_encrypt(key: bytes, plaintext: bytes, *, aad: bytes = b"") -> dict[str, str]:
    """Encrypt with AES-GCM; return hex-encoded nonce/ciphertext/tag bundle."""
    if len(key) != 32:
        raise ValueError("AES-GCM key must be 32 bytes")
    nonce = secrets.token_bytes(12)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, aad)
    # cryptography appends 16-byte tag to ciphertext
    return {
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
        "alg": "AES-256-GCM",
    }


def aes_gcm_decrypt(key: bytes, bundle: dict[str, str], *, aad: bytes = b"") -> bytes:
    nonce = bytes.fromhex(bundle["nonce"])
    ct = bytes.fromhex(bundle["ciphertext"])
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, aad)
