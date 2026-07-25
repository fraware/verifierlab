"""Filesystem content-addressed store (CAS)."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from verifierlab.artifacts.canonical import canonical_dumps, digest_of, sha256_digest

SCHEMA_VERSION = "1"


class ContentAddressedStore:
    """Put/get/has for opaque bytes and canonical JSON objects.

    Layout::

        <root>/sha256/<aa>/<digest>
        <root>/sha256/<aa>/<digest>.meta.json
    """

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root).resolve()
        self._objects = self.root / "sha256"
        self._objects.mkdir(parents=True, exist_ok=True)

    def _object_path(self, digest: str) -> Path:
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError(f"invalid sha256 digest: {digest!r}")
        return self._objects / digest[:2] / digest

    def has(self, digest: str) -> bool:
        return self._object_path(digest).is_file()

    def put_bytes(self, data: bytes, *, media_type: str = "application/octet-stream") -> str:
        digest = sha256_digest(data)
        path = self._object_path(digest)
        if path.is_file():
            return digest
        path.parent.mkdir(parents=True, exist_ok=True)
        meta = {
            "schema_version": SCHEMA_VERSION,
            "digest": digest,
            "algorithm": "sha256",
            "size": len(data),
            "media_type": media_type,
        }
        fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, path)
            meta_path = path.with_suffix(path.suffix + ".meta.json")
            # path.suffix is empty for digest filenames; write beside object.
            meta_path = Path(str(path) + ".meta.json")
            meta_path.write_text(
                json.dumps(meta, separators=(",", ":"), sort_keys=True) + "\n",
                encoding="utf-8",
            )
        except Exception:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise
        return digest

    def put_json(self, value: Any) -> str:
        """Store canonical JSON; digest is over the canonical bytes."""
        data = canonical_dumps(value)
        return self.put_bytes(data, media_type="application/json")

    def get_bytes(self, digest: str) -> bytes:
        path = self._object_path(digest)
        if not path.is_file():
            raise KeyError(f"object not found: {digest}")
        data = path.read_bytes()
        actual = sha256_digest(data)
        if actual != digest:
            raise RuntimeError(f"CAS integrity failure: expected {digest}, got {actual}")
        return data

    def get_json(self, digest: str) -> Any:
        raw = self.get_bytes(digest)
        return json.loads(raw.decode("utf-8"))

    def put_model(self, model: Any) -> str:
        """Store a Pydantic model (or object with ``model_dump``) as canonical JSON."""
        if hasattr(model, "model_dump"):
            payload = model.model_dump(mode="json")
        elif isinstance(model, dict):
            payload = model
        else:
            raise TypeError(f"cannot store type {type(model).__name__}")
        # Ensure schema_version present when dumping dicts that expect it.
        return self.put_json(payload)

    def digest_of_json(self, value: Any) -> str:
        return digest_of(value)
