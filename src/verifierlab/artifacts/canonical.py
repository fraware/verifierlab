"""Canonical JSON serialization (JCS-style) and SHA-256 digests."""

from __future__ import annotations

import hashlib
import math
from typing import Any


def _is_finite_number(value: float) -> bool:
    return not (math.isnan(value) or math.isinf(value))


def canonicalize(value: Any) -> Any:
    """Return a JSON-serializable structure with stable key ordering semantics.

    Rules (JCS-inspired subset used by VerifierLab):
    - ``dict`` keys must be strings; nested values are canonicalized recursively
    - ``list`` / ``tuple`` elements are canonicalized in order
    - ``bool`` and ``None`` are preserved
    - Integers are preserved; floats must be finite
    - Other types raise ``TypeError``
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if not _is_finite_number(value):
            raise ValueError(f"non-finite float is not canonicalizable: {value!r}")
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return [canonicalize(item) for item in value]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key in sorted(value.keys(), key=lambda k: str(k)):
            if not isinstance(key, str):
                raise TypeError(f"canonical JSON keys must be str, got {type(key).__name__}")
            out[key] = canonicalize(value[key])
        return out
    raise TypeError(f"unsupported type for canonical JSON: {type(value).__name__}")


def canonical_dumps(value: Any) -> bytes:
    """Serialize ``value`` to UTF-8 canonical JSON bytes (sorted keys, compact)."""
    import json

    canonical = canonicalize(value)
    text = json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )
    return text.encode("utf-8")


def sha256_digest(data: bytes) -> str:
    """Return lowercase hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def digest_of(value: Any) -> str:
    """Return SHA-256 hex digest of the canonical JSON encoding of ``value``."""
    return sha256_digest(canonical_dumps(value))
