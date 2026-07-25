"""Secret scanning hooks before report emit."""

from __future__ import annotations

import json
import re
from typing import Any

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("api_key_assignment", re.compile(r"(?i)api[_-]?key\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("vault_secret_marker", re.compile(r"VAULT_SECRET")),
    ("label_pre_freeze_marker", re.compile(r"LABEL_PRE_FREEZE")),
    ("bearer_token", re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*")),
    ("pem_private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]


def _payload_text(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    try:
        return json.dumps(payload, sort_keys=True, default=str)
    except TypeError:
        return str(payload)


def scan_for_secrets(payload: Any) -> list[str]:
    """Return human-readable hit labels for secret-like patterns in ``payload``."""
    text = _payload_text(payload)
    hits: list[str] = []
    for label, pat in _SECRET_PATTERNS:
        if pat.search(text):
            hits.append(label)
    return hits


def assert_no_secrets(payload: Any) -> None:
    hits = scan_for_secrets(payload)
    if hits:
        raise ValueError(f"secret patterns detected before report emit: {hits}")
