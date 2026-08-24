#!/usr/bin/env python3
"""Dedicated attack-worker entrypoint.

The worker accepts exactly one JSON work-unit request from stdin or from one
explicit file path and emits one JSON result to stdout. It does not expose the
general command surface.

Image construction is expected to physically remove coordinator-only package
surfaces. Startup refuses to run if any of them are present.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
from typing import Any


ROLE = "worker"
_FORBIDDEN_PACKAGE_DIRS = (
    "labels",
    "repairs",
    "disclosure",
    "reports",
    "cli",
)


def _package_root() -> Path:
    spec = importlib.util.find_spec("verifierlab")
    if spec is None or not spec.submodule_search_locations:
        raise SystemExit("worker cannot locate verifierlab package")
    return Path(next(iter(spec.submodule_search_locations))).resolve()


def _assert_pruned_runtime() -> None:
    root = _package_root()
    leaked = [name for name in _FORBIDDEN_PACKAGE_DIRS if (root / name).exists()]
    if leaked:
        raise SystemExit(
            "worker image contains coordinator-only package surfaces: " + ", ".join(leaked)
        )


def _load_request(argv: list[str]) -> dict[str, Any]:
    if len(argv) > 1:
        raise SystemExit("worker accepts at most one JSON request file")
    if argv:
        raw = Path(argv[0]).read_text(encoding="utf-8")
    else:
        raw = sys.stdin.read()
    if not raw.strip():
        raise SystemExit("worker requires one JSON request")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise SystemExit("worker request must be a JSON object")
    return payload


def main() -> None:
    os.environ["VALAB_ROLE"] = ROLE
    _assert_pruned_runtime()

    # Import only after proving the installed worker package has been pruned.
    from verifierlab.campaigns.worker import execute_work_unit

    request = _load_request(sys.argv[1:])
    result = execute_work_unit(request)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
