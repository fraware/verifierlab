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
import sys
from pathlib import Path
from typing import Any


ROLE = "worker"
_FORBIDDEN_PACKAGE_PATHS = (
    "labels",
    "repairs",
    "disclosure",
    "reports",
    "cli.py",
    "campaigns/engine.py",
    "campaigns/lifecycle.py",
)


def _package_root() -> Path:
    spec = importlib.util.find_spec("verifierlab")
    if spec is None or not spec.submodule_search_locations:
        raise SystemExit("worker cannot locate verifierlab package")
    return Path(next(iter(spec.submodule_search_locations))).resolve()


def _assert_pruned_runtime() -> None:
    root = _package_root()
    leaked = [rel for rel in _FORBIDDEN_PACKAGE_PATHS if (root / rel).exists()]
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

    request = _load_request(sys.argv[1:])
    if request.get("probe_catalogue"):
        from verifierlab.execution.probes import run_malicious_probe_catalogue

        report = run_malicious_probe_catalogue(
            backend_kind="docker_rootless",
            ran_inside_executor=True,
            secret_sentinels={},  # values never enter the worker; key absence is attested
            gt_guess_seed=int(request.get("gt_guess_seed") or 0),
            host_environ=dict(os.environ),
        )
        result = {
            "unit_id": request.get("unit_id"),
            "probe_catalogue": True,
            "isolation_probe_report": report.model_dump(mode="json"),
            "isolation_probe_report_digest": report.content_digest,
        }
    else:
        # Import only after proving the installed worker package has been pruned.
        from verifierlab.campaigns.worker import execute_work_unit

        result = execute_work_unit(request)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
