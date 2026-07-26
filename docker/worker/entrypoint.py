#!/usr/bin/env python3
"""Worker trust-boundary entrypoint.

Allows campaign run / attack worker surfaces. Refuses GT providers, vault, and
label-release commands.
"""

from __future__ import annotations

import os
import sys


ROLE = "worker"
FORBIDDEN_MODULES = (
    "verifierlab.labels.vault",
    "verifierlab.labels.keyring",
)
FORBIDDEN_ARGV = (
    "adjudicate",
    "release-labels",
)
DATA_DIR = os.environ.get("VALAB_DATA", "/var/lib/verifierlab/worker")


def _enforce() -> None:
    os.environ["VALAB_ROLE"] = ROLE
    if DATA_DIR == os.environ.get("VALAB_ADJUDICATOR_DATA"):
        raise SystemExit("worker must not share adjudicator data path")
    argv = [a.lower() for a in sys.argv[1:]]
    for token in FORBIDDEN_ARGV:
        if token in argv:
            raise SystemExit(f"role={ROLE} forbids CLI token {token!r}")
    for name in FORBIDDEN_MODULES:
        if name in sys.modules:
            raise SystemExit(f"role={ROLE} forbids preloaded module {name}")


def main() -> None:
    _enforce()
    from verifierlab.cli import app

    app(prog_name="valab")


if __name__ == "__main__":
    main()
