#!/usr/bin/env python3
"""Adjudicator trust-boundary entrypoint.

Allows freeze / adjudicate / release-labels. Refuses attack strategy execution
commands and shared worker data paths.
"""

from __future__ import annotations

import os
import sys


ROLE = "adjudicator"
FORBIDDEN_MODULES = (
    "verifierlab.attacks.rl",
)
FORBIDDEN_ARGV = (
    # Attack execution is a worker concern; adjudicator is post-freeze only.
    "--threads",
    "--processes",
)
DATA_DIR = os.environ.get("VALAB_DATA", "/var/lib/verifierlab/adjudicator")


def _enforce() -> None:
    os.environ["VALAB_ROLE"] = ROLE
    worker_data = os.environ.get("VALAB_WORKER_DATA", "/var/lib/verifierlab/worker")
    if DATA_DIR == worker_data:
        raise SystemExit("adjudicator must not share worker data path")
    argv = [a.lower() for a in sys.argv[1:]]
    # Disallow starting a fresh attack campaign from this image.
    if len(argv) >= 2 and argv[0] == "campaign" and argv[1] == "run":
        raise SystemExit(f"role={ROLE} forbids campaign run")
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
