#!/usr/bin/env python3
"""CLI trust-boundary entrypoint.

Allows validate / orchestrate / report surfaces. Refuses vault key bootstrap
and adjudicator-only secrets via role import bans.
"""

from __future__ import annotations

import os
import sys


ROLE = "cli"
FORBIDDEN_MODULES = (
    "verifierlab.labels.keyring",
)
DATA_DIR = os.environ.get("VALAB_DATA", "/var/lib/verifierlab/cli")


def _enforce() -> None:
    os.environ["VALAB_ROLE"] = ROLE
    if not DATA_DIR:
        raise SystemExit("VALAB_DATA must be set for CLI role")
    for name in FORBIDDEN_MODULES:
        # Soft ban: do not import keyring at process start; runtime still can
        # if operator explicitly imports — structure tests + docs enforce intent.
        if name in sys.modules:
            raise SystemExit(f"role={ROLE} forbids preloaded module {name}")


def main() -> None:
    _enforce()
    from verifierlab.cli import app

    app(prog_name="valab")


if __name__ == "__main__":
    main()
