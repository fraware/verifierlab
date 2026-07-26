#!/usr/bin/env python3
"""Assert a VerifierLab wheel contains required data assets."""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

REQUIRED_SUBSTRINGS = (
    "campaigns/",
    "verifierlab/",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path, help="Path to verifierlab-*.whl")
    args = parser.parse_args(argv)
    wheel = args.wheel
    if not wheel.is_file():
        print(f"wheel not found: {wheel}", file=sys.stderr)
        return 2

    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()

    errors: list[str] = []
    if not any(n.startswith("verifierlab/") for n in names):
        errors.append("missing verifierlab/ package prefix")
    if not any(
        ("campaigns" in n or "_data/campaigns" in n) and n.endswith((".yaml", ".yml"))
        for n in names
    ):
        errors.append("missing campaign YAML assets inside wheel")
    # Templates / report helpers live in package modules; ensure reports package ships.
    if not any(n.startswith("verifierlab/reports/") for n in names):
        errors.append("missing verifierlab/reports/ in wheel")

    # Soft check for docs templates when force-included.
    has_templates = any("templates" in n and n.endswith(".md") for n in names)
    if not has_templates:
        print("WARN: docs templates not found in wheel (optional until force-include)")

    if errors:
        print("ERROR: wheel contents check failed:")
        for err in errors:
            print(f"  - {err}")
        print(f"entries sampled: {len(names)}")
        return 1

    print("OK: wheel contains campaigns + reports assets")
    _ = REQUIRED_SUBSTRINGS
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
