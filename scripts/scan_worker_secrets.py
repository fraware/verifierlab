#!/usr/bin/env python3
"""Secret / leak scan hooks for the worker image tree (WP-18).

Fail closed if coordinator-only modules or obvious secret material appear
under docker/worker/. Intended for CI and local pre-publish checks.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WORKER = REPO / "docker" / "worker"

FORBIDDEN_NAME_FRAGMENTS = (
    "vault",
    "adjudicat",
    "label_release",
    "gt_valid",
    "ground_truth",
)
SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----"),
    re.compile(r"(?i)api[_-]?key\s*[:=]\s*['\"][^'\"]{8,}"),
    re.compile(r"(?i)secret\s*[:=]\s*['\"][^'\"]{8,}"),
)


def scan(root: Path = WORKER) -> list[str]:
    errors: list[str] = []
    if not root.is_dir():
        return [f"missing worker tree: {root}"]
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        lowered = rel.lower()
        for frag in FORBIDDEN_NAME_FRAGMENTS:
            if frag in lowered:
                errors.append(f"forbidden name fragment {frag!r} in {rel}")
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            errors.append(f"unreadable {rel}: {exc}")
            continue
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                errors.append(f"secret-like pattern in {rel}: {pattern.pattern}")
        for frag in ("verifierlab.labels", "verifierlab.repairs", "gt_valid"):
            if frag in text and path.suffix in {".py", ".sh", ".txt", ".md"}:
                # entrypoint may mention prune targets; allow comments that refuse them.
                if "must not" in text.lower() or "prun" in text.lower() or "forbid" in text.lower():
                    continue
                errors.append(f"coordinator module reference in {rel}: {frag}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=WORKER)
    args = parser.parse_args(argv)
    errors = scan(args.root.resolve())
    if errors:
        print("FAIL: worker secret/leak scan", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print(f"OK: worker tree clean ({args.root})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
