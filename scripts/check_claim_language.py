#!/usr/bin/env python3
"""Fail closed on banned overclaims in public docs (WP-20).

Scans README and docs/*.md for banned phrases outside allowlisted files and
quoted non-claim contexts.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

SCAN_ROOTS = (
    REPO / "README.md",
    REPO / "docs",
)

ALLOWLIST_FILES = frozenset(
    {
        "docs/claim-language.md",
        "docs/limitations.md",  # documents non-claims
        "docs/claim-invalidation-ledger.md",
        "docs/final-acceptance.md",
        "docs/quality-engineering.md",
    }
)

# Bare claims that must not appear as product status outside allowlists.
BANNED = (
    re.compile(r"\bproven robust\b", re.I),
    re.compile(r"\bproof of robustness\b", re.I),
    re.compile(r"\bsoundness guaranteed\b", re.I),
    re.compile(r"\bsound verifier\b", re.I),
    re.compile(r"\bproduction ready\b", re.I),
    re.compile(r"\bfully secure\b", re.I),
    re.compile(r"\bsecurity_grade\s*=\s*true\b", re.I),
    re.compile(r"\bsecurity grade achieved\b", re.I),
    # Product-status overclaims (allow "do not claim SOTA" style via negation check).
    re.compile(r"(?<!not )(?<!never )(?<!don't )(?<!do not )\bSOTA\b"),
    re.compile(r"(?<!not )(?<!never )\bstate of the art\b", re.I),
)


def _is_allowlisted(path: Path) -> bool:
    rel = path.relative_to(REPO).as_posix()
    return rel in ALLOWLIST_FILES or rel.startswith("docs/templates/")


def _strip_fenced_and_inline_code(text: str) -> str:
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    text = re.sub(r"`[^`]+`", "", text)
    # Drop markdown blockquotes (often cite banned phrases as counterexamples).
    lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith(">")]
    return "\n".join(lines)


def scan_file(path: Path) -> list[str]:
    if _is_allowlisted(path):
        return []
    raw = path.read_text(encoding="utf-8")
    body = _strip_fenced_and_inline_code(raw)
    hits: list[str] = []
    for pattern in BANNED:
        for match in pattern.finditer(body):
            # Negation windows: "do not claim SOTA", "never scientifically_qualified".
            start = max(0, match.start() - 40)
            window = body[start : match.end() + 10].lower()
            if any(
                neg in window
                for neg in (
                    "do not",
                    "don't",
                    "never",
                    "not a",
                    "not claim",
                    "non-claim",
                    "banned",
                    "without",
                    "must not",
                    "cannot",
                    "honest",
                )
            ):
                continue
            rel = path.relative_to(REPO).as_posix()
            hits.append(f"{rel}: banned claim {match.group(0)!r}")
    return hits


def iter_targets() -> list[Path]:
    out: list[Path] = []
    for root in SCAN_ROOTS:
        if root.is_file():
            out.append(root)
        elif root.is_dir():
            out.extend(sorted(root.rglob("*.md")))
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    errors: list[str] = []
    for path in iter_targets():
        errors.extend(scan_file(path))
    if errors:
        print("FAIL: claim-language lint", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print(f"OK: claim-language lint ({len(iter_targets())} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
