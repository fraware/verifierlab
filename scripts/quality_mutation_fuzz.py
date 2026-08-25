#!/usr/bin/env python3
"""Nightly-oriented mutation / fuzz scaffolding (WP-18).

This script is intentionally lightweight: it documents hooks and runs a
small regression corpus against canonicalization and schema verify. Full
mutmut campaigns are optional and not required for default CI green.

Usage:
  python scripts/quality_mutation_fuzz.py
  python scripts/quality_mutation_fuzz.py --corpus-only
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "tests" / "fixtures" / "fuzz_corpus"
MUTATION_NOTES = REPO / "docs" / "quality-engineering.md"


def ensure_corpus() -> list[Path]:
    CORPUS.mkdir(parents=True, exist_ok=True)
    seed = CORPUS / "canonical_smoke.json"
    if not seed.is_file():
        seed.write_text(
            json.dumps({"a": 1, "z": [True, None, "x"], "nested": {"k": "v"}}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
    return sorted(CORPUS.glob("*.json"))


def run_corpus() -> list[str]:
    sys.path.insert(0, str(REPO / "src"))
    from verifierlab.artifacts.canonical import digest_of
    from verifierlab.artifacts.schema_registry import load_schema_registry, verify_artifact_payload

    errors: list[str] = []
    for path in ensure_corpus():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{path.name}: invalid json ({exc})")
            continue
        digest = digest_of(payload)
        if len(digest) != 64:
            errors.append(f"{path.name}: bad digest length")
        # If the fixture declares an artifact type, verify fail-closed.
        if isinstance(payload, dict) and "artifact_type" in payload:
            try:
                reg = load_schema_registry(REPO / "registry" / "schema-registry-v1.json")
                report = verify_artifact_payload(
                    str(payload["artifact_type"]),
                    payload,
                    registry=reg,
                )
                if payload.get("expect_ok") is False and report["ok"]:
                    errors.append(f"{path.name}: expected verify failure")
            except Exception as exc:  # noqa: BLE001
                if payload.get("expect_ok") is not False:
                    errors.append(f"{path.name}: {exc}")
    return errors


def print_mutation_hooks() -> None:
    print("Mutation hooks (nightly; not default CI):")
    print("  pip install mutmut")
    print("  mutmut run --paths-to-mutate=src/verifierlab/api/decision.py")
    print("  mutmut run --paths-to-mutate=src/verifierlab/artifacts/canonical.py")
    print("  mutmut run --paths-to-mutate=src/verifierlab/assurance/resolver.py")
    print("Fuzz hooks:")
    print("  python scripts/quality_mutation_fuzz.py --corpus-only")
    print(f"Docs: {MUTATION_NOTES.relative_to(REPO) if MUTATION_NOTES.exists() else '(pending)'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-only", action="store_true")
    args = parser.parse_args(argv)
    if not args.corpus_only:
        print_mutation_hooks()
    errors = run_corpus()
    if errors:
        print("FAIL corpus:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print(f"OK: fuzz corpus ({len(ensure_corpus())} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
