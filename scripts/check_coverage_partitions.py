#!/usr/bin/env python3
"""Report coverage against config/coverage-partitions.toml (WP-18).

Usage:
  COVERAGE_FILE=.coverage python scripts/check_coverage_partitions.py
  python scripts/check_coverage_partitions.py --dry-run   # print targets only

Does not raise the global CI floor. Exits nonzero only when --enforce is set
and a partition is below its target (intended for nightly / optional jobs).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONFIG = REPO / "config" / "coverage-partitions.toml"


def load_partitions(path: Path) -> dict:
    try:
        import tomllib
    except ImportError:  # pragma: no cover
        import tomli as tomllib  # type: ignore
    return tomllib.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Fail when measured coverage is below partition targets",
    )
    args = parser.parse_args(argv)
    data = load_partitions(args.config)
    print(f"global_fail_under={data.get('ci', {}).get('global_fail_under', 40)}")
    partitions = {
        k: v for k, v in data.items() if k.startswith("partitions.") or k == "partitions"
    }
    # tomllib nests [partitions.X] under data['partitions'][X]
    nested = data.get("partitions") or {}
    for name, part in nested.items():
        target = part.get("target_branch_percent_practical") or part.get(
            "target_branch_percent"
        )
        modules = part.get("modules") or []
        print(f"[{name}] target>={target}% modules={len(modules)}")
        for mod in modules:
            print(f"  - {mod}")

    if args.dry_run:
        return 0

    try:
        from coverage import Coverage
    except ImportError:
        print("coverage package not installed; reporting targets only", file=sys.stderr)
        return 0 if not args.enforce else 1

    cov = Coverage()
    try:
        cov.load()
    except Exception as exc:  # noqa: BLE001
        print(f"no coverage data loaded: {exc}", file=sys.stderr)
        return 0 if not args.enforce else 1

    failures: list[str] = []
    for name, part in nested.items():
        target = float(
            part.get("target_branch_percent_practical")
            or part.get("target_branch_percent")
            or 0
        )
        # Aggregate measured percent across listed modules when data exists.
        measured_vals: list[float] = []
        for mod in part.get("modules") or []:
            # coverage module names use filesystem paths; best-effort match.
            _, statements, missing, _branches = 0, 0, 0, 0  # placeholders
            try:
                # analysis2 returns (statements, excluded, missing, missing_fmt)
                for filename in cov.get_data().measured_files():
                    if mod.replace(".", "/") in filename.replace("\\", "/"):
                        analysis = cov.analysis2(filename)
                        stmts = len(analysis[1])
                        miss = len(analysis[3])
                        if stmts:
                            measured_vals.append(100.0 * (stmts - miss) / stmts)
            except Exception:  # noqa: BLE001
                continue
            del statements, missing, _branches
        if not measured_vals:
            print(f"[{name}] no measured files (skip)")
            continue
        measured = sum(measured_vals) / len(measured_vals)
        print(f"[{name}] measured≈{measured:.1f}% target>={target}%")
        if measured + 1e-9 < target:
            failures.append(f"{name}: {measured:.1f}% < {target}%")

    if args.enforce and failures:
        print("FAIL:", file=sys.stderr)
        for item in failures:
            print(f"  - {item}", file=sys.stderr)
        return 1
    print("OK: partition report complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
