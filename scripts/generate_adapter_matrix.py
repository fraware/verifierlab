#!/usr/bin/env python3
"""Generate publishable adapter matrix JSON/Markdown from registry source.

Usage:
  python scripts/generate_adapter_matrix.py
  python scripts/generate_adapter_matrix.py --check
  python scripts/generate_adapter_matrix.py --out-json dist/adapter-matrix.json

Statuses are restricted to:
  live-tested / protocol-reference-tested / fixture-only / unsupported

Never labels fixture-only paths as live-tested. EnvAssure remains
fixture-only (not installable) until the package is on PyPI.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "registry" / "adapter-matrix-v1.json"
DEFAULT_MD = REPO / "docs" / "adapters" / "matrix.md"
DEFAULT_JSON = REPO / "dist" / "adapter-matrix.json"

ALLOWED_STATUSES = frozenset(
    {
        "live-tested",
        "protocol-reference-tested",
        "fixture-only",
        "unsupported",
    }
)


def load_matrix(path: Path = SOURCE) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def render_markdown(matrix: dict[str, Any]) -> str:
    contract = matrix.get("adapter_contract") or {}
    lines = [
        "# Adapter matrix",
        "",
        "Generated from `registry/adapter-matrix-v1.json`.",
        "Do not hand-edit this page; run `python scripts/generate_adapter_matrix.py`.",
        "",
        matrix.get("note") or "",
        "",
        (
            f"Adapter contract `{contract.get('contract_id', '—')}` "
            f"v{contract.get('version', '—')}."
        ),
        "",
        "| Adapter | Extra | Status | Live vs fixture | Versions | CI | Limitations |",
        "| ------- | ----- | ------ | --------------- | -------- | -- | ----------- |",
    ]
    for row in matrix.get("adapters") or []:
        versions = row.get("versions") or {}
        ver_s = ", ".join(f"{k} `{v}`" for k, v in sorted(versions.items())) or "—"
        extra = row.get("extra")
        extra_s = f"`[{extra}]`" if extra else "(base)"
        lines.append(
            "| {adapter} | {extra} | {status} | {lvf} | {ver} | {ci} | {lim} |".format(
                adapter=row.get("adapter", ""),
                extra=extra_s,
                status=row.get("status", ""),
                lvf=row.get("live_vs_fixture", ""),
                ver=ver_s,
                ci=row.get("ci", ""),
                lim=row.get("limitations", "—"),
            )
        )
    lines.extend(
        [
            "",
            "## Notes",
            "",
        ]
    )
    for row in matrix.get("adapters") or []:
        note = row.get("note")
        if note:
            lines.append(f"- **{row.get('adapter')}:** {note}")
    lines.append("")
    return "\n".join(lines)


def write_outputs(
    matrix: dict[str, Any],
    *,
    md_path: Path,
    json_path: Path,
) -> None:
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown(matrix), encoding="utf-8")
    # Publishable copy with generation metadata.
    payload = dict(matrix)
    payload["source"] = "registry/adapter-matrix-v1.json"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def check_honesty(matrix: dict[str, Any]) -> list[str]:
    """Fail closed on status vocabulary + fixture-as-live + EnvAssure rules."""
    errors: list[str] = []
    # Prefer in-package validator when importable (editable / installed).
    try:
        from verifierlab.targets.contract import validate_matrix_document

        return validate_matrix_document(matrix)
    except ImportError:
        pass

    by_name = {r["adapter"]: r for r in matrix.get("adapters") or [] if "adapter" in r}
    for row in matrix.get("adapters") or []:
        status = str(row.get("status") or "")
        if status not in ALLOWED_STATUSES:
            errors.append(f"{row.get('adapter')}: illegal status {status!r}")
        live_vs = str(row.get("live_vs_fixture") or "").lower()
        if status in {"fixture-only", "unsupported"} and (
            "live-tested" in live_vs or live_vs.strip() == "live"
        ):
            errors.append(f"{row.get('adapter')}: fixture/unsupported cannot claim live-tested")
    env = by_name.get("envassure") or {}
    if env.get("status") not in {"fixture-only", "unsupported"}:
        errors.append("envassure must be fixture-only or unsupported until installable")
    if env.get("installable") is True:
        errors.append("envassure installable=true is not yet allowed (package unpublished)")
    statuses = {r.get("status") for r in matrix.get("adapters") or []}
    if "live-tested" not in statuses:
        errors.append("matrix must include at least one live-tested adapter")
    if not statuses & {"fixture-only", "unsupported", "protocol-reference-tested"}:
        errors.append("matrix must document at least one non-live path")
    return errors


def check_outputs(matrix: dict[str, Any], *, md_path: Path, json_path: Path) -> list[str]:
    errors = check_honesty(matrix)
    expected_md = render_markdown(matrix)
    if not md_path.is_file():
        errors.append(f"missing {md_path}")
    elif md_path.read_text(encoding="utf-8") != expected_md:
        errors.append(f"stale markdown: {md_path} (regenerate)")
    if not json_path.is_file():
        errors.append(f"missing {json_path}")
    else:
        on_disk = json.loads(json_path.read_text(encoding="utf-8"))
        # Compare adapter rows only (ignore ephemeral keys).
        if on_disk.get("adapters") != matrix.get("adapters"):
            errors.append(f"stale json adapters: {json_path}")
        if on_disk.get("adapter_contract") != matrix.get("adapter_contract"):
            errors.append(f"stale json adapter_contract: {json_path}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_MD)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_JSON)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit nonzero if generated outputs are missing or stale",
    )
    args = parser.parse_args(argv)

    matrix = load_matrix(args.source.resolve())
    if args.check:
        errors = check_outputs(matrix, md_path=args.out_md, json_path=args.out_json)
        if errors:
            print("FAIL:", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)
            return 1
        print("OK: adapter matrix outputs are current", file=sys.stderr)
        return 0

    write_outputs(matrix, md_path=args.out_md, json_path=args.out_json)
    # Always validate honesty after write.
    honesty = check_honesty(matrix)
    if honesty:
        print("FAIL: honesty checks:", file=sys.stderr)
        for err in honesty:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print(f"wrote {args.out_md}")
    print(f"wrote {args.out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
