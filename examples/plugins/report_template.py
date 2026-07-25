"""Plugin template: custom report renderer."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def render_example_report(run_dir: Path, payload: dict[str, Any]) -> Path:
    out = Path(run_dir) / "report" / "example.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(f"example report for {payload.get('run_id')}\n", encoding="utf-8")
    return out
