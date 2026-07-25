"""Resolve dotted ``module:attr`` refs used in campaign specs."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Any


def ensure_repo_on_path() -> None:
    """Allow ``examples.*`` imports when running from a source checkout."""
    repo = Path(__file__).resolve().parents[3]
    examples = repo / "examples"
    if str(repo) not in sys.path:
        sys.path.insert(0, str(repo))
    if examples.is_dir() and str(examples.parent) not in sys.path:
        sys.path.insert(0, str(examples.parent))


def load_object(ref: str) -> Any:
    """Load ``package.module:attribute`` or ``package.module.attribute``."""
    ensure_repo_on_path()
    if ":" in ref:
        module_name, attr = ref.split(":", 1)
    else:
        parts = ref.rsplit(".", 1)
        if len(parts) != 2:
            raise ValueError(f"invalid object ref: {ref!r}")
        module_name, attr = parts
    module = importlib.import_module(module_name)
    obj: Any = module
    for part in attr.split("."):
        obj = getattr(obj, part)
    return obj
