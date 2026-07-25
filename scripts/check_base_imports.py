#!/usr/bin/env python3
"""Fail CI if the base install graph pulls heavy ML / cluster SDKs.

Checks:
1. ``verifierlab`` base (non-extra) requirements do not list forbidden packages.
2. Importing the base package does not newly load forbidden top-level modules.

Host environments may already have torch/ray installed for unrelated work; that
alone must not fail the gate. What matters is that VerifierLab does not depend
on them.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import sys

FORBIDDEN = frozenset(
    {
        "torch",
        "pytorch",
        "ray",
        "kubernetes",
        "transformers",
        "openai",
        "anthropic",
        "vllm",
        "tensorflow",
        "jax",
        "jaxlib",
        "boto3",
        "botocore",
        "gymnasium",
        "gym",
        "inspect_ai",
        "moto",
    }
)

_BASE_MODULES = (
    "verifierlab",
    "verifierlab.api",
    "verifierlab.artifacts",
    "verifierlab.attacks",
    "verifierlab.budgets",
    "verifierlab.campaigns",
    "verifierlab.cli",
    "verifierlab.config",
    "verifierlab.execution",
    "verifierlab.labels",
    "verifierlab.reports",
    "verifierlab.statistics",
    "verifierlab.targets",
)


def _normalized(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def _check_requires() -> list[str]:
    dist = importlib.metadata.distribution("verifierlab")
    requires = dist.requires or []
    base_names: set[str] = set()
    for req in requires:
        # Skip optional extras (packaging markers like `; extra == 'dev'`).
        if "extra ==" in req:
            continue
        name = req.split(";", 1)[0].strip()
        for sep in ("[", " ", "<", ">", "=", "!"):
            if sep in name:
                name = name.split(sep, 1)[0]
        base_names.add(_normalized(name))
    forbidden_norm = {_normalized(f) for f in FORBIDDEN}
    return sorted(n for n in base_names if n in forbidden_norm)


def _check_import_graph() -> list[str]:
    before = set(sys.modules)
    for name in _BASE_MODULES:
        importlib.import_module(name)
    after = set(sys.modules)
    newly = after - before
    pulled: set[str] = set()
    for mod in newly:
        top = mod.split(".", 1)[0].lower()
        if top in FORBIDDEN:
            pulled.add(top)
    return sorted(pulled)


def main() -> int:
    hits = _check_requires()
    if hits:
        print("ERROR: base dependencies include forbidden packages:", ", ".join(hits))
        return 1

    pulled = _check_import_graph()
    if pulled:
        print(
            "ERROR: importing verifierlab base loaded forbidden modules:",
            ", ".join(pulled),
        )
        return 1

    print("OK: base dependency graph has no heavy ML / cluster SDKs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
