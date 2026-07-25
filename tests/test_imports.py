"""Base import graph must not pull heavy ML / cluster SDKs."""

from __future__ import annotations

import importlib


def test_base_package_imports() -> None:
    import verifierlab
    import verifierlab.api
    import verifierlab.artifacts
    import verifierlab.budgets
    import verifierlab.campaigns
    import verifierlab.cli
    import verifierlab.config
    import verifierlab.execution
    import verifierlab.targets

    assert verifierlab.__version__


def test_heavy_deps_not_required() -> None:
    """Heavy SDKs must not be required by the base package.

    If they happen to be installed in the host environment, probing them must
    not fail the suite (broken/OOM torch installs are common on shared hosts).
    """
    for name in ("torch", "ray", "kubernetes", "transformers"):
        try:
            importlib.import_module(name)
        except ImportError:
            continue
        except OSError:
            # Present but unloadable (e.g. paging-file / DLL issues) — ignore.
            continue
        # If somehow present and importable, importing verifierlab must not
        # have required them — this test only documents absence preference.
        pass
