#!/usr/bin/env bash
# Wheel-oriented smoke entrypoint (also works with editable installs).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
python - <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

root = Path(".").resolve()
manifest = json.loads((root / "example-manifest.json").read_text(encoding="utf-8"))
print(f"example={manifest.get('example_id')} status={manifest.get('integration_status')}")
print(f"install_hint={manifest.get('install')}")
if importlib.util.find_spec("verifierlab") is None:
    print(
        "verifierlab not importable; install the released wheel "
        f"({manifest.get('install')}) or an editable checkout.",
        file=sys.stderr,
    )
    # Still succeed for contract smoke — verify.sh checks files.
else:
    import verifierlab

    print(f"verifierlab={getattr(verifierlab, '__version__', 'unknown')}")
print("example smoke ok:", root)
PY
