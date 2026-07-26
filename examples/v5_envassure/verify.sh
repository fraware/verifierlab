#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
test -f example-manifest.json
test -f campaign.yaml
test -f README.md
python -c "import json; json.load(open('example-manifest.json'))"
echo "verify ok"
