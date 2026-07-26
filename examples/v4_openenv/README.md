# Example V4 — OpenEnv

Install from a **released wheel** with the `[openenv]` extra (HTTP reference
path also works without the heavy SDK).

## Install (wheel)

```bash
pip install "verifierlab[openenv]>=0.2.0rc2"
./run.sh && ./verify.sh
```

## Install (local editable)

```bash
pip install -e "../../.[openenv]"
./run.sh && ./verify.sh
```

Prefer the official client when present; do not claim hosted Spaces automation.
