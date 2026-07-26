# Example V1 — Native Python verifier

Full lifecycle oriented to a **released wheel** install (local editable also works).

## Install (wheel)

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install "verifierlab>=0.2.0rc2"
./run.sh && ./verify.sh
```

## Install (local editable, development)

```bash
pip install -e "../.."   # from this example directory, repo root
# or: pip install -e ".[dev]" from the repo root
./run.sh && ./verify.sh
```

## Contract

| File | Role |
| ---- | ---- |
| `campaign.yaml` | Pinned smoke campaign |
| `verifier/` | Native grade callable |
| `environment/` | Tiny deterministic env |
| `expected/public_summary.json` | Public expected summary |
| `run.sh` / `verify.sh` | Wheel-oriented entrypoints |
| `example-manifest.json` | Install metadata (`integration_status: live`) |

`integration_status` is **live** for the native path — not a verifier-soundness claim.
