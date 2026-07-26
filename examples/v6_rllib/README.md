# Example V6 — RLlib

## Install (wheel)

```bash
pip install "verifierlab[rllib]>=0.2.0rc2"
./run.sh && ./verify.sh
```

## Install (local editable)

```bash
pip install -e "../../.[rllib]"
./run.sh && ./verify.sh
```

Integration conformance only — **not** a capability / SOTA claim. PR-tier tests
skip when Ray is missing (`integration_status: live_when_ray_installed`,
`claim: integration_conformance`).
