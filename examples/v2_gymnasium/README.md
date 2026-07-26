# Example V2 — Gymnasium

Install from a **released wheel** with the `[gym]` extra (local editable also works).

## Install (wheel)

```bash
pip install "verifierlab[gym]>=0.2.0rc2"
./run.sh && ./verify.sh
```

## Install (local editable)

```bash
pip install -e "../../.[gym]"
./run.sh && ./verify.sh
```

Legacy `gym` is **not** a beta claim — use Gymnasium via `[gym]`. See
`example-manifest.json` (`integration_status: live`).
