# Example V3 — Inspect AI

Install from a **released wheel** with the `[inspect]` extra.

## Install (wheel)

```bash
pip install "verifierlab[inspect]>=0.2.0rc2"
./run.sh && ./verify.sh
```

## Install (local editable)

```bash
pip install -e "../../.[inspect]"
./run.sh && ./verify.sh
```

Modes: `live_task`, `scorer_verifier`, `eval_log_import` (fixture/regression —
never labeled live). See `example-manifest.json`.
