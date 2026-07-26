# Example V5 — EnvAssure

## Install (wheel, when published)

```bash
pip install "verifierlab[envassure]>=0.2.0rc2"
./run.sh && ./verify.sh
```

Until `envassure` is published on PyPI this example uses the fixture/protocol
backend and reports **not-live**. Never claim live from fixtures.

## Install (local editable)

```bash
pip install -e "../../.[envassure]"   # may fail if package unpublished
./run.sh && ./verify.sh               # fixture path still verifies contract files
```

See `example-manifest.json` (`integration_status: not-live`).
