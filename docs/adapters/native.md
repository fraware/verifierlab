# Native Python verifier

## Supported versions

- VerifierLab base package (`requires-python >=3.11,<3.14`)
- No optional extra

## Live vs fixture

**Live.** Native `@verifier` callables and in-tree tutorial targets run without
extra SDKs. Example V1: `examples/v1_native_verifier/`.

## Boundary

Worker sees broker + environment only. Ground truth and vault material stay in
adjudication after freeze.

## Mapping

| VerifierLab surface | Native mapping |
| --- | --- |
| `EnvironmentTarget` | Python env plugin / fake env |
| Verifier | `@verifier` callable / `VerifierSpec` |
| Decision | `Decision` / fail-closed `normalize_decision` |

## Unsupported semantics

- Does not claim OS-level sandboxing by default (process-local trust boundary)
- Does not claim verifier soundness from “no exploit found”

## Conformance command

```bash
uv run pytest tests/test_adapter_conformance.py -q
uv run valab campaign validate campaigns/fake-smoke.yaml
```

## CI status

Required on every CI run (`ci.yml`).

## Example

```bash
cd examples/v1_native_verifier
pip install verifierlab   # released wheel
./run.sh && ./verify.sh
```

## Troubleshooting

- Missing contract fields: run `valab inspect <ref>` and complete `VerifierSpec`
- Process workers: ensure module-level `campaigns/worker.py` path is used
