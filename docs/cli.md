# CLI reference

Entry point: `valab` (`verifierlab.cli:app`). Package: `verifierlab`.

| Command | Purpose |
| ------- | ------- |
| `valab --version` | Package version (`0.2.0rc1` on this release line) |
| `valab init [--path DIR] [--force]` | Create `.valab` workspace (store + runs) |
| `valab doctor [--format text\|json]` | Environment / dependency health |
| `valab inspect MODULE:ATTR [--format text\|json]` | Print `VerifierSpec` for a `@verifier` |
| `valab run CAMPAIGN.yaml` | Tutorial alias for `campaign run` |
| `valab campaign validate PATH` | Load + validate `CampaignSpec` |
| `valab campaign run PATH [--threads\|--processes] [--workers N]` | Attack plane only |
| `valab campaign freeze RUN_DIR` | Seal vault + append `FreezeRecord` |
| `valab campaign adjudicate RUN_DIR [--campaign PATH]` | Hidden-GT adjudication (coordinator) |
| `valab campaign release-labels RUN_DIR` | Release sealed labels after adjudication |
| `valab report builds RUN_DIR` | Offline HTML/JSON/CSV rebuild (post-release) |
| `valab stats power --p0 … --p1 … (--n\|--power)` | Binomial power / sample size |
| `valab plugins list [--format text\|json]` | Discover `verifierlab.plugins` entry points |

## Required lifecycle

```text
campaign run → freeze → adjudicate → release-labels → report builds
```

`report builds` raises if labels have not been released.

Default workspace: `./.valab`. Artifacts are content-addressed under `store/`;
run bundles under `runs/`.

Structured output: pass `--format json` where supported.

Common options on campaign run:

- `--workspace PATH` — override workspace root
- `--workers N` — pool size (default 2)
- `--threads` / `--processes` — thread pool vs process pool (prefer processes)

## Deferred (intentionally not in alpha CLI)

| Deferred command | Reason |
| ---------------- | ------ |
| `valab campaign resume` | Resume is automatic when the run dir exists (`resume=True` default in engine) |
| `valab campaign cancel` | Local launcher cancellation is in-process; no durable cancel IPC yet |
| `valab disclose *` | Disclosure registry is a Python API; see [disclosure.md](disclosure.md) |
| `valab stats bootstrap` | Bootstrap helpers exist in `verifierlab.statistics`; CLI surface deferred |
| `valab adapter *` | Adapters are library imports + extras; see [adapters.md](adapters.md) |
| Interactive TUI dashboard | `[dashboard]` extra reserved; not shipped |
