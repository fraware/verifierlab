# Known limitations (honest non-claims)

This document records where VerifierLab (`0.1.0a0` alpha) is **solid** versus
**intentionally thin**. Do not treat thin surfaces as production SDK
integrations unless noted as live below. Cross-links:
[adapters.md](adapters.md), [methodology.md](methodology.md),
[threat-model.md](threat-model.md).

## Solid (integrity core)

| Area | Notes |
| ---- | ----- |
| Filesystem CAS + canonical digests | Golden digest tests |
| `@verifier` / CampaignSpec / budgets | Validated + ledger overrun policy |
| Local launcher (resume, idempotency) | Failed units persisted |
| Ordinary + optimized cohorts | Mandatory cohort tagging |
| Public vs GT separation | Workers/strategies never receive `gt_valid`; coordinator enriches |
| Label vault + freeze | Post-freeze injection rejected; release-gated reads |
| Lifecycle transitions | Enforced freeze → label_release; illegal jumps rejected |
| FAR/FRR + abstention/missingness | Explicit denominators; stratified by access model; mixed-access pooling rejected |
| Wilson + Clopper–Pearson (pure Python) | No SciPy; see numerical caveats below |
| Delta-debug minimization | Preserves accept∧invalid predicate |
| Repair + mandatory fresh attacker | `compare_repair` |
| Offline report rebuild | From immutable `work_units/` + manifest (`AssuranceReport`) |
| Refund tutorial / planted pack | Offline CI smoke |
| Campaign packs A–E | Runnable offline with taxonomy recovery assertions |
| Metamorphic / isomorphic GT invariance | `verifierlab.statistics.metamorphic` |
| Time-to-exploit + Kaplan–Meier | Censored survival helpers in `statistics` |
| Adversarial self-tests (§30.2) | Label leak, freeze injection, budget undercount, secret-in-report |
| Base package import gate | No torch/ray/k8s/boto3/gymnasium/inspect-ai in base deps |
| **Gymnasium live adapter** (`[gym]`) | Real `gymnasium.Env` → native `EnvironmentTarget` |
| **Inspect live adapter** (`[inspect]`) | Real `inspect-ai` Task/eval/log mapping when installed |
| **Harbor live adapter** (`[harbor]`) | Real Harbor `Trajectory` / validator when installed (Py≥3.12) |
| **NeMo Gym HTTP adapter** (`[nemo]`) | Live HTTP client + in-repo reference resources server |
| **OpenEnv adapter** (`[openenv]`) | Live HTTP protocol client + in-repo reference env server |

## Live behind optional extras

| Area | Extra | Reality |
| ---- | ----- | ------- |
| Gymnasium | `[gym]` | **Live** wrap of `gymnasium.Env`. Missing extra → clear `ImportError` (no stub pass). |
| Inspect | `[inspect]` pins `inspect-ai` | **Live** Task/`eval`/`read_eval_log` mapping. Fixture eval-log JSON remains as **log-format regression** only. CI live tests use `mockllm/model` when inspect-ai is installed; otherwise skip. |
| Harbor | `[harbor]` pins `harbor` (Py≥3.12) | **Live** ATIF parse/validate via Harbor Pydantic models. Fixture ATIF JSON is **log-format regression**. Harbor agent/sandbox orchestration stays outside VerifierLab (consume ATIF artifacts). Install can fail on some hosts when Harbor's `litellm` build deps (maturin/truststore) are broken — `harbor_sdk_available()` / `harbor_install_status()` then report `broken_install` or `not_installed`, live tests skip, and the ATIF regression path stays green. Prefer Linux CI or a conda env for the live SDK; Windows developers can validate via ATIF fixtures without installing Harbor. |
| NeMo Gym endpoints | `[nemo]` (no NVIDIA pin) | **Live** HTTP client for `/seed_session`, `/verify`, tool routes. CI starts the **stdlib reference server**; adapter never bypasses the protocol. |
| OpenEnv | `[openenv]` pins `openenv` (optional/heavy) | **Live** HTTP simulation protocol (`/reset`, `/step`, `/state`). CI always uses the **in-repo reference server**. SDK discovery tests skip when `openenv` is absent. |
| S3-compatible CAS | `[objectstore]` | **Live** `S3ObjectStoreClient` via boto3 (AWS / MinIO). Filesystem `LocalObjectStoreClient` remains the default. |
| Slurm launcher | `[slurm]` | **Live** when `sbatch`/`squeue`/`scancel` exist and `dry_run=False`; otherwise explicit dry-run with `dry_run_reason`. |
| Kubernetes launcher | `[kubernetes]` | **Live** Job create/status/delete when the `kubernetes` client + kubeconfig work; otherwise explicit dry-run. |

### Install extras

```bash
pip install "verifierlab[gym]"
pip install "verifierlab[inspect]"      # pins inspect-ai
pip install "verifierlab[harbor]"       # pins harbor; requires Python >=3.12
pip install "verifierlab[nemo]"         # HTTP client + reference server (stdlib)
pip install "verifierlab[openenv]"      # optional heavy openenv SDK; reference path works without it
pip install "verifierlab[objectstore]"
pip install "verifierlab[kubernetes]"
pip install "verifierlab[adapters]"     # gym + inspect + harbor + openenv + nemo
```

### CI strategy

| Adapter | Always in CI | When extra/SDK present |
| ------- | ------------ | ---------------------- |
| Inspect | Eval-log JSON format regression | Minimal Task + `mockllm/model` eval |
| Harbor | ATIF JSON format regression | Parse/validate with Harbor `Trajectory` |
| NeMo | Live client vs local reference HTTP server | Same (no NVIDIA stack) |
| OpenEnv | Live client vs local reference HTTP server | SDK import discovery |
| Gym | Skip / ImportError without gymnasium | TinyDiscrete + optional CartPole |

## Thin (exists; do not overclaim)

| Area | Reality |
| ---- | ------- |
| Harbor agent orchestration | VerifierLab consumes ATIF + Harbor types; it does not run Harbor sandboxes/agents in-process. |
| NeMo training stack | HTTP resources/verifier protocol only — not NeMo Gym Ray training loops or NVIDIA containers. |
| OpenEnv Docker / Spaces deploy | Protocol + reference env are live; HF Spaces / Docker providers remain optional upstream. |
| Clopper–Pearson | Pure-Python incomplete beta (continued fraction). Common (n, k, α) vectors are golden-tested; extreme parameters may differ by a few ulps from SciPy. |
| Snapshot/restore on fake / gym / openenv | Deterministic re-seed+replay fidelity — not a full time-travel debugger. |
| RL path | Local tabular Q-learning only in base; heavy trainers remain optional/external. |
| Sandbox profiles | **Declarative** policy tags (`SandboxProfile`) for reference campaigns — not a container/OS sandbox runtime. |
| Threat model doc | Expanded beyond M0 draft but still research-draft. |

## Missing / deferred (excellence backlog)

- SciPy-backed exact intervals as an optional `[stats]` extra
- Full OS/container sandbox enforcement for untrusted verifier code
- Independent multi-host reproduction bake-off automation
- In-process Harbor sandbox runner (today: ATIF + types; orchestration is Harbor's)

## Adapter claim (copy into reports)

> External adapters in this release: **Gymnasium**, **Inspect** (`inspect-ai`),
> **Harbor** (ATIF + Harbor types), **NeMo Gym HTTP** (reference server in CI),
> and **OpenEnv** (HTTP protocol + reference env in CI). Optional extras pin
> real packages where they exist on PyPI; when an SDK is absent, tests skip with
> an explicit reason or imports fail with an install hint — never a fake stub
> pass. Slurm, Kubernetes, and S3 paths are live when their extras/binaries are
> present; otherwise they dry-run with an explicit status field.
