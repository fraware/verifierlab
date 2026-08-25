# Known limitations (honest non-claims)

This document records where VerifierLab (`0.2.0rc2` release candidate on
`integration/final-assurance`) is **solid** versus **intentionally thin**. Do
not treat thin surfaces as production SDK integrations or as a soundness proof.

Cross-links: [adapters.md](adapters.md), [methodology.md](methodology.md),
[threat-model.md](threat-model.md), [claim-language.md](claim-language.md),
[final-acceptance.md](final-acceptance.md),
[SECURITY](https://github.com/fraware/verifierlab/blob/main/SECURITY.md),
[beta-acceptance.md](beta-acceptance.md).

## Capability summary (do not inflate)

| Layer | What exists | What it does **not** mean |
| ----- | ----------- | ------------------------- |
| RC gates 1–6 | `tests/test_acceptance_gates.py` | Scientific or security maturity |
| Final gates A–J | `tests/test_final_acceptance_gates.py` | G7 *software* readiness only |
| Assurance stack | EvidenceResolver, schema registry, method surfaces | Auto-earned `scientifically_qualified` |
| Flagship study | `studies/flagship-2026/` → `internally_verified` | Independent or security-grade qualification |
| Local/process runs | Development / internal verification cap | `security_grade` evidence |

Approved phrasing: [claim-language.md](claim-language.md).

## Achieved — RC + final-assurance in-repo

| Area | Reality today |
| ---- | ------------- |
| Process workers | Module-level `campaigns/worker.py`; CI process smoke + multi-OS matrix (Windows `continue-on-error`) |
| Typed decisions | Fail-closed `normalize_decision` / `VerifierDecision` status set (including repair/minimize paths) |
| GT isolation | Attack workers do not import GT; refuse GT-like refs; `gt_valid` only post-adjudication |
| Vault / freeze | Vault v2 salted + encrypted; append-only freeze → adjudicate → release |
| Access models | Capability-gated at `VerifierBroker`; episode feedback respects score_only / label_only |
| Optimized loops | Persistent attacker runtime; candidate-level BoN/beam/evo/RL metering; worker budget vouchers; compute_units on candidate eval |
| Splits / StatsPlan | Materialized splits + StatsPlan compiler (CIs + gap bootstrap); no default pooling |
| Adapter conformance | Shared contract + honest matrix statuses; live SDKs scheduled or skip-if-missing |
| RC acceptance suite | `tests/test_acceptance_gates.py` encodes gates 1–6 |
| Final acceptance | Gates A–J + NG-01…NG-15 in `tests/test_final_acceptance_gates.py` |
| Sealed runs | `SealedRunManifest`; tip index only advances via lifecycle transitions after seal |
| Maturity derivation | Artifact-derived labels only; caller booleans cannot promote |
| Claim-language lint | `scripts/check_claim_language.py` on README/docs |

Package version is **`0.2.0rc2`**. Remaining thin surfaces below are intentional non-claims, not untested scaffolding.

## Phase D (exploits / repair / audit / sandbox)

| Area | Reality today |
| ---- | ------------- |
| Multidimensional exploits | Intent clauses for process/auth/side-effect/resource/…; classic accept∧invalid remains |
| Minimization | Preserves public accept + hidden invalidity; emits preservation report |
| Repair campaign | `RepairCampaignArtifact` / `run_repair_campaign`: profiles, regression, holdout, equalized budget, paired stats |
| Transcript audit | Structural scan + plugin hook; **never** ground truth (`is_ground_truth=False`) |
| Container sandbox | Optional `[sandbox]` + `docker_runner`; no network / RO mounts / limits when Docker works; honest degrade if missing |
| Default local trust boundary | Process-local Python — declarative profiles alone are not OS isolation |
| Security-grade path | Digest-pinned rootless worker + probe catalogue; rootful/process hosts fail closed |

## Solid (integrity-adjacent plumbing)

| Area | Notes |
| ---- | ----- |
| Filesystem CAS + canonical digests | Golden digest tests |
| `@verifier` / CampaignSpec / budgets | Validated + ledger overrun policy |
| Local launcher (resume, idempotency) | Failed units persisted; process path uses top-level worker |
| Ordinary + optimized cohort tags | Mandatory; persistent optimized strategies checkpoint |
| Public vs GT split | Workers: broker + env only; adjudicator loads GT after freeze |
| Label vault + freeze / release | Injection rejected; release-gated reads; audit log |
| Lifecycle transitions | `run → freeze → adjudicate → release → report` |
| FAR/FRR + abstention/missingness | Explicit denominators; stratified; pooling rejected by default |
| Wilson + Clopper–Pearson (pure Python) | No SciPy; see numerical caveats below |
| Delta-debug minimization | Preserves public accept + hidden invalidity (+ optional intent clauses) |
| Repair campaign artifact | `compare_repair` → `run_repair_campaign` (holdout, equalized budget, paired stats) |
| Offline report rebuild | From immutable `work_units/` + post-release labels |
| Refund tutorial / planted pack | Offline CI smoke with full lifecycle |
| Campaign packs A–F | A/B/F in default CI; C/D/E `pack_heavy` / nightly |
| Metamorphic / isomorphic GT invariance | `verifierlab.statistics.metamorphic` |
| Time-to-exploit + Kaplan–Meier | Censored survival helpers in `statistics` |
| Adversarial self-tests (§30.2) | Label leak, freeze injection, budget undercount, secret-in-report |
| Base package import gate | No torch/ray/k8s/boto3/gymnasium/inspect-ai in base deps |
| **Gymnasium / Inspect / Harbor / NeMo / OpenEnv adapters** | Live or fixture paths as documented in the matrix |

## Live behind optional extras

| Area | Extra | Reality |
| ---- | ----- | ------- |
| Gymnasium | `[gym]` | **Live** wrap of `gymnasium.Env`. Missing extra → clear `ImportError` (no stub pass). |
| Inspect | `[inspect]` pins `inspect-ai` | **Live** Task/`eval`/`read_eval_log` mapping. Fixture eval-log JSON remains as **log-format regression** only. CI live tests use `mockllm/model` when inspect-ai is installed; otherwise skip. |
| Harbor | `[harbor]` pins `harbor` (Py≥3.12) | **Live** ATIF parse/validate via Harbor Pydantic models. Fixture ATIF JSON is **log-format regression**. |
| NeMo Gym endpoints | `[nemo]` (no NVIDIA pin) | **Live** HTTP client + **stdlib reference server** in CI. |
| OpenEnv | `[openenv]` pins `openenv` (optional/heavy) | **Live** HTTP simulation protocol + in-repo reference env. |
| EnvAssure | `[envassure]` | **Fixture-only** until the package is installable on the index. |
| RLlib | `[rllib]` | Protocol / conformance; skip-if-missing; **not** an attacker-capability claim. |
| S3-compatible CAS | `[objectstore]` | **Live** `S3ObjectStoreClient` via boto3. |
| Slurm / Kubernetes | `[slurm]` / `[kubernetes]` | Live when binaries/client work; otherwise explicit dry-run. |
| Docker plugin sandbox | `[sandbox]` | **Optional.** CLI `docker` required; degrades to `unavailable` when missing (never silent pass). |

### CI strategy

| Surface | Default CI | Scheduled / release |
| ------- | ---------- | ------------------- |
| Core + packs A/B/F | Always | — |
| Packs C/D/E | Excluded (`pack_heavy`) | Extras matrix / nightly |
| Adapter fixtures | Always | Live SDKs in extras matrix |
| Coverage threshold | `--cov-fail-under=40` | — |
| Multi-OS process | Ubuntu/macOS hard-fail; Windows soft-fail (**not** release-qualified — see [support-matrix.md](support-matrix.md)) | — |
| CodeQL | On PR/push | Weekly schedule |
| pip-audit + SBOM | Hard-fail high/critical on `main` / release / tags | Manual dispatch |

## Thin (exists; do not overclaim)

| Area | Reality |
| ---- | ------- |
| Harbor agent orchestration | Consumes ATIF + types; does not run Harbor sandboxes in-process. |
| NeMo training stack | HTTP protocol only — not Ray/NVIDIA containers. |
| OpenEnv Docker / Spaces | Protocol + reference env live; upstream providers optional. |
| Clopper–Pearson | Pure-Python incomplete beta; extreme params may differ from SciPy. |
| RL path | Local tabular Q-learning in base; `TrainerAdapter` is broker-only step loop (not a product RL trainer); heavy trainers optional/external. |
| Concurrent vouchers | Coordinator **atomically reserves** disjoint query vouchers before submit (`reserve_query_voucher`); merge releases the reservation after spend. Parallel workers can no longer oversubscribe remaining quota. Unused reservation returns to the pool. |
| Sandbox profiles | Declarative tags + optional Docker runner (`[sandbox]`); default local path trusts host Python. |
| Attack depth | Research-grade families under declared budgets — not a product RL attacker. |
| Clean-room dry-run | Mechanical reconstruction ≠ independent verification. |

## Missing / deferred (excellence backlog)

- SciPy-backed exact intervals as an optional `[stats]` extra
- Independent multi-host reproduction bake-off automation (external trust root)
- Rootless/separate-domain live probe runners (admin/infra)
- In-process Harbor sandbox runner
- Hard pip-audit fail on every PR against unprotected forks (protected `main` / release already hard-fail; see [quality-engineering.md](quality-engineering.md))
- Real prospective deployment field outcomes (no backfill)

## Adapter claim (copy into reports)

> External adapters in this release: **Gymnasium**, **Inspect** (`inspect-ai`),
> **Harbor** (ATIF + Harbor types), **NeMo Gym HTTP** (reference server in CI),
> and **OpenEnv** (HTTP protocol + reference env in CI). EnvAssure remains
> fixture-only until installable. RLlib is protocol/conformance only. Optional
> extras pin real packages where they exist on PyPI; when an SDK is absent,
> tests skip with an explicit reason or imports fail with an install hint —
> never a fake stub pass.
