"""Campaign lifecycle orchestration."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from verifierlab.artifacts.canonical import digest_of, sha256_digest
from verifierlab.artifacts.cas import ContentAddressedStore
from verifierlab.artifacts.lifecycle_records import (
    AdjudicationReleaseRecord,
    AttackRunManifest,
    SealedRunManifest,
)
from verifierlab.artifacts.records import RunManifest
from verifierlab.attacks.runtime import attacker_store_path, is_learning_strategy
from verifierlab.campaigns.lifecycle import (
    LifecycleState,
    assert_transition,
    labels_released,
    lifecycle_of,
    read_tip_index,
    write_tip_index,
)
from verifierlab.campaigns.splits import materialize_split_manifest, split_lookup
from verifierlab.campaigns.worker import execute_work_unit
from verifierlab.config.campaign import AttackSpec, CampaignSpec, load_campaign
from verifierlab.execution.local import LocalLauncher
from verifierlab.execution.protocol import ExecutionPolicy
from verifierlab.execution.secure import (
    SecurityGradeRefused,
    assert_local_dev_maturity_cap,
    select_secure_launcher,
)
from verifierlab.labels.adjudication_service import adjudicate_run, resolve_is_valid
from verifierlab.labels.freeze import FreezeRecord, assert_run_sealed_immutable
from verifierlab.labels.vault import LabelVault


@dataclass(frozen=True)
class CampaignRunResult:
    run_id: str
    run_digest: str
    manifest: RunManifest
    run_dir: Path
    elapsed_s: float


def default_workspace(cwd: Path | None = None) -> Path:
    return (cwd or Path.cwd()) / ".valab"


def init_workspace(root: Path, *, force: bool = False) -> Path:
    root = root.resolve()
    (root / "store").mkdir(parents=True, exist_ok=True)
    (root / "runs").mkdir(parents=True, exist_ok=True)
    (root / "keys").mkdir(parents=True, exist_ok=True)
    marker = root / "README.txt"
    if not marker.exists() or force:
        marker.write_text(
            "VerifierLab local workspace\n"
            "store/ — content-addressed artifacts\n"
            "runs/ — campaign run bundles\n"
            "keys/ — vault keyring (coordinator-only)\n",
            encoding="utf-8",
        )
    return root


def _build_work_units(
    spec: CampaignSpec,
    *,
    run_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Build work units with split assignment and persistent attacker paths.

    Split manifests are materialized before attack. Holdout units get
    ``learning=False`` so the training attacker cannot update on them.
    """
    attacks = list(spec.attacks)
    if not attacks:
        attacks = [
            AttackSpec(
                name=spec.baseline.strategy,
                strategy=spec.baseline.strategy,
                cohort="ordinary" if spec.baseline.strategy == "ordinary" else "optimized",
                units=spec.work_units,
                config=dict(spec.baseline.config),
            )
        ]
    draft: list[dict[str, Any]] = []
    idx = 0
    max_steps = int(spec.environment.config.get("max_steps", 3))
    for attack in attacks:
        attacker_seed = int(attack.config.get("seed", spec.seed))
        for _ in range(attack.units):
            unit_id = f"{spec.name}-{attack.name}-{spec.seed}-{idx:04d}"
            commitment_nonce = f"{unit_id}:{uuid.uuid4().hex}"
            persistent = is_learning_strategy(attack.strategy)
            unit: dict[str, Any] = {
                "unit_id": unit_id,
                "seed": spec.seed + idx,
                "unit_index": idx,
                "max_steps": max_steps,
                "campaign_name": spec.name,
                "access_model": spec.access_model.value,
                "strategy": attack.strategy,
                "strategy_config": {
                    **dict(attack.config),
                    "cohort": attack.cohort,
                    "seed": attacker_seed,
                },
                "cohort": attack.cohort,
                "attacker_seed": attacker_seed,
                "persistent": persistent,
                "environment_ref": spec.environment.ref,
                "environment_kind": spec.environment.kind,
                "environment_config": dict(spec.environment.config),
                "verifier_ref": spec.verifier.ref,
                "verifier_kind": spec.verifier.kind,
                "verifier_config": dict(spec.verifier.config),
                "commitment_nonce": commitment_nonce,
                # Intentionally omitted: ground_truth_ref (VAL-R03).
            }
            if persistent and run_dir is not None:
                unit["attacker_dir"] = str(
                    attacker_store_path(run_dir, attack.strategy, attacker_seed)
                )
            draft.append(unit)
            idx += 1

    # Materialize splits from CampaignSpec.splits before attack (VAL-R11).
    unit_ids = [u["unit_id"] for u in draft]
    split_manifest = materialize_split_manifest(spec, unit_ids=unit_ids, run_dir=run_dir)
    lookup = split_lookup(split_manifest)
    for unit in draft:
        info = lookup.get(unit["unit_id"], {"split": "train", "learning": True})
        unit["split"] = info["split"]
        # Holdout inaccessible to training updates.
        unit["learning"] = bool(info["learning"])
        unit["label_tier"] = info.get("label_tier")
        unit["attack_visible"] = info.get("attack_visible", True)
        if not unit["learning"] and unit.get("attacker_dir"):
            # Holdout may load frozen weights but must not write.
            unit["learning"] = False

    # WP-04: opaque IDs on the attack plane when custody was materialized.
    if run_dir is not None:
        custody_path = Path(run_dir) / "custody" / "hidden_split.json"
        if custody_path.is_file():
            from verifierlab.campaigns.custody import apply_opaque_ids_to_work_units

            custody = json.loads(custody_path.read_text(encoding="utf-8"))
            draft = apply_opaque_ids_to_work_units(draft, custody)
    return draft


def _order_units_for_persistence(units: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run learning units for the same attacker sequentially (train before holdout)."""

    def _key(u: dict[str, Any]) -> tuple[Any, ...]:
        persistent = 1 if u.get("persistent") else 0
        attacker = (u.get("strategy"), u.get("attacker_seed"))
        # Train (learning=True) before holdout within the same attacker.
        holdout = 0 if u.get("learning", True) else 1
        return (persistent, attacker, holdout, int(u.get("unit_index", 0)))

    return sorted(units, key=_key)


def _single_verifier_profile_digest(rows: list[dict[str, Any]]) -> str:
    """Return one verifier profile digest shared by all attributable worker rows.

    Infrastructure failures that never construct a verifier profile may omit the
    digest. Any non-error row must carry one. A campaign with no attributable
    profile, more than one profile, or a malformed digest is not eligible for a
    canonical attack-run manifest and fails closed.
    """
    observed: set[str] = set()
    for row in rows:
        raw = row.get("verifier_profile_digest")
        if raw is None:
            if not row.get("error"):
                raise RuntimeError(
                    "integrity violation: completed work unit missing verifier profile digest"
                )
            continue
        value = str(raw).lower()
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise RuntimeError("integrity violation: malformed verifier profile digest")
        observed.add(value)

    if not observed:
        raise RuntimeError("cannot bind campaign: no verifier profile digest was produced")
    if len(observed) != 1:
        raise RuntimeError(
            "integrity violation: campaign produced multiple verifier profile digests: "
            + ", ".join(sorted(observed))
        )
    return next(iter(observed))


async def run_campaign_async(
    spec: CampaignSpec,
    *,
    workspace: Path,
    run_id: str | None = None,
    max_workers: int = 2,
    resume: bool = True,
    use_processes: bool = True,
    build_report_on_complete: bool = False,
) -> CampaignRunResult:
    """Run the attack plane only. Reports require freeze → adjudicate → release."""
    started = time.perf_counter()
    attack_started_at = time.time()
    workspace = init_workspace(workspace)
    store = ContentAddressedStore(workspace / "store")
    campaign_digest = store.put_json(spec.model_dump(mode="json"))

    run_id = run_id or f"run-{uuid.uuid4().hex[:12]}"
    run_dir = workspace / "runs" / run_id
    if run_dir.exists() and not resume:
        raise FileExistsError(f"run directory already exists: {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=True)

    # Ensure vault keyring exists on coordinator; workers never open it.
    LabelVault.open(run_dir / "vault", workspace=workspace)

    execution_policy = ExecutionPolicy.model_validate((spec.metadata or {}).get("execution") or {})
    assert_local_dev_maturity_cap(execution_policy)
    execution_meta: dict[str, Any] = {
        "execution_policy_digest": execution_policy.content_digest,
        "execution_mode": execution_policy.mode,
        "local_dev_maturity_cap": execution_policy.local_dev_maturity_cap,
    }
    boundary_digests: list[str] = []
    probe_report_digest: str | None = None

    if execution_policy.mode == "security_grade":
        try:
            secure = select_secure_launcher(execution_policy)
        except SecurityGradeRefused as exc:
            raise RuntimeError(
                "security-grade execution refused (fail closed; no local fallback): " + str(exc)
            ) from exc
        if execution_policy.run_isolation_probes:
            probe = secure.run_isolation_probes(gt_guess_seed=spec.seed)
            probe_report_digest = probe.content_digest
            execution_meta["isolation_probe_report_digest"] = probe_report_digest
            execution_meta["isolation_probe_security_grade_eligible"] = (
                probe.security_grade_eligible
            )
        work_units = _order_units_for_persistence(_build_work_units(spec, run_dir=run_dir))
        rows = []
        for unit in work_units:
            # Security-grade plane: no host attacker_dir mounts.
            unit = {k: v for k, v in unit.items() if k not in {"attacker_dir", "run_dir"}}
            if unit.get("persistent"):
                raise RuntimeError(
                    "security-grade campaign requires AttackerStateEnvelope for "
                    "persistent attackers; host attacker_dir is forbidden"
                )
            row = secure.execute(unit)
            rows.append(row)
            digest = row.get("execution_boundary_digest")
            if digest:
                boundary_digests.append(str(digest))
        outcome = {
            "status": "completed",
            "results": rows,
            "completed": {str(r.get("unit_id")): r for r in rows if r.get("unit_id")},
            "ledger_digest": None,
            "overrun": False,
        }
        execution_meta["launcher"] = "secure"
        execution_meta["backend_kind"] = secure.backend_kind
        execution_meta["security_grade"] = bool(secure.security_grade)
        execution_meta["execution_boundary_digests"] = boundary_digests
    else:
        launcher = LocalLauncher(
            store=store,
            run_dir=run_dir,
            budget=spec.budget,
            max_workers=max_workers,
            use_processes=use_processes,
        )
        work_units = _order_units_for_persistence(_build_work_units(spec, run_dir=run_dir))
        # Persistent attackers share filesystem checkpoints — serialize those units.
        if any(u.get("persistent") for u in work_units):
            launcher.max_workers = 1
        outcome = await launcher.run_all(work_units, executor_fn=execute_work_unit)
        execution_meta["launcher"] = "local_dev"
        execution_meta["security_grade"] = False

    # Freeze learning attackers after the attack plane completes (holdout seal).
    from verifierlab.attacks.runtime import AttackerStore

    frozen_dirs: set[str] = set()
    for unit in work_units:
        adir = unit.get("attacker_dir")
        if adir and adir not in frozen_dirs:
            AttackerStore(Path(adir)).freeze()
            frozen_dirs.add(adir)

    rows = list(outcome["results"])
    verifier_profile_digest = _single_verifier_profile_digest(rows)

    work_digests: list[str] = []
    failed_count = 0
    for row in rows:
        if row.get("error") and "trajectory" not in row:
            failed_count += 1
            if row.get("unit_digest") or row.get("cas_digest"):
                work_digests.append(str(row.get("cas_digest") or row.get("unit_digest")))
            continue
        # Attack artifacts only — no gt_valid, no vault commits, no exploits.
        if row.get("gt_valid") is not None:
            raise RuntimeError("integrity violation: gt_valid present on attack artifact")
        if row.get("error"):
            failed_count += 1
        digest = row.get("cas_digest") or row.get("unit_digest")
        if digest:
            work_digests.append(str(digest))
    outcome.pop("results", None)

    status = outcome["status"]
    if failed_count and status == "completed":
        status = "completed_with_failures"

    attack = AttackRunManifest(
        run_id=run_id,
        campaign_digest=campaign_digest,
        status=status,
        work_unit_digests=work_digests,
        ledger_digest=outcome.get("ledger_digest"),
        overrun=bool(outcome.get("overrun")),
        prev_digest=None,
        metadata={
            "campaign_name": spec.name,
            "access_model": spec.access_model.value,
            "seed": spec.seed,
            "completed_units": len(outcome.get("completed") or {}),
            "failed_units": failed_count,
            "exploit_count": 0,
            "lifecycle": LifecycleState.ATTACK.value,
            "gt_evaluated_on": None,
            "plane": "attack",
            "verifier_profile_digest": verifier_profile_digest,
            "verifier_profile_digest_source": "worker_consensus",
            "stats_plan": spec.stats_plan.model_dump(mode="json"),
            "attack_started_at": attack_started_at,
            "budget": spec.budget.model_dump(mode="json"),
            **execution_meta,
        },
    )
    tip_payload = attack.model_dump(mode="json")
    tip_digest, index = write_tip_index(
        run_dir,
        store=store,
        tip_payload=tip_payload,
        tip_kind="attack_run",
        lifecycle=LifecycleState.ATTACK,
        run_id=run_id,
        prev_chain=[],
    )

    if build_report_on_complete and labels_released(run_dir):
        from verifierlab.reports.html import build_report

        build_report(
            run_dir,
            access_model=spec.access_model.value,
            run_id=run_id,
            run_digest=tip_digest,
        )

    # Compatibility wrapper for CampaignRunResult.manifest
    manifest = RunManifest(
        run_id=run_id,
        campaign_digest=campaign_digest,
        status=status,
        work_unit_digests=work_digests,
        ledger_digest=outcome.get("ledger_digest"),
        overrun=bool(outcome.get("overrun")),
        metadata=dict(index.get("metadata") or {}),
    )

    elapsed = time.perf_counter() - started
    return CampaignRunResult(
        run_id=run_id,
        run_digest=tip_digest,
        manifest=manifest,
        run_dir=run_dir,
        elapsed_s=elapsed,
    )


def _digest_tree(path: Path) -> str:
    """Digest sorted relative paths + file digests under ``path``.

    Missing or empty trees yield a stable empty-tree digest (never ``None``)
    so sealed manifests remain complete and digest-stable (VALAB-05).
    """
    if not path.is_dir():
        return digest_of({"tree": str(path.as_posix()), "entries": []})
    rows: list[dict[str, str]] = []
    for child in sorted(path.rglob("*")):
        if child.is_file():
            rel = child.relative_to(path).as_posix()
            rows.append({"path": rel, "sha256": sha256_digest(child.read_bytes())})
    return digest_of({"tree": path.as_posix(), "entries": rows})


def freeze_run(run_dir: Path, *, store: ContentAddressedStore | None = None) -> FreezeRecord:
    """Freeze a completed run: seal vault, append FreezeRecord, write SealedRunManifest."""
    run_dir = Path(run_dir)
    index = read_tip_index(run_dir)
    current = lifecycle_of(run_dir)
    assert_transition(current, LifecycleState.FREEZE)

    ws = run_dir.parent.parent
    if store is None:
        store = ContentAddressedStore(ws / "store")

    vault = LabelVault.open(run_dir / "vault", workspace=ws)
    vault.freeze(role="coordinator")
    commitments = [p.stem for p in (run_dir / "vault" / "commitments").glob("*.json")]
    prev = str(index.get("tip_digest") or index.get("run_digest") or "")
    freeze = FreezeRecord(
        freeze_id=f"freeze-{index['run_id']}",
        run_id=str(index["run_id"]),
        campaign_digest=str(index.get("campaign_digest") or ""),
        prev_digest=prev,
        commitment_digests=sorted(commitments),
        frozen_at=time.time(),
        metadata={"attack_tip": prev},
    )
    tip_payload = freeze.model_dump(mode="json")
    tip_digest, _ = write_tip_index(
        run_dir,
        store=store,
        tip_payload=tip_payload,
        tip_kind="freeze",
        lifecycle=LifecycleState.FREEZE,
        run_id=str(index["run_id"]),
        prev_chain=list(index.get("chain") or [prev]),
        extra_index={
            "campaign_digest": index.get("campaign_digest"),
            "work_unit_digests": index.get("work_unit_digests") or [],
            "ledger_digest": index.get("ledger_digest"),
            "status": index.get("status"),
            "overrun": index.get("overrun", False),
            "metadata": dict(index.get("metadata") or {}),
        },
    )
    (run_dir / "freeze.json").write_text(
        json.dumps({**tip_payload, "content_digest": tip_digest}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    # VALAB-05 / WP-04: seal the run bundle (vault tip digest, not plaintext labels).
    meta = dict(index.get("metadata") or {})
    campaign_digest = str(index.get("campaign_digest") or "")
    attack_digests = sorted(str(d) for d in (index.get("work_unit_digests") or []))
    vault_tip = vault.audit_tip
    work_unit_cas = _digest_tree(run_dir / "work_units")

    split_digest = None
    public_split_digest = None
    custody_digest = None
    split_path = run_dir / "splits" / "manifest.json"
    if split_path.is_file():
        split_body = json.loads(split_path.read_text(encoding="utf-8"))
        split_digest = str(split_body.get("content_digest") or digest_of(split_body))
        public_split_digest = split_body.get("public_split_view_digest")
        custody_digest = split_body.get("custody_digest")
    pub_path = run_dir / "splits" / "public_view.json"
    if pub_path.is_file() and not public_split_digest:
        pub = json.loads(pub_path.read_text(encoding="utf-8"))
        public_split_digest = str(pub.get("content_digest") or digest_of(pub))
    custody_path = run_dir / "custody" / "hidden_split.json"
    if custody_path.is_file() and not custody_digest:
        custody = json.loads(custody_path.read_text(encoding="utf-8"))
        custody_digest = str(custody.get("content_digest") or digest_of(custody))

    attacker_ids: list[str] = []
    attackers_dir = run_dir / "attackers"
    if attackers_dir.is_dir():
        for path in sorted(attackers_dir.rglob("*")):
            if path.is_file():
                attacker_ids.append(sha256_digest(path.read_bytes()))

    state_heads: list[str] = []
    for key in ("attacker_state_heads", "attack_state_head_digests"):
        raw = meta.get(key)
        if isinstance(raw, list):
            state_heads.extend(str(x) for x in raw)

    boundary_digests = [str(d) for d in (meta.get("execution_boundary_digests") or []) if d]
    public_commitments = sorted(str(c) for c in commitments)

    prereg_digest = None
    if isinstance(meta.get("stats_plan"), dict):
        prereg = meta["stats_plan"].get("preregistration")
        if isinstance(prereg, dict):
            prereg_digest = digest_of(prereg)
    # Prefer CAS campaign preregistration when present.
    if campaign_digest:
        try:
            camp = store.get_json(campaign_digest)
            stats = camp.get("stats_plan") or {}
            if isinstance(stats, dict) and stats.get("preregistration"):
                prereg_digest = digest_of(stats["preregistration"])
        except Exception:
            pass

    from verifierlab.campaigns.registrations import (
        FreezeSealBundle,
        build_chronology_evidence,
        list_registration_digests,
    )

    research_regs = list_registration_digests(run_dir)
    chronology = build_chronology_evidence(
        run_dir,
        run_id=str(index["run_id"]),
        attack_started_at=meta.get("attack_started_at"),
        sealed_at=time.time(),
    )
    chronology_digest = chronology.content_digest()
    (run_dir / "chronology.json").write_text(
        json.dumps(
            {**chronology.model_dump(mode="json"), "content_digest": chronology_digest},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    bundle = FreezeSealBundle(
        run_id=str(index["run_id"]),
        campaign_digest=campaign_digest or ("0" * 64),
        split_manifest_digest=split_digest,
        public_split_view_digest=public_split_digest,
        custody_digest=custody_digest,
        verifier_profile_digest=meta.get("verifier_profile_digest")
        or meta.get("verifier_digest")
        or meta.get("profile_digest"),
        attacker_identity_digests=sorted(set(attacker_ids)),
        budget_digest=digest_of(meta.get("budget") or index.get("ledger_digest") or {}),
        work_unit_cas_digest=work_unit_cas,
        execution_boundary_digests=boundary_digests,
        attack_state_head_digests=sorted(set(state_heads)),
        public_commitment_digests=public_commitments,
        preregistration_digest=prereg_digest,
        research_registration_digests=research_regs,
        chronology_digest=chronology_digest,
        sealed_at=time.time(),
        metadata={"freeze_id": freeze.freeze_id},
    )
    bundle_digest = bundle.content_digest()
    store.put_json(bundle.model_dump(mode="json"))
    (run_dir / "freeze_seal_bundle.json").write_text(
        json.dumps(
            {**bundle.model_dump(mode="json"), "content_digest": bundle_digest},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    sealed = SealedRunManifest(
        seal_id=f"seal-{index['run_id']}",
        run_id=str(index["run_id"]),
        freeze_digest=tip_digest,
        campaign_digest=campaign_digest,
        verifier_digest=meta.get("verifier_profile_digest")
        or meta.get("verifier_digest")
        or meta.get("profile_digest"),
        attack_digests=attack_digests,
        environment_fingerprint=meta.get("environment_fingerprint")
        or digest_of({"env": meta.get("environment") or meta.get("environment_kind")}),
        random_seeds={
            "campaign_seed": meta.get("seed"),
            "split_seed": meta.get("split_seed"),
        },
        budget_digest=digest_of(meta.get("budget") or index.get("ledger_digest") or {}),
        inputs_digest=work_unit_cas,
        outputs_digest=_digest_tree(run_dir / "vault" / "commitments"),
        vault_tip_digest=vault_tip,
        report_config_digest=digest_of(meta.get("stats_plan") or {}),
        split_manifest_digest=split_digest,
        public_split_view_digest=public_split_digest,
        custody_digest=custody_digest,
        attacker_identity_digests=sorted(set(attacker_ids)),
        execution_boundary_digests=boundary_digests,
        attack_state_head_digests=sorted(set(state_heads)),
        public_commitment_digests=public_commitments,
        preregistration_digest=prereg_digest,
        research_registration_digests=research_regs,
        chronology_digest=chronology_digest,
        freeze_seal_bundle_digest=bundle_digest,
        sealed_at=time.time(),
        metadata={
            "freeze_id": freeze.freeze_id,
            "execution_mode": meta.get("execution_mode"),
            "execution_policy_digest": meta.get("execution_policy_digest"),
            "execution_boundary_digests": list(meta.get("execution_boundary_digests") or []),
            "isolation_probe_report_digest": meta.get("isolation_probe_report_digest"),
            "security_grade": meta.get("security_grade", False),
            "backend_kind": meta.get("backend_kind"),
            "work_unit_cas_digest": work_unit_cas,
        },
    )
    sealed_payload = sealed.model_dump(mode="json")
    sealed_digest = sealed.content_digest()
    store.put_json(sealed_payload)
    (run_dir / "sealed_run.json").write_text(
        json.dumps({**sealed_payload, "content_digest": sealed_digest}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    assert_run_sealed_immutable(run_dir)

    # Capture immutable attack-plane tip for post-freeze mutation checks.
    (run_dir / "attack_plane_lock.json").write_text(
        json.dumps(
            {
                "work_unit_cas_digest": work_unit_cas,
                "sealed_run_digest": sealed_digest,
                "freeze_digest": tip_digest,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return freeze


def adjudicate_campaign(
    run_dir: Path,
    *,
    campaign_path: Path | str | None = None,
    store: ContentAddressedStore | None = None,
) -> Any:
    """CLI/engine entry: adjudicate after freeze."""
    run_dir = Path(run_dir)
    index = read_tip_index(run_dir)
    spec: CampaignSpec | None = None
    if campaign_path is not None:
        spec, _ = load_campaign(campaign_path)
    else:
        # Reload campaign from CAS.
        ws = run_dir.parent.parent
        store = store or ContentAddressedStore(ws / "store")
        dig = index.get("campaign_digest")
        if dig:
            raw = store.get_json(str(dig))
            spec = CampaignSpec.model_validate(raw)
    if spec is None:
        raise ValueError("cannot resolve campaign spec for adjudication")
    return adjudicate_run(run_dir, spec=spec, store=store, workspace=run_dir.parent.parent)


def release_labels(
    run_dir: Path, *, store: ContentAddressedStore | None = None
) -> AdjudicationReleaseRecord:
    """Release sealed labels and append AdjudicationReleaseRecord tip."""
    run_dir = Path(run_dir)
    index = read_tip_index(run_dir)
    current = lifecycle_of(run_dir)
    assert_transition(current, LifecycleState.LABEL_RELEASE)

    ws = run_dir.parent.parent
    if store is None:
        store = ContentAddressedStore(ws / "store")

    # Post-freeze attack plane must remain immutable before label release.
    lock_path = run_dir / "attack_plane_lock.json"
    if lock_path.is_file():
        from verifierlab.campaigns.registrations import assert_attack_plane_immutable

        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        assert_attack_plane_immutable(
            run_dir, expected_work_unit_digest=str(lock["work_unit_cas_digest"])
        )

    vault = LabelVault.open(run_dir / "vault", workspace=ws)
    vault.release(role="coordinator")

    # Materialize gt_valid into analysis copies (attack work_units stay immutable).
    analysis_wu = run_dir / "analysis" / "work_units"
    analysis_wu.mkdir(parents=True, exist_ok=True)
    adj_dir = run_dir / "adjudications"
    commitments: list[str] = []
    for adj_path in sorted(adj_dir.glob("*.json")) if adj_dir.is_dir() else []:
        adj = json.loads(adj_path.read_text(encoding="utf-8"))
        unit_id = adj.get("unit_id")
        src = run_dir / "work_units" / f"{unit_id}.json"
        if not src.is_file():
            continue
        row = json.loads(src.read_text(encoding="utf-8"))
        row["gt_valid"] = adj.get("gt_valid")
        row["exploit"] = adj.get("exploit")
        row["vault_commitment"] = adj.get("vault_commitment")
        row["labels_released"] = True
        (analysis_wu / f"{unit_id}.json").write_text(
            json.dumps(row, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if adj.get("vault_commitment"):
            commitments.append(str(adj["vault_commitment"]))

    prev = str(index.get("tip_digest") or index.get("run_digest") or "")
    release = AdjudicationReleaseRecord(
        release_id=f"release-{index['run_id']}",
        run_id=str(index["run_id"]),
        prev_digest=prev,
        adjudication_digest=prev if index.get("tip_kind") == "adjudication" else None,
        released_at=time.time(),
        commitment_digests=sorted(commitments),
        metadata={"analysis_work_units": str(analysis_wu)},
    )
    tip_payload = release.model_dump(mode="json")
    tip_digest, _ = write_tip_index(
        run_dir,
        store=store,
        tip_payload=tip_payload,
        tip_kind="adjudication_release",
        lifecycle=LifecycleState.LABEL_RELEASE,
        run_id=str(index["run_id"]),
        prev_chain=list(index.get("chain") or [prev]),
        extra_index={
            "campaign_digest": index.get("campaign_digest"),
            "work_unit_digests": index.get("work_unit_digests") or [],
            "ledger_digest": index.get("ledger_digest"),
            "status": index.get("status"),
            "overrun": index.get("overrun", False),
            "metadata": {
                **dict(index.get("metadata") or {}),
                "labels_released": True,
            },
        },
    )
    (run_dir / "release.json").write_text(
        json.dumps({**tip_payload, "content_digest": tip_digest}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    # WP-04: LabelReleaseReceipt binds exact sealed run + label set.
    from verifierlab.labels.release import LabelReleaseReceipt, label_set_digest

    sealed_path = run_dir / "sealed_run.json"
    sealed_digest = ""
    freeze_digest = ""
    if sealed_path.is_file():
        sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
        sealed_digest = str(sealed.get("content_digest") or "")
        freeze_digest = str(sealed.get("freeze_digest") or "")
    freeze_path = run_dir / "freeze.json"
    if not freeze_digest and freeze_path.is_file():
        freeze_digest = str(
            json.loads(freeze_path.read_text(encoding="utf-8")).get("content_digest") or ""
        )
    if len(sealed_digest) == 64 and len(freeze_digest) == 64:
        receipt = LabelReleaseReceipt(
            receipt_id=f"label-receipt-{index['run_id']}",
            run_id=str(index["run_id"]),
            sealed_run_digest=sealed_digest,
            freeze_digest=freeze_digest,
            adjudication_digest=release.adjudication_digest,
            label_set_digest=label_set_digest(sorted(commitments)),
            commitment_digests=sorted(commitments),
            released_at=float(release.released_at),
            chronology={
                "sealed_run_digest": sealed_digest,
                "release_tip_digest": tip_digest,
            },
            metadata={"analysis_work_units": str(analysis_wu)},
        )
        receipt_digest = receipt.content_digest()
        store.put_json(receipt.model_dump(mode="json"))
        (run_dir / "label_release_receipt.json").write_text(
            json.dumps(
                {**receipt.model_dump(mode="json"), "content_digest": receipt_digest},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    return release


def run_campaign(
    path: Path | str,
    *,
    workspace: Path | None = None,
    run_id: str | None = None,
    max_workers: int = 2,
    use_processes: bool = True,
) -> CampaignRunResult:
    spec, _diags = load_campaign(path)
    ws = workspace or default_workspace()
    return asyncio.run(
        run_campaign_async(
            spec,
            workspace=ws,
            run_id=run_id,
            max_workers=max_workers,
            use_processes=use_processes,
        )
    )


# Re-export for callers that imported resolve helpers from engine.
_resolve_is_valid = resolve_is_valid
