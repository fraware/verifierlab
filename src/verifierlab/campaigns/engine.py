"""Campaign lifecycle orchestration."""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from verifierlab.artifacts.cas import ContentAddressedStore
from verifierlab.artifacts.records import RunManifest
from verifierlab.attacks.registry import create_strategy
from verifierlab.campaigns.episode import enrich_episode_with_gt, run_episode
from verifierlab.campaigns.lifecycle import LifecycleState, assert_transition
from verifierlab.config.campaign import AttackSpec, CampaignSpec, load_campaign
from verifierlab.execution.local import LocalLauncher
from verifierlab.labels.freeze import FreezeRecord
from verifierlab.labels.vault import LabelVault
from verifierlab.plugins.loader import load_object
from verifierlab.reports.html import build_report


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
    marker = root / "README.txt"
    if not marker.exists() or force:
        marker.write_text(
            "VerifierLab local workspace\nstore/ — content-addressed artifacts\nruns/ — campaign run bundles\n",
            encoding="utf-8",
        )
    return root


def _resolve_is_valid(spec: CampaignSpec) -> Callable[[dict[str, Any]], bool] | None:
    provider = spec.ground_truth.provider
    # Prefer module-level helpers for planted packs.
    candidates = []
    if ":" in provider:
        mod = provider.split(":", 1)[0]
        candidates.append(f"{mod}:refund_is_valid")
        candidates.append(f"{mod}:_is_valid")
    if spec.environment.kind == "fake" or "fake" in spec.environment.ref:
        candidates.append("verifierlab.targets.fake:PlantedOracleGroundTruth._is_valid")
    for ref in candidates:
        try:
            fn = load_object(ref)
            if callable(fn):
                return fn  # type: ignore[no-any-return]
        except Exception:
            continue
    # Fallback: instantiate GT and use private static if present.
    try:
        gt_cls = load_object(provider) if ":" in provider or "." in provider else None
        if gt_cls is not None and hasattr(gt_cls, "_is_valid"):
            return gt_cls._is_valid  # type: ignore[no-any-return]
    except Exception:
        return None
    return None


def _build_work_units(spec: CampaignSpec) -> list[dict[str, Any]]:
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
    units: list[dict[str, Any]] = []
    idx = 0
    max_steps = int(spec.environment.config.get("max_steps", 3))
    for attack in attacks:
        for _ in range(attack.units):
            unit_id = f"{spec.name}-{attack.name}-{spec.seed}-{idx:04d}"
            units.append(
                {
                    "unit_id": unit_id,
                    "seed": spec.seed + idx,
                    "unit_index": idx,
                    "max_steps": max_steps,
                    "campaign_name": spec.name,
                    "access_model": spec.access_model.value,
                    "strategy": attack.strategy,
                    "strategy_config": dict(attack.config),
                    "cohort": attack.cohort,
                    "environment_ref": spec.environment.ref,
                    "environment_kind": spec.environment.kind,
                    "environment_config": dict(spec.environment.config),
                    "verifier_ref": spec.verifier.ref,
                    "ground_truth_ref": spec.ground_truth.provider,
                }
            )
            # Propagate cohort into strategy config so strategies that stamp
            # action metadata stay consistent with campaign stratification.
            units[-1]["strategy_config"] = {
                **units[-1]["strategy_config"],
                "cohort": attack.cohort,
            }
            idx += 1
    return units


def _make_executor_fn(spec: CampaignSpec) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """Build a worker entry point that never evaluates ground truth."""

    def _execute(payload: dict[str, Any]) -> dict[str, Any]:
        env_kind = payload.get("environment_kind") or spec.environment.kind
        max_steps = int(payload.get("max_steps", 3))
        if env_kind == "fake":
            from verifierlab.targets.fake import (
                FakeEnvironment,
                PlantedOracleGroundTruth,
                fake_refund_verifier,
            )

            env = FakeEnvironment(max_steps=max_steps)
            gt: Any = PlantedOracleGroundTruth()
            verifier = fake_refund_verifier
        else:
            env_cls = load_object(payload["environment_ref"])
            env_cfg = dict(payload.get("environment_config") or {})
            env_cfg.pop("max_steps", None)
            env = env_cls(max_steps=max_steps, **env_cfg) if env_cfg else env_cls(max_steps=max_steps)
            gt_cls = load_object(payload["ground_truth_ref"])
            gt = gt_cls() if isinstance(gt_cls, type) else gt_cls
            verifier = load_object(payload["verifier_ref"])

        strategy = create_strategy(payload["strategy"], dict(payload.get("strategy_config") or {}))
        return run_episode(
            unit_id=payload["unit_id"],
            seed=int(payload["seed"]),
            max_steps=max_steps,
            env=env,
            verifier=verifier,
            gt=gt,
            strategy=strategy,
            strategy_config=dict(payload.get("strategy_config") or {}),
            cohort=str(payload.get("cohort") or "optimized"),
            access_model=str(payload.get("access_model") or spec.access_model.value),
            strategy_name=str(payload["strategy"]),
        )

    return _execute


async def run_campaign_async(
    spec: CampaignSpec,
    *,
    workspace: Path,
    run_id: str | None = None,
    max_workers: int = 2,
    resume: bool = True,
    use_processes: bool = True,
    build_report_on_complete: bool = True,
) -> CampaignRunResult:
    started = time.perf_counter()
    workspace = init_workspace(workspace)
    store = ContentAddressedStore(workspace / "store")
    campaign_digest = store.put_json(spec.model_dump(mode="json"))

    run_id = run_id or f"run-{uuid.uuid4().hex[:12]}"
    run_dir = workspace / "runs" / run_id
    if run_dir.exists() and not resume:
        raise FileExistsError(f"run directory already exists: {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=True)

    vault = LabelVault(run_dir / "vault")
    launcher = LocalLauncher(
        store=store,
        run_dir=run_dir,
        budget=spec.budget,
        max_workers=max_workers,
        use_processes=use_processes,
    )
    work_units = _build_work_units(spec)
    executor_fn = _make_executor_fn(spec)
    outcome = await launcher.run_all(work_units, executor_fn=executor_fn)

    # Coordinator-only GT enrichment (workers never see labels / gt_valid).
    is_valid = _resolve_is_valid(spec)
    work_digests: list[str] = []
    exploit_count = 0
    failed_count = 0
    for row in outcome["results"]:
        if row.get("error") and "trajectory" not in row:
            failed_count += 1
            if row.get("unit_digest") or row.get("cas_digest"):
                work_digests.append(str(row.get("cas_digest") or row.get("unit_digest")))
            continue
        if is_valid is not None and row.get("trajectory") is not None:
            row = enrich_episode_with_gt(
                row,
                is_valid=is_valid,
                cohort=str(row.get("cohort") or "optimized"),
                access_model=spec.access_model.value,
            )
            # Persist enriched coordinator record (idempotent overwrite).
            launcher.persist_unit(row)
        traj = row.get("trajectory") or {}
        gt_valid = row.get("gt_valid")
        if row.get("commitment") and gt_valid is not None and not vault.frozen:
            with contextlib.suppress(RuntimeError):
                vault.commit(traj, {"valid": gt_valid, "reason": "coordinator"})
        if row.get("exploit"):
            exploit_count += 1
        if row.get("error"):
            failed_count += 1
        digest = row.get("cas_digest") or row.get("unit_digest")
        if digest:
            work_digests.append(str(digest))
    # Drop in-memory trajectories; report rebuild streams from work_units/.
    outcome.pop("results", None)

    status = outcome["status"]
    if failed_count and status == "completed":
        status = "completed_with_failures"
    manifest = RunManifest(
        run_id=run_id,
        campaign_digest=campaign_digest,
        status=status,
        work_unit_digests=work_digests,
        ledger_digest=outcome.get("ledger_digest"),
        overrun=bool(outcome.get("overrun")),
        metadata={
            "campaign_name": spec.name,
            "access_model": spec.access_model.value,
            "seed": spec.seed,
            "completed_units": len(outcome.get("completed") or {}),
            "failed_units": failed_count,
            "exploit_count": exploit_count,
            "lifecycle": LifecycleState.ATTACK.value,
            "gt_evaluated_on": "coordinator",
        },
    )
    manifest_digest = store.put_json(manifest.model_dump(mode="json"))
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                **manifest.model_dump(mode="json"),
                "run_digest": manifest_digest,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    if build_report_on_complete and status in {
        "completed",
        "budget_exceeded",
        "completed_with_failures",
    }:
        # Stream from disk — do not re-materialize all trajectories in RAM.
        build_report(
            run_dir,
            access_model=spec.access_model.value,
            run_id=run_id,
            run_digest=manifest_digest,
        )


    elapsed = time.perf_counter() - started
    return CampaignRunResult(
        run_id=run_id,
        run_digest=manifest_digest,
        manifest=manifest,
        run_dir=run_dir,
        elapsed_s=elapsed,
    )


def freeze_run(run_dir: Path, *, store: ContentAddressedStore | None = None) -> FreezeRecord:
    """Freeze a completed run: seal vault and write FreezeRecord."""
    run_dir = Path(run_dir)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    current = (manifest.get("metadata") or {}).get("lifecycle", LifecycleState.ATTACK.value)
    assert_transition(current, LifecycleState.FREEZE)
    vault = LabelVault(run_dir / "vault")
    vault.freeze()
    commitments = [p.stem for p in (run_dir / "vault" / "commitments").glob("*.json")]
    freeze = FreezeRecord(
        freeze_id=f"freeze-{manifest['run_id']}",
        run_id=manifest["run_id"],
        campaign_digest=manifest["campaign_digest"],
        commitment_digests=sorted(commitments),
        frozen_at=time.time(),
        metadata={"run_digest": manifest.get("run_digest")},
    )
    payload = freeze.model_dump(mode="json")
    (run_dir / "freeze.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if store is not None:
        store.put_json(payload)
    manifest["metadata"] = {
        **(manifest.get("metadata") or {}),
        "lifecycle": LifecycleState.FREEZE.value,
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return freeze


def release_labels(run_dir: Path) -> None:
    run_dir = Path(run_dir)
    manifest_path = run_dir / "manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        current = (manifest.get("metadata") or {}).get("lifecycle", LifecycleState.FREEZE.value)
        assert_transition(current, LifecycleState.LABEL_RELEASE)
        manifest["metadata"] = {
            **(manifest.get("metadata") or {}),
            "lifecycle": LifecycleState.LABEL_RELEASE.value,
        }
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    vault = LabelVault(run_dir / "vault")
    vault.release()



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
