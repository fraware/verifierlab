"""Split governance: materialize train/holdout manifests (VAL-R11 / VALAB-06)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from verifierlab.artifacts.canonical import digest_of
from verifierlab.artifacts.records import LabelTier
from verifierlab.config.campaign import CampaignSpec, SplitSpec

HOLDOUT_NAMES = frozenset({"holdout", "test", "eval", "evaluation", "private_holdout"})

_DEFAULT_TIER_BY_NAME: dict[str, LabelTier] = {
    "train": LabelTier.DEVELOPMENT,
    "dev": LabelTier.DEVELOPMENT,
    "development": LabelTier.DEVELOPMENT,
    "regression": LabelTier.REGRESSION,
    "release": LabelTier.RELEASE,
    "holdout": LabelTier.RELEASE,
    "test": LabelTier.RELEASE,
    "eval": LabelTier.RELEASE,
    "evaluation": LabelTier.RELEASE,
    "private_holdout": LabelTier.PRIVATE_HOLDOUT,
    "private": LabelTier.PRIVATE_HOLDOUT,
}


def is_holdout_split(name: str) -> bool:
    return str(name).strip().lower() in HOLDOUT_NAMES


def resolve_label_tier(split: SplitSpec | str) -> LabelTier:
    """Resolve the LabelTier for a split name or SplitSpec."""
    if isinstance(split, SplitSpec):
        if split.label_tier:
            return LabelTier(split.label_tier)
        name = split.name
    else:
        name = split
    key = str(name).strip().lower()
    return _DEFAULT_TIER_BY_NAME.get(key, LabelTier.DEVELOPMENT)


def assign_split_indices(
    n_units: int,
    splits: list[SplitSpec],
    *,
    seed: int = 0,
) -> list[str]:
    """Assign each unit index to a split name.

    When ``splits`` is empty, every unit is assigned to ``train``.
    Fractions are converted to counts (last split absorbs remainder).
    Named holdout splits (holdout/test/eval) mark evaluation units.
    """
    if n_units <= 0:
        return []
    if not splits:
        return ["train"] * n_units

    counts: list[tuple[str, int]] = []
    remaining = n_units
    for i, split in enumerate(splits):
        if split.count is not None:
            c = min(int(split.count), remaining)
        else:
            frac = float(split.fraction or 0.0)
            c = remaining if i == len(splits) - 1 else min(remaining, round(frac * n_units))
        counts.append((split.name, c))
        remaining -= c
    if remaining > 0 and counts:
        name, c = counts[-1]
        counts[-1] = (name, c + remaining)

    # Deterministic shuffle of indices then fill by split order.
    import random

    rng = random.Random(seed)
    indices = list(range(n_units))
    rng.shuffle(indices)
    assignment = ["train"] * n_units
    cursor = 0
    for name, c in counts:
        for _ in range(c):
            if cursor >= n_units:
                break
            assignment[indices[cursor]] = name
            cursor += 1
    return assignment


def materialize_split_manifest(
    spec: CampaignSpec,
    *,
    unit_ids: list[str],
    run_dir: Path | None = None,
) -> dict[str, Any]:
    """Build and optionally persist a split manifest for the campaign run."""
    n = len(unit_ids)
    split_seed = int(spec.seed)
    if spec.splits:
        # Prefer first split's seed when declared.
        for s in spec.splits:
            if s.seed is not None:
                split_seed = int(s.seed)
                break
    names = assign_split_indices(n, list(spec.splits), seed=split_seed)
    split_by_name = {s.name: s for s in spec.splits}
    by_split: dict[str, list[str]] = {}
    units: list[dict[str, Any]] = []
    for unit_id, split_name in zip(unit_ids, names, strict=True):
        by_split.setdefault(split_name, []).append(unit_id)
        split_spec = split_by_name.get(split_name)
        tier = resolve_label_tier(split_spec if split_spec is not None else split_name)
        units.append(
            {
                "unit_id": unit_id,
                "split": split_name,
                "learning": not is_holdout_split(split_name),
                "label_tier": tier.value,
                "attack_visible": tier != LabelTier.PRIVATE_HOLDOUT,
            }
        )
    manifest = {
        "schema_version": "2",
        "campaign": spec.name,
        "seed": split_seed,
        "splits_declared": [s.model_dump(mode="json") for s in spec.splits],
        "by_split": {k: sorted(v) for k, v in sorted(by_split.items())},
        "units": units,
    }
    manifest["content_digest"] = digest_of(
        {k: v for k, v in manifest.items() if k != "content_digest"}
    )
    if run_dir is not None:
        path = Path(run_dir) / "splits" / "manifest.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def split_lookup(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Map unit_id -> {split, learning, label_tier, attack_visible}."""
    return {
        str(u["unit_id"]): {
            "split": u["split"],
            "learning": bool(u["learning"]),
            "label_tier": u.get("label_tier") or LabelTier.DEVELOPMENT.value,
            "attack_visible": bool(u.get("attack_visible", True)),
        }
        for u in manifest.get("units") or []
    }
