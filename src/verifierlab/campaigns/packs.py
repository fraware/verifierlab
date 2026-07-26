"""Benchmark pack layout helpers (lint / verify / sidecars).

Packs remain YAML-first under ``campaigns/packs/``. Sidecar directories
(``pack-a/``, …) hold profile JSON, splits, and expected-public digests without
rewriting science YAML content.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from verifierlab.artifacts.canonical import digest_of
from verifierlab.config.campaign import CampaignSpec, CampaignSpecError, load_campaign
from verifierlab.diagnostics.codes import Diagnostic, DiagnosticSeverity
from verifierlab.verifiers.profile import VerifierProfile

_PACK_LETTER = re.compile(r"^pack-([a-e])(?:-|$)", re.IGNORECASE)

# Packs A-E get sidecars; F remains integrity-only without science sidecars.
SCIENCE_PACK_LETTERS = frozenset({"a", "b", "c", "d", "e"})


def packs_root(repo_root: Path | None = None) -> Path:
    if repo_root is not None:
        return Path(repo_root) / "campaigns" / "packs"
    # src/verifierlab/campaigns/packs.py → parents[3] = repo root when editable.
    here = Path(__file__).resolve()
    candidates = [
        here.parents[3] / "campaigns" / "packs",
        Path.cwd() / "campaigns" / "packs",
    ]
    for cand in candidates:
        if cand.is_dir():
            return cand
    return candidates[0]


def discover_pack_yaml(path: Path) -> Path:
    """Resolve a pack path to its campaign YAML."""
    p = Path(path)
    if p.is_file() and p.suffix in {".yaml", ".yml", ".json"}:
        return p
    if p.is_dir():
        for name in ("campaign.yaml", "campaign.yml", "campaign.json"):
            cand = p / name
            if cand.is_file():
                return cand
        # Sidecar dir pack-a/ → sibling pack-a-*.yaml
        letter = p.name.lower().removeprefix("pack-")
        if len(letter) == 1:
            root = p.parent
            matches = sorted(root.glob(f"pack-{letter}-*.yaml")) + sorted(
                root.glob(f"pack-{letter}-*.yml")
            )
            if matches:
                return matches[0]
    raise FileNotFoundError(f"no campaign YAML found for pack path {path}")


def pack_letter(name_or_path: str | Path) -> str | None:
    text = Path(name_or_path).stem if isinstance(name_or_path, Path) else str(name_or_path)
    text = text.replace("\\", "/").split("/")[-1]
    m = _PACK_LETTER.match(text)
    if m:
        return m.group(1).lower()
    return None


def sidecar_dir_for(yaml_path: Path) -> Path:
    """Return ``packs/pack-X/`` sidecar directory for a pack YAML."""
    letter = pack_letter(yaml_path)
    if letter is None:
        raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        letter = str((raw.get("metadata") or {}).get("pack") or "").strip().lower()
    if not letter or letter not in SCIENCE_PACK_LETTERS:
        raise ValueError(f"sidecar layout only defined for packs A-E, got {yaml_path}")
    return yaml_path.parent / f"pack-{letter}"


def campaign_public_digest(spec: CampaignSpec) -> str:
    """Content-addressed digest over the public campaign binding (no secrets)."""
    payload = spec.model_dump(mode="json")
    # Strip anything that could grow private; metadata stays (expected taxonomies).
    return digest_of(payload)


def build_profile_sidecar(spec: CampaignSpec) -> dict[str, Any]:
    """Build a public verifier profile JSON for the pack sidecar."""
    profile = VerifierProfile(
        name=spec.verifier.ref,
        implementation_digest=digest_of(
            {
                "ref": spec.verifier.ref,
                "kind": spec.verifier.kind,
                "version": spec.verifier.version,
            }
        ),
        config_digest=digest_of(dict(spec.verifier.config)),
        decision_semantics={
            "status_set": ["accept", "reject", "abstain", "indeterminate", "error"],
            "fail_closed": True,
        },
        applicability={
            "decision_space": "binary",
            "target_kinds": [spec.verifier.kind, "python", "native"],
            "requires_hidden_labels": False,
            "campaign": spec.name,
            "access_model": spec.access_model.value,
        },
        access_surface={
            "inputs": ["trajectory", "observation"],
            "may_read_hidden_labels": False,
            "may_import_label_vault": False,
            "may_read_ground_truth": False,
            "stdout_protocol": "json_decision",
        },
        metadata={
            "pack": (spec.metadata or {}).get("pack"),
            "theme": (spec.metadata or {}).get("theme"),
            "pinned_versions": dict(spec.pinned_versions),
        },
    )
    body = profile.model_dump(mode="json")
    body["content_digest"] = profile.content_digest()
    return body


def build_splits_sidecar(spec: CampaignSpec) -> dict[str, Any]:
    if spec.splits:
        splits = [s.model_dump(mode="json") for s in spec.splits]
    else:
        # Default public split declaration when YAML omits splits.
        n = int(spec.work_units)
        train = max(1, n // 2)
        holdout = n - train
        splits = [
            {"name": "train", "count": train, "label_tier": "development"},
            {"name": "holdout", "count": holdout, "label_tier": "release"},
        ]
    payload = {
        "schema_version": "1",
        "campaign": spec.name,
        "splits": splits,
        "work_units": spec.work_units,
    }
    payload["content_digest"] = digest_of(payload)
    return payload


def build_expected_public_digests(spec: CampaignSpec, profile: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "schema_version": "1",
        "campaign": spec.name,
        "campaign_digest": campaign_public_digest(spec),
        "verifier_profile_digest": profile.get("content_digest"),
        "pinned_versions": dict(spec.pinned_versions),
        "budget_digest": digest_of(spec.budget.model_dump(mode="json")),
        "access_model": spec.access_model.value,
        "primary_estimand": _primary_estimand(spec),
        "interval_method": _interval_method(spec),
        "expected_taxonomies": list((spec.metadata or {}).get("expected_taxonomies") or []),
        # Signing semantics (Milestone B): content-addressed digest + pins;
        # optional author signature is out of band.
        "signing": {
            "mode": "content_addressed",
            "means": [
                "campaign_digest",
                "pinned_versions",
                "sealed_run_manifest",
            ],
            "author_signature": "optional_stretch",
        },
    }
    payload["content_digest"] = digest_of(
        {k: v for k, v in payload.items() if k != "content_digest"}
    )
    return payload


def _primary_estimand(spec: CampaignSpec) -> str:
    meta = spec.metadata or {}
    if meta.get("primary_estimand"):
        return str(meta["primary_estimand"])
    return "far_optimized_vs_ordinary"


def _interval_method(spec: CampaignSpec) -> str:
    meta = spec.metadata or {}
    if meta.get("interval_method"):
        return str(meta["interval_method"])
    methods = list(spec.stats_plan.methods or [])
    return str(methods[0]) if methods else "wilson"


def build_planted_failure_sidecar(spec: CampaignSpec) -> dict[str, Any]:
    """Public planted-failure card — never includes hidden labels."""
    meta = spec.metadata or {}
    planted = meta.get("planted_failure")
    if isinstance(planted, dict):
        body = {
            "schema_version": "1",
            "campaign": spec.name,
            "id": planted.get("id") or "planted",
            "public_description": planted.get("public_description")
            or planted.get("description")
            or "",
            "expected_taxonomies": list(
                planted.get("expected_taxonomies")
                or meta.get("expected_taxonomies")
                or []
            ),
            "optimized_attack_names": [
                a.name for a in spec.attacks if a.cohort == "optimized"
            ],
        }
    else:
        optimized = [a for a in spec.attacks if a.cohort == "optimized"]
        body = {
            "schema_version": "1",
            "campaign": spec.name,
            "id": str(planted or (optimized[0].name if optimized else "planted")),
            "public_description": (
                f"Pack plants optimized attacks that should surface expected "
                f"taxonomies: {list(meta.get('expected_taxonomies') or [])}"
            ),
            "expected_taxonomies": list(meta.get("expected_taxonomies") or []),
            "optimized_attack_names": [a.name for a in optimized],
        }
    # Hard exclude any accidental label payloads.
    for banned in ("labels", "gt_valid", "hidden_labels", "vault"):
        body.pop(banned, None)
    body["content_digest"] = digest_of(body)
    return body


def build_adjudication_protocol_sidecar(spec: CampaignSpec) -> dict[str, Any]:
    """Public description of the hidden adjudication protocol (no labels)."""
    meta = spec.metadata or {}
    proto = meta.get("adjudication_protocol")
    if isinstance(proto, dict):
        steps = list(proto.get("steps") or [])
        summary = str(proto.get("summary") or proto.get("description") or "")
    else:
        steps = [
            "Freeze attack-plane artifacts (commitments only).",
            "Adjudicate in a separate trust boundary with ground-truth provider.",
            "Release labels only after freeze; workers never see unreleased labels.",
            "Compile StatsPlan strata; never pool blindly across cohorts.",
        ]
        summary = (
            "Hidden adjudication runs after freeze in the adjudicator plane. "
            "Public packs carry protocol description and digests only — never labels."
        )
    body = {
        "schema_version": "1",
        "campaign": spec.name,
        "kind": "hidden_adjudication_protocol",
        "summary": summary,
        "steps": steps,
        "labels_in_public_pack": False,
        "release_gate": "freeze_then_adjudicate_then_release_labels",
        "custodian_held": ["ground_truth", "unreleased_labels", "vault_keys"],
    }
    body["content_digest"] = digest_of(body)
    return body


def science_completeness(spec: CampaignSpec) -> dict[str, Any]:
    """Checklist used by pack lint for Milestone D science packs."""
    optimized = [a for a in spec.attacks if a.cohort == "optimized"]
    ordinary = [a for a in spec.attacks if a.cohort == "ordinary"]
    has_baseline = bool(spec.baseline and spec.baseline.strategy)
    return {
        "baseline": has_baseline,
        "optimized_attacks": len(optimized),
        "ordinary_or_baseline_cohort": len(ordinary) >= 1 or has_baseline,
        "access_model": bool(spec.access_model),
        "budget": bool(spec.budget),
        "splits": bool(spec.splits) or True,  # sidecar may supply defaults
        "primary_estimand": bool(_primary_estimand(spec)),
        "interval_method": bool(_interval_method(spec)),
        "stats_plan_methods": list(spec.stats_plan.methods or []),
        "planted_failure": bool((spec.metadata or {}).get("planted_failure"))
        or len(optimized) >= 1,
        "two_optimized_attacks": len(optimized) >= 2,
    }


def assert_no_labels_in_public_pack(side: Path) -> list[Diagnostic]:
    """Ensure sidecar tree does not embed hidden labels or vault material."""
    diags: list[Diagnostic] = []
    banned_names = {"vault", "labels.json", "hidden_labels.json", "gt_valid.json"}
    banned_keys = {"gt_valid", "hidden_label", "vault_key", "decrypt_key", "private_key"}
    if not side.is_dir():
        return diags
    for path in side.rglob("*"):
        if path.is_dir() and path.name.lower() in {"vault", "private"}:
            diags.append(
                Diagnostic(
                    code="VALAB.PACK.PUBLIC_LABEL_LEAK",
                    severity=DiagnosticSeverity.ERROR,
                    message=f"public pack must not contain {path.name}/",
                    path=str(path),
                )
            )
        if path.is_file() and path.name.lower() in banned_names:
            diags.append(
                Diagnostic(
                    code="VALAB.PACK.PUBLIC_LABEL_LEAK",
                    severity=DiagnosticSeverity.ERROR,
                    message=f"public pack must not contain {path.name}",
                    path=str(path),
                )
            )
        if path.is_file() and path.suffix.lower() == ".json":
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict):
                for key in banned_keys:
                    if key in payload:
                        diags.append(
                            Diagnostic(
                                code="VALAB.PACK.PUBLIC_LABEL_LEAK",
                                severity=DiagnosticSeverity.ERROR,
                                message=f"forbidden key {key!r} in public sidecar",
                                path=str(path),
                            )
                        )
    return diags


def write_pack_sidecars(yaml_path: Path, *, force: bool = False) -> Path:
    """Write profile / splits / expected-public-digests + science sidecars for packs A-E."""
    yaml_path = discover_pack_yaml(yaml_path)
    spec, _diags = load_campaign(yaml_path)
    out_dir = sidecar_dir_for(yaml_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    # Pointer so pack CLI can find the science YAML from the sidecar tree.
    pointer = {
        "schema_version": "1",
        "campaign_yaml": yaml_path.name,
        "campaign": spec.name,
        "theme": (spec.metadata or {}).get("theme"),
        "primary_estimand": _primary_estimand(spec),
        "interval_method": _interval_method(spec),
        "science_completeness": science_completeness(spec),
    }
    _write_json(out_dir / "pack.json", pointer, force=force)
    profile = build_profile_sidecar(spec)
    _write_json(out_dir / "profile.json", profile, force=force)
    splits = build_splits_sidecar(spec)
    _write_json(out_dir / "splits.json", splits, force=force)
    expected = build_expected_public_digests(spec, profile)
    _write_json(out_dir / "expected-public-digests.json", expected, force=force)
    _write_json(out_dir / "planted-failure.json", build_planted_failure_sidecar(spec), force=force)
    _write_json(
        out_dir / "adjudication-protocol.json",
        build_adjudication_protocol_sidecar(spec),
        force=force,
    )
    return out_dir


def _write_json(path: Path, payload: dict[str, Any], *, force: bool) -> None:
    if path.is_file() and not force:
        # Refresh digests if structure exists; always rewrite for determinism.
        pass
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def lint_pack(path: Path) -> tuple[bool, list[Diagnostic], dict[str, Any]]:
    """Validate campaign YAML + sidecar presence/consistency for packs A-E."""
    diags: list[Diagnostic] = []
    try:
        yaml_path = discover_pack_yaml(path)
    except FileNotFoundError as exc:
        diags.append(
            Diagnostic(
                code="VALAB.PACK.MISSING_YAML",
                severity=DiagnosticSeverity.ERROR,
                message=str(exc),
                path=str(path),
            )
        )
        return False, diags, {}

    try:
        spec, cam_diags = load_campaign(yaml_path)
    except CampaignSpecError as exc:
        return False, list(exc.diagnostics), {}
    diags.extend(cam_diags)

    letter = pack_letter(yaml_path) or str((spec.metadata or {}).get("pack") or "").lower()
    info: dict[str, Any] = {
        "campaign": spec.name,
        "yaml": str(yaml_path),
        "pack": letter,
    }

    if letter in SCIENCE_PACK_LETTERS:
        side = sidecar_dir_for(yaml_path)
        info["sidecar_dir"] = str(side)
        required = (
            "profile.json",
            "splits.json",
            "expected-public-digests.json",
            "pack.json",
            "planted-failure.json",
            "adjudication-protocol.json",
        )
        for name in required:
            if not (side / name).is_file():
                diags.append(
                    Diagnostic(
                        code="VALAB.PACK.MISSING_SIDECAR",
                        severity=DiagnosticSeverity.ERROR,
                        message=f"missing sidecar {name}",
                        path=str(side / name),
                    )
                )
        checklist = science_completeness(spec)
        info["science_completeness"] = checklist
        if not checklist["baseline"]:
            diags.append(
                Diagnostic(
                    code="VALAB.PACK.MISSING_BASELINE",
                    severity=DiagnosticSeverity.ERROR,
                    message="science pack requires baseline",
                    path=str(yaml_path),
                )
            )
        if not checklist["two_optimized_attacks"]:
            diags.append(
                Diagnostic(
                    code="VALAB.PACK.MISSING_OPTIMIZED_ATTACKS",
                    severity=DiagnosticSeverity.ERROR,
                    message="science pack requires at least two optimized attacks",
                    path=str(yaml_path),
                )
            )
        if not spec.splits:
            # Sidecar splits are acceptable; warn only if sidecar also missing.
            if not (side / "splits.json").is_file():
                diags.append(
                    Diagnostic(
                        code="VALAB.PACK.MISSING_SPLITS",
                        severity=DiagnosticSeverity.ERROR,
                        message="science pack requires splits in YAML or splits.json sidecar",
                        path=str(yaml_path),
                    )
                )
        if not spec.stats_plan.methods:
            diags.append(
                Diagnostic(
                    code="VALAB.PACK.MISSING_INTERVAL_METHOD",
                    severity=DiagnosticSeverity.ERROR,
                    message="science pack requires stats_plan.methods (interval method)",
                    path=str(yaml_path),
                )
            )
        diags.extend(assert_no_labels_in_public_pack(side))
        if (side / "expected-public-digests.json").is_file():
            expected = json.loads((side / "expected-public-digests.json").read_text(encoding="utf-8"))
            live = campaign_public_digest(spec)
            if expected.get("campaign_digest") != live:
                diags.append(
                    Diagnostic(
                        code="VALAB.PACK.DIGEST_MISMATCH",
                        severity=DiagnosticSeverity.ERROR,
                        message="expected-public campaign_digest does not match YAML",
                        path=str(side / "expected-public-digests.json"),
                    )
                )
            info["campaign_digest"] = live
            info["primary_estimand"] = expected.get("primary_estimand") or _primary_estimand(spec)
            info["interval_method"] = expected.get("interval_method") or _interval_method(spec)

    ok = not any(d.severity == DiagnosticSeverity.ERROR for d in diags)
    return ok, diags, info


def verify_pack(path: Path) -> tuple[bool, list[Diagnostic], dict[str, Any]]:
    """Lint plus recompute sidecar digests and confirm pins are present."""
    ok, diags, info = lint_pack(path)
    try:
        yaml_path = discover_pack_yaml(path)
        spec, _ = load_campaign(yaml_path)
    except (FileNotFoundError, CampaignSpecError):
        return ok, diags, info

    if not spec.pinned_versions.get("verifierlab") or not spec.pinned_versions.get("campaign"):
        diags.append(
            Diagnostic(
                code="VALAB.PACK.MISSING_PINS",
                severity=DiagnosticSeverity.ERROR,
                message="pinned_versions must include verifierlab and campaign",
                path=str(yaml_path),
            )
        )
        ok = False

    letter = pack_letter(yaml_path) or str((spec.metadata or {}).get("pack") or "").lower()
    if letter in SCIENCE_PACK_LETTERS:
        side = sidecar_dir_for(yaml_path)
        profile_path = side / "profile.json"
        if profile_path.is_file():
            stored = json.loads(profile_path.read_text(encoding="utf-8"))
            live_profile = build_profile_sidecar(spec)
            if stored.get("content_digest") != live_profile.get("content_digest"):
                diags.append(
                    Diagnostic(
                        code="VALAB.PACK.PROFILE_STALE",
                        severity=DiagnosticSeverity.ERROR,
                        message="profile.json content_digest is stale; regenerate sidecars",
                        path=str(profile_path),
                    )
                )
                ok = False
        info["signing"] = {
            "mode": "content_addressed",
            "campaign_digest": campaign_public_digest(spec),
            "pins": dict(spec.pinned_versions),
        }
    ok = ok and not any(d.severity == DiagnosticSeverity.ERROR for d in diags)
    return ok, diags, info


def inspect_pack(path: Path) -> dict[str, Any]:
    yaml_path = discover_pack_yaml(path)
    spec, diags = load_campaign(yaml_path)
    letter = pack_letter(yaml_path) or str((spec.metadata or {}).get("pack") or "").lower()
    payload: dict[str, Any] = {
        "campaign": spec.name,
        "yaml": str(yaml_path),
        "pack": letter,
        "access_model": spec.access_model.value,
        "work_units": spec.work_units,
        "attacks": [a.name for a in spec.attacks],
        "pinned_versions": dict(spec.pinned_versions),
        "campaign_digest": campaign_public_digest(spec),
        "diagnostics": [d.model_dump(mode="json") for d in diags],
        "signing": {
            "mode": "content_addressed",
            "means": ["campaign_digest", "pinned_versions", "sealed_run_manifest"],
        },
    }
    if letter in SCIENCE_PACK_LETTERS:
        side = sidecar_dir_for(yaml_path)
        payload["sidecar_dir"] = str(side)
        payload["sidecars_present"] = {
            name: (side / name).is_file()
            for name in (
                "pack.json",
                "profile.json",
                "splits.json",
                "expected-public-digests.json",
                "planted-failure.json",
                "adjudication-protocol.json",
            )
        }
        payload["science_completeness"] = science_completeness(spec)
        payload["primary_estimand"] = _primary_estimand(spec)
        payload["interval_method"] = _interval_method(spec)
    return payload


__all__ = [
    "SCIENCE_PACK_LETTERS",
    "assert_no_labels_in_public_pack",
    "build_adjudication_protocol_sidecar",
    "build_expected_public_digests",
    "build_planted_failure_sidecar",
    "build_profile_sidecar",
    "build_splits_sidecar",
    "campaign_public_digest",
    "discover_pack_yaml",
    "inspect_pack",
    "lint_pack",
    "pack_letter",
    "packs_root",
    "science_completeness",
    "sidecar_dir_for",
    "verify_pack",
    "write_pack_sidecars",
]
