"""Campaign packs A-E: validate + runnable recovery assertions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from verifierlab.campaigns.coevolution import lineage_chain, run_coevolution_epoch
from verifierlab.campaigns.engine import init_workspace, run_campaign
from verifierlab.config.campaign import load_campaign
from verifierlab.reports import build_report

PACKS = Path(__file__).resolve().parents[1] / "campaigns" / "packs"
REPO = Path(__file__).resolve().parents[1]


def test_packs_a_through_e_validate() -> None:
    files = sorted(PACKS.glob("pack-*.yaml"))
    assert len(files) == 5
    for path in files:
        spec, diags = load_campaign(path)
        assert spec.name.startswith("pack-")
        assert spec.attacks
        assert not any(d.severity.value == "error" for d in diags)
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        expected = (raw.get("metadata") or {}).get("expected_taxonomies") or []
        assert expected, f"{path.name} must declare expected_taxonomies"


@pytest.mark.integration
@pytest.mark.parametrize(
    "pack_name",
    [
        "pack-a-outcome-vs-process.yaml",
        "pack-b-rubric.yaml",
        "pack-c-isomorphic.yaml",
        "pack-d-eval-cheating.yaml",
        "pack-e-coevolution.yaml",
    ],
)
def test_pack_recovers_planted_taxonomies(tmp_path: Path, pack_name: str) -> None:
    path = PACKS / pack_name
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    expected = set((raw.get("metadata") or {}).get("expected_taxonomies") or [])
    workspace = init_workspace(tmp_path / ".valab")
    result = run_campaign(path, workspace=workspace, max_workers=2, use_processes=False)
    assert result.manifest.status == "completed"
    assert (result.manifest.metadata or {}).get("exploit_count", 0) >= 1

    classes: set[str] = set()
    for wu in (result.run_dir / "work_units").glob("*.json"):
        row = json.loads(wu.read_text(encoding="utf-8"))
        exploit = row.get("exploit")
        if exploit:
            classes.add(str(exploit["taxonomy"]))

    missing = expected - classes
    assert not missing, f"{pack_name}: missing taxonomies {sorted(missing)}; got {sorted(classes)}"

    report = build_report(result.run_dir)
    assert report["exploit_count"] >= 1

    if pack_name.startswith("pack-e"):
        from examples.refunds.verifier import grade

        rows = [
            json.loads(p.read_text(encoding="utf-8"))
            for p in sorted((result.run_dir / "work_units").glob("*.json"))
        ]
        epoch0 = run_coevolution_epoch(
            epoch=0,
            verifier_fn=grade,
            verifier_version="refund_grade@1",
            attack_results=rows,
        )
        epoch1 = run_coevolution_epoch(
            epoch=1,
            verifier_fn=grade,
            verifier_version="refund_grade@1",
            attack_results=rows,
            parent_epoch_digest=epoch0["epoch_digest"],
        )
        chain = lineage_chain([epoch0, epoch1])
        assert len(chain) == 2
        assert epoch1["parent_epoch_digest"] == epoch0["epoch_digest"]
        assert epoch0["n_exploits"] >= 1
