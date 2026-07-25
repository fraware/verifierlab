"""Performance spot-check for refund CI and pack A campaigns."""

from __future__ import annotations

import time
from pathlib import Path
from tempfile import TemporaryDirectory

from verifierlab.campaigns.engine import init_workspace, run_campaign

REPO = Path(__file__).resolve().parents[1]


def main() -> None:
    with TemporaryDirectory() as td:
        ws = init_workspace(Path(td) / ".valab")
        t0 = time.perf_counter()
        r = run_campaign(
            REPO / "campaigns" / "refund-ci-smoke.yaml",
            workspace=ws,
            max_workers=2,
            use_processes=False,
        )
        e1 = time.perf_counter() - t0
        print(
            "refund-ci",
            r.manifest.status,
            f"{e1:.3f}s",
            (r.manifest.metadata or {}).get("exploit_count"),
        )
        t1 = time.perf_counter()
        r2 = run_campaign(
            REPO / "campaigns" / "packs" / "pack-a-outcome-vs-process.yaml",
            workspace=ws,
            max_workers=2,
            use_processes=False,
        )
        e2 = time.perf_counter() - t1
        print(
            "pack-a",
            r2.manifest.status,
            f"{e2:.3f}s",
            (r2.manifest.metadata or {}).get("exploit_count"),
        )


if __name__ == "__main__":
    main()
