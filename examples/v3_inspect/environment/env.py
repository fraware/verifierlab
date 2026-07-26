from __future__ import annotations

from typing import Any


def make_env(**_kwargs: Any) -> Any:
    from pathlib import Path
    from verifierlab.targets.inspect_adapter import InspectAdapter, inspect_sdk_available
    fixture = Path(__file__).resolve().parents[3] / 'tests' / 'fixtures' / 'inspect_eval_log.json'
    if inspect_sdk_available():
        return InspectAdapter(mode='live_task')
    return InspectAdapter(eval_log_path=fixture, mode='eval_log_import')
