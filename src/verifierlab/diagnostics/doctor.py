"""``valab doctor`` health checks."""

from __future__ import annotations

import importlib
import platform
import sys
from dataclasses import dataclass
from pathlib import Path

from verifierlab import __version__
from verifierlab.diagnostics.codes import Diagnostic, DiagnosticSeverity


@dataclass(frozen=True)
class DoctorReport:
    ok: bool
    diagnostics: list[Diagnostic]
    info: dict[str, str]


def run_doctor(*, workspace: Path | None = None) -> DoctorReport:
    diags: list[Diagnostic] = []
    info: dict[str, str] = {
        "verifierlab_version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
    }

    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 11) or (major, minor) >= (3, 14):
        diags.append(
            Diagnostic(
                code="VALAB.DOCTOR.PYTHON",
                severity=DiagnosticSeverity.ERROR,
                message=f"Python >=3.11,<3.14 required; found {sys.version.split()[0]}",
            )
        )

    for mod in ("pydantic", "typer", "yaml", "rich"):
        try:
            importlib.import_module(mod if mod != "yaml" else "yaml")
        except ImportError:
            diags.append(
                Diagnostic(
                    code="VALAB.DOCTOR.DEP",
                    severity=DiagnosticSeverity.ERROR,
                    message=f"required module {mod!r} is not importable",
                )
            )

    for forbidden in ("torch", "ray", "kubernetes"):
        try:
            importlib.import_module(forbidden)
        except ImportError:
            continue
        diags.append(
            Diagnostic(
                code="VALAB.DOCTOR.HEAVY_DEP",
                severity=DiagnosticSeverity.WARNING,
                message=f"{forbidden} is importable; base campaigns should not require it",
            )
        )

    # Optional adapter probes (informational — never fail doctor).
    try:
        from verifierlab.targets.harbor_adapter import harbor_install_status

        harbor = harbor_install_status()
        info["harbor"] = str(harbor.get("mode"))
        if not harbor.get("available"):
            diags.append(
                Diagnostic(
                    code="VALAB.DOCTOR.HARBOR",
                    severity=DiagnosticSeverity.INFO,
                    message=(
                        f"Harbor live SDK unavailable ({harbor.get('mode')}); "
                        f"lighter path: {harbor.get('lighter_path')} "
                        f"— {harbor.get('hint') or harbor.get('reason')}"
                    ),
                )
            )
    except Exception as exc:
        diags.append(
            Diagnostic(
                code="VALAB.DOCTOR.HARBOR",
                severity=DiagnosticSeverity.INFO,
                message=f"Harbor probe failed: {exc}",
            )
        )

    root = workspace or Path.cwd() / ".valab"
    if not root.exists():
        diags.append(
            Diagnostic(
                code="VALAB.DOCTOR.WORKSPACE",
                severity=DiagnosticSeverity.INFO,
                message="no .valab workspace yet; run `valab init`",
            )
        )
    else:
        info["workspace"] = str(root.resolve())

    ok = not any(d.severity == DiagnosticSeverity.ERROR for d in diags)
    return DoctorReport(ok=ok, diagnostics=diags, info=info)
