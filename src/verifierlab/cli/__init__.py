"""Typer CLI application for ``valab``."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from verifierlab import __version__
from verifierlab.api.verifier import get_verifier_spec
from verifierlab.campaigns.engine import (
    adjudicate_campaign,
    default_workspace,
    freeze_run,
    init_workspace,
    release_labels,
    run_campaign,
)
from verifierlab.config.campaign import CampaignSpecError, load_campaign
from verifierlab.diagnostics.codes import DiagnosticSeverity
from verifierlab.diagnostics.doctor import run_doctor
from verifierlab.plugins.loader import load_object
from verifierlab.reports.html import build_report
from verifierlab.statistics.intervals import power_binomial, sample_size_for_power

console = Console(stderr=True)
app = typer.Typer(
    name="valab",
    help="Verifier Assurance Lab — local-first verifier robustness campaigns.",
    no_args_is_help=True,
    add_completion=False,
)
campaign_app = typer.Typer(help="Campaign validate / run commands.", no_args_is_help=True)
report_app = typer.Typer(help="Build assurance reports.", no_args_is_help=True)
stats_app = typer.Typer(help="Statistics and power analysis.", no_args_is_help=True)
plugins_app = typer.Typer(help="Plugin discovery.", no_args_is_help=True)
app.add_typer(campaign_app, name="campaign")
app.add_typer(report_app, name="report")
app.add_typer(stats_app, name="stats")
app.add_typer(plugins_app, name="plugins")


def _print_json(payload: object) -> None:
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit(0)


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        help="Show version and exit.",
        is_eager=True,
        callback=_version_callback,
    ),
) -> None:
    """Verifier Assurance Lab CLI."""


@app.command("init")
def init_cmd(
    path: Path | None = typer.Option(
        None,
        "--path",
        help="Workspace directory (default: ./.valab)",
    ),
    force: bool = typer.Option(False, "--force", help="Rewrite workspace marker files."),
) -> None:
    """Create a local ``.valab`` workspace (store + runs)."""
    root = path or default_workspace()
    created = init_workspace(root, force=force)
    typer.echo(f"Initialized workspace at {created}")


@app.command("doctor")
def doctor_cmd(
    format: str = typer.Option("text", "--format", help="Output format: text|json"),
) -> None:
    """Environment and dependency health checks."""
    report = run_doctor()
    if format == "json":
        _print_json(
            {
                "ok": report.ok,
                "info": report.info,
                "diagnostics": [d.model_dump(mode="json") for d in report.diagnostics],
            }
        )
    else:
        for key, value in report.info.items():
            console.print(f"[bold]{key}[/bold]: {value}")
        if report.diagnostics:
            table = Table(title="Diagnostics")
            table.add_column("Severity")
            table.add_column("Code")
            table.add_column("Message")
            for d in report.diagnostics:
                table.add_row(d.severity.value, d.code, d.message)
            console.print(table)
        console.print("[green]OK[/green]" if report.ok else "[red]FAIL[/red]")
    raise typer.Exit(0 if report.ok else 1)


@app.command("inspect")
def inspect_cmd(
    target: str = typer.Argument(..., help="Dotted ref module:attr to a @verifier callable"),
    format: str = typer.Option("text", "--format", help="Output format: text|json"),
) -> None:
    """Inspect a Python verifier and print its VerifierSpec."""
    try:
        fn = load_object(target)
        spec = get_verifier_spec(fn)
    except Exception as exc:
        console.print(f"[red]inspect failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    payload = spec.model_dump(mode="json")
    if format == "json":
        _print_json(payload)
    else:
        console.print(f"name: {spec.name}")
        console.print(f"version: {spec.version}")
        console.print(f"decision_space: {spec.decision_space.value}")
        console.print(f"access_model: {spec.access_model.value}")
        console.print(f"stochastic: {spec.stochastic}")
        console.print(f"abstention: {spec.abstention.value}")
        console.print(f"side_effects: {spec.side_effects.value}")
        console.print(f"timeout_s: {spec.timeout_s}")
        console.print(f"score_range: {spec.score_range}")
        console.print(f"allowed_exceptions: {spec.allowed_exceptions}")
        console.print(f"external_resources: {spec.external_resources}")
        console.print(f"input_schema: {spec.input_schema is not None}")
        console.print(f"output_schema: {spec.output_schema is not None}")
        console.print(f"contract_complete: {spec.contract_complete()}")
        console.print(f"callable_digest: {spec.callable_digest}")
        console.print(f"source: {spec.source.module}:{spec.source.qualname}")
        for lim in spec.limitations:
            console.print(f"limitation: {lim}")
    raise typer.Exit(0)


@app.command("run")
def run_cmd(
    path: Path = typer.Argument(..., exists=True, readable=True, help="Campaign YAML/JSON"),
    workspace: Path | None = typer.Option(None, "--workspace"),
    workers: int = typer.Option(2, "--workers", min=1),
    threads: bool = typer.Option(
        False,
        "--threads/--processes",
        help="Use thread workers; default is process pool",
    ),
    format: str = typer.Option("text", "--format"),
) -> None:
    """Alias for ``valab campaign run`` (tutorial path)."""
    campaign_run(path=path, workspace=workspace, workers=workers, threads=threads, format=format)


@campaign_app.command("validate")
def campaign_validate(
    path: Path = typer.Argument(..., exists=True, readable=True, help="Campaign YAML/JSON"),
    format: str = typer.Option("text", "--format", help="Output format: text|json"),
) -> None:
    """Load and validate a campaign specification."""
    try:
        spec, diags = load_campaign(path)
    except CampaignSpecError as exc:
        if format == "json":
            _print_json(
                {
                    "ok": False,
                    "diagnostics": [d.model_dump(mode="json") for d in exc.diagnostics],
                }
            )
        else:
            for d in exc.diagnostics:
                console.print(f"[{d.severity.value}] {d.code}: {d.message} ({d.path})")
        raise typer.Exit(1) from exc

    payload = {
        "ok": True,
        "name": spec.name,
        "access_model": spec.access_model.value,
        "disclosure_class": spec.disclosure_class.value,
        "diagnostics": [d.model_dump(mode="json") for d in diags],
    }
    if format == "json":
        _print_json(payload)
    else:
        console.print(f"Campaign [bold]{spec.name}[/bold] is valid")
        for d in diags:
            if d.severity != DiagnosticSeverity.ERROR:
                console.print(f"[{d.severity.value}] {d.code}: {d.message}")
    raise typer.Exit(0)


@campaign_app.command("run")
def campaign_run(
    path: Path = typer.Argument(..., exists=True, readable=True, help="Campaign YAML/JSON"),
    workspace: Path | None = typer.Option(
        None,
        "--workspace",
        help="Workspace root (default: ./.valab)",
    ),
    workers: int = typer.Option(2, "--workers", min=1, help="Process/thread pool size"),
    threads: bool = typer.Option(
        False,
        "--threads/--processes",
        help="Use thread workers. Default is process pool (picklable worker entry).",
    ),
    format: str = typer.Option("text", "--format", help="Output format: text|json"),
) -> None:
    """Execute a campaign via the local asyncio launcher."""
    try:
        result = run_campaign(
            path,
            workspace=workspace,
            max_workers=workers,
            use_processes=not threads,
        )
    except CampaignSpecError as exc:
        console.print(f"[red]Invalid campaign:[/red] {exc}")
        raise typer.Exit(1) from exc
    except Exception as exc:
        console.print(f"[red]Campaign failed:[/red] {exc}")
        raise typer.Exit(2) from exc

    payload = {
        "run_id": result.run_id,
        "run_digest": result.run_digest,
        "status": result.manifest.status,
        "elapsed_s": result.elapsed_s,
        "run_dir": str(result.run_dir),
        "overrun": result.manifest.overrun,
        "campaign_digest": result.manifest.campaign_digest,
        "exploit_count": (result.manifest.metadata or {}).get("exploit_count"),
    }
    if format == "json":
        _print_json(payload)
    else:
        console.print(f"Run ID:      {result.run_id}")
        console.print(f"Run digest:  {result.run_digest}")
        console.print(f"Status:      {result.manifest.status}")
        console.print(f"Elapsed:     {result.elapsed_s:.3f}s")
        console.print(f"Bundle:      {result.run_dir}")
        if payload["exploit_count"] is not None:
            console.print(f"Exploits:    {payload['exploit_count']}")
    raise typer.Exit(
        0
        if result.manifest.status in {"completed", "budget_exceeded", "completed_with_failures"}
        else 1
    )


@campaign_app.command("freeze")
def campaign_freeze(
    run_dir: Path = typer.Argument(..., exists=True, file_okay=False, help="Run bundle directory"),
) -> None:
    """Freeze a run: seal label vault and append FreezeRecord tip."""
    freeze = freeze_run(run_dir)
    typer.echo(json.dumps(freeze.model_dump(mode="json"), indent=2, sort_keys=True))


@campaign_app.command("adjudicate")
def campaign_adjudicate(
    run_dir: Path = typer.Argument(..., exists=True, file_okay=False, help="Run bundle directory"),
    campaign: Path | None = typer.Option(
        None,
        "--campaign",
        exists=True,
        readable=True,
        help="Campaign YAML/JSON (optional if campaign_digest is in the store)",
    ),
) -> None:
    """Hidden-GT adjudication after freeze (coordinator-only; not in workers)."""
    try:
        record = adjudicate_campaign(run_dir, campaign_path=campaign)
    except Exception as exc:
        console.print(f"[red]Adjudication failed:[/red] {exc}")
        raise typer.Exit(2) from exc
    typer.echo(json.dumps(record.model_dump(mode="json"), indent=2, sort_keys=True))


@campaign_app.command("release-labels")
def campaign_release_labels(
    run_dir: Path = typer.Argument(..., exists=True, file_okay=False, help="Run bundle directory"),
) -> None:
    """Release sealed labels after adjudication."""
    release_labels(run_dir)
    typer.echo(f"Labels released for {run_dir}")


@report_app.command("builds")
def report_builds(
    run_dir: Path = typer.Argument(..., exists=True, file_okay=False, help="Run bundle directory"),
    format: str = typer.Option("text", "--format"),
) -> None:
    """Rebuild static HTML/JSON/CSV report from immutable run artifacts.

    Blocked until ``freeze → adjudicate → release-labels``.
    """
    try:
        payload = build_report(run_dir)
    except PermissionError as exc:
        console.print(f"[red]Report blocked:[/red] {exc}")
        raise typer.Exit(3) from exc
    if format == "json":
        _print_json(payload)
    else:
        console.print(f"Report written under {run_dir / 'report'}")
        console.print(f"Exploits: {payload.get('exploit_count')}")
        console.print(f"FAR: {(payload.get('metrics') or {}).get('overall', {}).get('far')}")
    raise typer.Exit(0)


@plugins_app.command("list")
def plugins_list(
    format: str = typer.Option("text", "--format", help="Output format: text|json"),
) -> None:
    """List entry points registered under ``verifierlab.plugins``."""
    from verifierlab.plugins import discover_plugins

    found = discover_plugins()
    payload = {
        name: {
            "status": "error" if isinstance(obj, BaseException) else "loaded",
            "type": type(obj).__name__,
            "detail": str(obj) if isinstance(obj, BaseException) else None,
        }
        for name, obj in sorted(found.items())
    }
    if format == "json":
        _print_json({"count": len(payload), "plugins": payload})
    else:
        if not payload:
            typer.echo("No plugins registered under verifierlab.plugins")
        else:
            for name, info in payload.items():
                typer.echo(f"{name}: {info['status']} ({info['type']})")
    raise typer.Exit(0)


@stats_app.command("power")
def stats_power(
    p0: float = typer.Option(..., "--p0", help="Baseline proportion"),
    p1: float = typer.Option(..., "--p1", help="Alternative proportion"),
    n: int | None = typer.Option(None, "--n", help="Sample size (compute power)"),
    power: float | None = typer.Option(None, "--power", help="Target power (compute n)"),
    alpha: float = typer.Option(0.05, "--alpha"),
    format: str = typer.Option("text", "--format"),
) -> None:
    """Binomial power analysis or sample-size planning."""
    if n is not None:
        payload = power_binomial(p0=p0, p1=p1, n=n, alpha=alpha)
    elif power is not None:
        payload = sample_size_for_power(p0=p0, p1=p1, power=power, alpha=alpha)
    else:
        console.print("[red]Provide --n or --power[/red]")
        raise typer.Exit(2)
    if format == "json":
        _print_json(payload)
    else:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    raise typer.Exit(0)


__all__ = ["app"]
