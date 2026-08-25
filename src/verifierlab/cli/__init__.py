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
verifier_app = typer.Typer(
    help="Verifier inspect / test / package / conformance.",
    no_args_is_help=True,
)
pack_app = typer.Typer(
    help="Benchmark pack lint / verify / run / reproduce / inspect.",
    no_args_is_help=True,
)
assurance_app = typer.Typer(
    help="Artifact-derived assurance qualification (WP-05).",
    no_args_is_help=True,
)
app.add_typer(campaign_app, name="campaign")
app.add_typer(report_app, name="report")
app.add_typer(stats_app, name="stats")
app.add_typer(plugins_app, name="plugins")
app.add_typer(verifier_app, name="verifier")
app.add_typer(pack_app, name="pack")
app.add_typer(assurance_app, name="assurance")


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
    """Inspect a Python verifier and print its VerifierSpec.

    Same implementation as ``valab verifier inspect``.
    """
    verifier_inspect(target=target, format=format)


def _inspect_verifier_payload(target: str) -> dict[str, object]:
    fn = load_object(target)
    spec = get_verifier_spec(fn)
    return spec.model_dump(mode="json")


def _print_verifier_spec_text(payload: dict[str, object]) -> None:
    console.print(f"name: {payload.get('name')}")
    console.print(f"version: {payload.get('version')}")
    console.print(f"decision_space: {payload.get('decision_space')}")
    console.print(f"access_model: {payload.get('access_model')}")
    console.print(f"stochastic: {payload.get('stochastic')}")
    console.print(f"abstention: {payload.get('abstention')}")
    console.print(f"side_effects: {payload.get('side_effects')}")
    console.print(f"timeout_s: {payload.get('timeout_s')}")
    console.print(f"score_range: {payload.get('score_range')}")
    console.print(f"allowed_exceptions: {payload.get('allowed_exceptions')}")
    console.print(f"external_resources: {payload.get('external_resources')}")
    console.print(f"input_schema: {payload.get('input_schema') is not None}")
    console.print(f"output_schema: {payload.get('output_schema') is not None}")
    console.print(f"callable_digest: {payload.get('callable_digest')}")
    source = payload.get("source") or {}
    if isinstance(source, dict):
        console.print(f"source: {source.get('module')}:{source.get('qualname')}")
    limitations = payload.get("limitations")
    if isinstance(limitations, (list, tuple)):
        for lim in limitations:
            console.print(f"limitation: {lim}")


@verifier_app.command("inspect")
def verifier_inspect(
    target: str = typer.Argument(..., help="Dotted ref module:attr to a @verifier callable"),
    format: str = typer.Option("text", "--format", help="Output format: text|json"),
) -> None:
    """Inspect a Python verifier and print its VerifierSpec."""
    try:
        payload = _inspect_verifier_payload(target)
    except Exception as exc:
        console.print(f"[red]inspect failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    if format == "json":
        _print_json(payload)
    else:
        _print_verifier_spec_text(payload)
        fn = load_object(target)
        spec = get_verifier_spec(fn)
        console.print(f"contract_complete: {spec.contract_complete()}")
    raise typer.Exit(0)


@verifier_app.command("test")
def verifier_test(
    target: str = typer.Argument(..., help="Dotted ref module:attr"),
    input_json: Path | None = typer.Option(
        None,
        "--input",
        exists=True,
        readable=True,
        help="JSON trajectory/observation file (default: minimal empty trajectory)",
    ),
    isolation: str = typer.Option(
        "auto",
        "--isolation",
        help="auto|inprocess|subprocess — packaged path prefers subprocess",
    ),
    timeout_s: float = typer.Option(30.0, "--timeout"),
    format: str = typer.Option("text", "--format"),
) -> None:
    """Invoke a verifier once and print the normalized decision."""
    from verifierlab.api.verifier import normalize_decision
    from verifierlab.verifiers.runner import PythonVerifierRunner

    trajectory: dict[str, object]
    if input_json is not None:
        trajectory = json.loads(input_json.read_text(encoding="utf-8"))
    else:
        trajectory = {"steps": [], "schema_version": "1"}

    try:
        if isolation == "inprocess":
            use_sub = False
        elif isolation == "subprocess":
            use_sub = True
        else:
            # auto: prefer subprocess boundary (packaged path).
            use_sub = True
        if use_sub:
            runner = PythonVerifierRunner.from_ref(target, timeout_s=timeout_s)
            decision = runner.invoke(trajectory)
            mode = "subprocess"
        else:
            fn = load_object(target)
            decision = normalize_decision(fn(trajectory))
            mode = "inprocess"
    except Exception as exc:
        console.print(f"[red]verifier test failed:[/red] {exc}")
        raise typer.Exit(1) from exc

    payload = {
        "mode": mode,
        "decision": decision.model_dump(mode="json"),
    }
    if format == "json":
        _print_json(payload)
    else:
        console.print(f"mode: {mode}")
        console.print(f"status: {decision.status}")
        console.print(f"accepted: {decision.accepted}")
        console.print(f"score: {decision.score}")
        console.print(f"reason_codes: {decision.reason_codes}")
    raise typer.Exit(0 if decision.status != "error" else 1)


@verifier_app.command("package")
def verifier_package(
    target: str = typer.Argument(..., help="Dotted ref module:attr"),
    out: Path = typer.Option(..., "--out", help="Output directory for packaged verifier"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    """Write a minimal packaged-verifier layout (profile + mount config)."""
    from verifierlab.verifiers.profile import VerifierProfile
    from verifierlab.verifiers.runner import PythonVerifierRunner

    try:
        fn = load_object(target)
        profile = VerifierProfile.for_callable(
            fn,
            name=target,
            applicability={"isolation": "subprocess", "runner": "PythonVerifierRunner"},
            access_surface={"may_read_hidden_labels": False, "subprocess": True},
        )
    except Exception as exc:
        console.print(f"[red]package failed:[/red] {exc}")
        raise typer.Exit(1) from exc

    if out.exists() and any(out.iterdir()) and not force:
        console.print(f"[red]refusing to overwrite non-empty {out}; pass --force[/red]")
        raise typer.Exit(2)

    out.mkdir(parents=True, exist_ok=True)
    runner = PythonVerifierRunner.from_ref(target, config={"packaged": True})
    manifest = {
        "schema_version": "1",
        "ref": target,
        "isolation": "subprocess",
        "runner": "PythonVerifierRunner",
        "digests": runner.digests(),
        "profile_digest": profile.content_digest(),
        "mount": {
            "kind": "packaged",
            "ref": target,
            "config": {"isolation": "subprocess", "packaged": True},
        },
    }
    (out / "profile.json").write_text(
        json.dumps(
            {**profile.model_dump(mode="json"), "content_digest": profile.content_digest()},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (out / "package.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    typer.echo(str(out))
    raise typer.Exit(0)


@verifier_app.command("conformance")
def verifier_conformance(
    target: str | None = typer.Argument(
        None,
        help="Optional verifier ref (decision suite runs regardless)",
    ),
    format: str = typer.Option("text", "--format"),
) -> None:
    """Run shared decision-normalization conformance checks."""
    from verifierlab.targets.conformance import check_decision_normalization

    checks = check_decision_normalization()
    details: dict[str, object] = {"decision_normalization": checks}
    if target:
        try:
            from verifierlab.verifiers.runner import PythonVerifierRunner

            runner = PythonVerifierRunner.from_ref(target, timeout_s=15.0)
            # Smoke: empty trajectory must return a typed decision (not crash).
            decision = runner.invoke({"steps": []})
            checks["subprocess_smoke"] = decision.status in {
                "accept",
                "reject",
                "abstain",
                "indeterminate",
                "error",
            }
            details["subprocess_decision"] = decision.model_dump(mode="json")
            details["digests"] = runner.digests()
        except Exception as exc:
            checks["subprocess_smoke"] = False
            details["subprocess_error"] = str(exc)

    ok = all(checks.values()) if checks else False
    payload = {"ok": ok, "checks": checks, "details": details}
    if format == "json":
        _print_json(payload)
    else:
        for name, passed in checks.items():
            console.print(f"{'PASS' if passed else 'FAIL'}: {name}")
        console.print("[green]OK[/green]" if ok else "[red]FAIL[/red]")
    raise typer.Exit(0 if ok else 1)


@pack_app.command("lint")
def pack_lint(
    path: Path = typer.Argument(..., help="Pack YAML or sidecar directory"),
    format: str = typer.Option("text", "--format"),
) -> None:
    """Validate pack campaign YAML and required sidecars (A-E)."""
    from verifierlab.campaigns.packs import lint_pack

    ok, diags, info = lint_pack(path)
    payload = {
        "ok": ok,
        "info": info,
        "diagnostics": [d.model_dump(mode="json") for d in diags],
    }
    if format == "json":
        _print_json(payload)
    else:
        console.print(f"pack: {info.get('campaign') or path}")
        for d in diags:
            console.print(f"[{d.severity.value}] {d.code}: {d.message} ({d.path})")
        console.print("[green]OK[/green]" if ok else "[red]FAIL[/red]")
    raise typer.Exit(0 if ok else 1)


@pack_app.command("verify")
def pack_verify(
    path: Path = typer.Argument(..., help="Pack YAML or sidecar directory"),
    format: str = typer.Option("text", "--format"),
) -> None:
    """Lint plus pin / digest verification for pack sidecars."""
    from verifierlab.campaigns.packs import verify_pack

    ok, diags, info = verify_pack(path)
    payload = {
        "ok": ok,
        "info": info,
        "diagnostics": [d.model_dump(mode="json") for d in diags],
    }
    if format == "json":
        _print_json(payload)
    else:
        console.print(f"pack: {info.get('campaign') or path}")
        if info.get("signing"):
            console.print(f"signing: {info['signing']}")
        for d in diags:
            console.print(f"[{d.severity.value}] {d.code}: {d.message} ({d.path})")
        console.print("[green]OK[/green]" if ok else "[red]FAIL[/red]")
    raise typer.Exit(0 if ok else 1)


@pack_app.command("run")
def pack_run(
    path: Path = typer.Argument(..., help="Pack YAML or sidecar directory"),
    workspace: Path | None = typer.Option(None, "--workspace"),
    workers: int = typer.Option(2, "--workers", min=1),
    threads: bool = typer.Option(False, "--threads/--processes"),
    format: str = typer.Option("text", "--format"),
) -> None:
    """Run a pack campaign (resolves sidecar dirs to YAML)."""
    from verifierlab.campaigns.packs import discover_pack_yaml

    try:
        yaml_path = discover_pack_yaml(path)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    campaign_run(
        path=yaml_path,
        workspace=workspace,
        workers=workers,
        threads=threads,
        format=format,
    )


@pack_app.command("reproduce")
def pack_reproduce(
    path: Path = typer.Argument(..., help="Pack YAML or sidecar directory"),
    format: str = typer.Option("text", "--format"),
) -> None:
    """Verify pack digests/pins (reproduction gate without re-running attacks)."""
    from verifierlab.campaigns.packs import inspect_pack, verify_pack

    ok, diags, info = verify_pack(path)
    inspected = inspect_pack(path)
    payload = {
        "ok": ok,
        "mode": "digest_and_pins",
        "info": info,
        "inspect": inspected,
        "diagnostics": [d.model_dump(mode="json") for d in diags],
        "note": (
            "Pack reproduce checks content-addressed campaign digest + pins. "
            "Full sealed-run reproduction uses valab campaign freeze artifacts / "
            "scripts/verify_repro_bundle.py."
        ),
    }
    if format == "json":
        _print_json(payload)
    else:
        console.print(f"campaign_digest: {inspected.get('campaign_digest')}")
        console.print(f"signing: {inspected.get('signing')}")
        for d in diags:
            console.print(f"[{d.severity.value}] {d.code}: {d.message}")
        console.print("[green]OK[/green]" if ok else "[red]FAIL[/red]")
    raise typer.Exit(0 if ok else 1)


@pack_app.command("inspect")
def pack_inspect(
    path: Path = typer.Argument(..., help="Pack YAML or sidecar directory"),
    format: str = typer.Option("text", "--format"),
) -> None:
    """Inspect pack metadata, digests, and sidecar presence."""
    from verifierlab.campaigns.packs import inspect_pack

    try:
        payload = inspect_pack(path)
    except Exception as exc:
        console.print(f"[red]pack inspect failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    if format == "json":
        _print_json(payload)
    else:
        console.print(f"campaign: {payload.get('campaign')}")
        console.print(f"pack: {payload.get('pack')}")
        console.print(f"access_model: {payload.get('access_model')}")
        console.print(f"work_units: {payload.get('work_units')}")
        console.print(f"campaign_digest: {payload.get('campaign_digest')}")
        console.print(f"signing: {payload.get('signing')}")
        if payload.get("sidecars_present") is not None:
            console.print(f"sidecars: {payload.get('sidecars_present')}")
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


@assurance_app.command("qualify")
def assurance_qualify(
    run_or_study: Path = typer.Argument(..., help="Sealed run or study directory"),
    claim: Path = typer.Option(..., "--claim", help="Path to AssuranceClaim JSON"),
    trust_root: list[str] = typer.Option(
        [],
        "--trust-root",
        help="External trust root as id=secret (repeatable)",
    ),
    attestation: list[Path] = typer.Option(
        [],
        "--attestation",
        help="Path to ExternalAssuranceAttestation JSON (repeatable)",
    ),
    format: str = typer.Option("json", "--format", help="Output format: json|text"),
) -> None:
    """Qualify assurance maturity from sealed artifacts (not caller booleans)."""
    from verifierlab.assurance import ExternalAssuranceAttestation, qualify_run

    roots: dict[str, str] = {}
    for item in trust_root:
        if "=" not in item:
            console.print(f"[red]invalid --trust-root {item!r}; expected id=secret[/red]")
            raise typer.Exit(2)
        rid, secret = item.split("=", 1)
        roots[rid] = secret
    atts: list[ExternalAssuranceAttestation] = []
    for path in attestation:
        atts.append(
            ExternalAssuranceAttestation.model_validate(
                json.loads(Path(path).read_text(encoding="utf-8"))
            )
        )
    try:
        result = qualify_run(
            run_or_study,
            claim=claim,
            trust_roots=roots or None,
            attestations=atts or None,
        )
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    payload = result.model_dump(mode="json")
    payload["content_digest"] = result.digest
    if format == "json":
        _print_json(payload)
    else:
        typer.echo(f"level: {result.level}")
        typer.echo(f"ordinal: {result.ordinal}")
        typer.echo(f"security_grade_execution: {result.security_grade_execution}")
        typer.echo(f"blockers: {', '.join(result.blockers) or '(none)'}")
        typer.echo(f"claim_digest: {result.claim_digest}")
        typer.echo(f"resolver_version: {result.resolver_version}")
    raise typer.Exit(0)


__all__ = ["app"]
