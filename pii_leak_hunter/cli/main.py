from __future__ import annotations

from pathlib import Path

import typer

from pii_leak_hunter import __version__
from pii_leak_hunter.core.baseline import apply_baseline, write_baseline
from pii_leak_hunter.core.models import ScanResult
from pii_leak_hunter.core.pipeline import Pipeline
from pii_leak_hunter.hunts.live import (
    DIFF_SIGNATURE_FAMILIES,
    apply_hunt_baseline,
    load_hunt_artifact,
    prepare_hunt_result,
    write_hunt_artifact,
)
from pii_leak_hunter.hunts.recipes import get_recipe, list_recipes
from pii_leak_hunter.output.evidence_pack import write_evidence_pack
from pii_leak_hunter.output.csv_writer import write_csv
from pii_leak_hunter.output.json_writer import write_json
from pii_leak_hunter.output.markdown_writer import write_markdown
from pii_leak_hunter.output.sarif_writer import write_sarif
from pii_leak_hunter.providers.factory import (
    SUPPORTED_PROVIDERS,
    build_provider,
    normalize_provider_name,
    resolve_provider_scan_options,
)
from pii_leak_hunter.scoring.risk import exceeds_threshold
from pii_leak_hunter.security.least_privilege import PRESETS, get_preset, validate_preset
from pii_leak_hunter.sources.registry import build_source, is_target_source
from pii_leak_hunter.utils.config import ConfigurationError

APP_NAME = "PII Leak Hunter"
REPO_URL = "https://github.com/efij/pii-leak-hunter"
DIFF_SIGNATURE_FAMILY_COUNT = len(DIFF_SIGNATURE_FAMILIES)

app = typer.Typer(
    help=(
        "Operator-grade leak hunting for logs, SaaS, and operational data.\n\n"
        f"Version: {__version__}\n"
        f"Repo: {REPO_URL}\n"
        f"Hunt diff signatures: {DIFF_SIGNATURE_FAMILY_COUNT} families\n\n"
        "Start simple:\n"
        "  pii-leak-hunter scan --provider datadog\n"
        "  pii-leak-hunter scan github://your-org\n"
        "  pii-leak-hunter hunt prod-credentials --provider cloudwatch\n"
    ),
    add_completion=False,
    rich_markup_mode="markdown",
    no_args_is_help=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        help="Show version, repo link, and hunt diff signature pack details.",
        is_eager=True,
    ),
) -> None:
    if version:
        _print_platform_header()
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        _print_platform_header()
        typer.echo(ctx.get_help())
        raise typer.Exit()


@app.command("scan-file")
def scan_file(
    path: Path,
    out_json: Path | None = typer.Option(None, "--out-json", help="Write filtered findings to JSON."),
    out_md: Path | None = typer.Option(None, "--out-md", help="Write a Markdown report."),
    out_csv: Path | None = typer.Option(None, "--out-csv", help="Write a flat CSV export."),
    out_sarif: Path | None = typer.Option(None, "--out-sarif", help="Write SARIF for CI/code-scanning workflows."),
    out_evidence: Path | None = typer.Option(None, "--out-evidence", help="Write an evidence pack zip."),
    baseline_in: Path | None = typer.Option(None, "--baseline-in", help="Compare findings against a prior baseline JSON."),
    baseline_out: Path | None = typer.Option(None, "--baseline-out", help="Write a baseline JSON artifact for future diffs."),
    new_only: bool = typer.Option(False, "--new-only", help="Keep only findings that are new versus the baseline."),
    recipe: str | None = typer.Option(None, "--recipe", help="Filter the result through a built-in hunt recipe."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Exit with code 2 if any finding meets or exceeds this severity."),
    unsafe_show_values: bool = typer.Option(False, "--unsafe-show-values", help="Include raw values in exported files."),
) -> None:
    """Scan local files, directories, or compressed log artifacts."""
    try:
        _print_command_banner("scan-file")
        _validate_recipe(recipe)
        loaded = build_source(str(path)).load()
        result = Pipeline().run(loaded.records, source=loaded.source, metadata=loaded.metadata, recipe_id=recipe)
        result = _apply_baseline_if_requested(result, baseline_in=baseline_in, new_only=new_only)
        _emit_outputs(
            result,
            out_json=out_json,
            out_md=out_md,
            out_csv=out_csv,
            out_sarif=out_sarif,
            out_evidence=out_evidence,
            include_values=unsafe_show_values,
        )
        if baseline_out:
            write_baseline(result, str(baseline_out))
        _print_summary(result)
        _exit_for_threshold(result, fail_on)
    except typer.Exit:
        raise
    except Exception as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command("scan")
def scan(
    target: str | None = typer.Argument(None, help="Optional file path or source URI like github://org or teams://workspace?..."),
    provider: str = typer.Option("coralogix", "--provider", help="Remote log provider when no URI/path target is given."),
    query: str | None = typer.Option(
        None,
        "--query",
        help="Optional provider-native filter. Omit it to scan all logs for leaks.",
    ),
    from_: str | None = typer.Option(
        None,
        "--from",
        help="Start time for the scan window. Defaults to -24h.",
    ),
    to: str = typer.Option("now", "--to", help="End time for the scan window."),
    out_json: Path | None = typer.Option(None, "--out-json", help="Write filtered findings to JSON."),
    out_md: Path | None = typer.Option(None, "--out-md", help="Write a Markdown report."),
    out_csv: Path | None = typer.Option(None, "--out-csv", help="Write a flat CSV export."),
    out_sarif: Path | None = typer.Option(None, "--out-sarif", help="Write SARIF for CI/code-scanning workflows."),
    out_evidence: Path | None = typer.Option(None, "--out-evidence", help="Write an evidence pack zip."),
    baseline_in: Path | None = typer.Option(None, "--baseline-in", help="Compare findings against a prior baseline JSON."),
    baseline_out: Path | None = typer.Option(None, "--baseline-out", help="Write a baseline JSON artifact for future diffs."),
    new_only: bool = typer.Option(False, "--new-only", help="Keep only findings that are new versus the baseline."),
    recipe: str | None = typer.Option(None, "--recipe", help="Filter the result through a built-in hunt recipe."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Exit with code 2 if any finding meets or exceeds this severity."),
    unsafe_show_values: bool = typer.Option(False, "--unsafe-show-values", help="Include raw values in exported files."),
) -> None:
    """Scan a remote provider or a local/source URI target with automatic leak hunting."""
    try:
        _print_command_banner("scan")
        _validate_recipe(recipe)
        if is_target_source(target):
            loaded = build_source(target).load()
            result = Pipeline().run(loaded.records, source=loaded.source, metadata=loaded.metadata, recipe_id=recipe)
            result = _apply_baseline_if_requested(result, baseline_in=baseline_in, new_only=new_only)
            _emit_outputs(
                result,
                out_json=out_json,
                out_md=out_md,
                out_csv=out_csv,
                out_sarif=out_sarif,
                out_evidence=out_evidence,
                include_values=unsafe_show_values,
            )
            if baseline_out:
                write_baseline(result, str(baseline_out))
            _print_summary(result)
            _exit_for_threshold(result, fail_on)
            return

        provider_name = normalize_provider_name(provider)
        if provider_name not in SUPPORTED_PROVIDERS:
            raise typer.BadParameter(
                f"provider must be one of {', '.join(SUPPORTED_PROVIDERS)}"
            )
        resolved_query, resolved_from = resolve_provider_scan_options(provider_name, query, from_)
        client = build_provider(provider_name)
        records = client.fetch(query=resolved_query, start=resolved_from, end=to)
        provider_details = getattr(client, "last_fetch_details", {})
        result = Pipeline().run(
            records,
            source=provider_name,
            metadata={
                "mode": "remote",
                "provider": provider_name,
                "query": resolved_query,
                "from": resolved_from,
                "to": to,
                "provider_details": provider_details,
            },
            recipe_id=recipe,
        )
        result = _apply_baseline_if_requested(result, baseline_in=baseline_in, new_only=new_only)
        _emit_outputs(
            result,
            out_json=out_json,
            out_md=out_md,
            out_csv=out_csv,
            out_sarif=out_sarif,
            out_evidence=out_evidence,
            include_values=unsafe_show_values,
        )
        if baseline_out:
            write_baseline(result, str(baseline_out))
        _print_summary(result)
        _exit_for_threshold(result, fail_on)
    except typer.Exit:
        raise
    except ConfigurationError as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command("least-privilege")
def least_privilege(
    integration: str = typer.Argument(...),
    validate: bool = typer.Option(False, "--validate", help="Echo the preset status block after the preset details."),
) -> None:
    """Show the least-privilege preset for an integration."""
    _print_command_banner("least-privilege")
    preset = get_preset(integration)
    if preset is None:
        typer.echo(f"Unknown integration. Available: {', '.join(sorted(PRESETS))}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"{preset.title}")
    typer.echo(f"Integration: {preset.integration}")
    typer.echo(f"Minimum access: {preset.minimum_access}")
    typer.echo("Required scopes:")
    for scope in preset.required_scopes:
        typer.echo(f"- {scope}")
    typer.echo("Notes:")
    for note in preset.notes:
        typer.echo(f"- {note}")
    if validate:
        info = validate_preset(integration)
        typer.echo(f"Validation status: {info['status']}")


@app.command("recipes")
def recipes() -> None:
    """List built-in hunt recipes."""
    _print_command_banner("recipes")
    for recipe in list_recipes():
        typer.echo(f"{recipe.recipe_id}: {recipe.title}")
        typer.echo(f"  {recipe.description}")


@app.command("hunt")
def hunt(
    recipe: str = typer.Argument(..., help="Built-in hunt recipe id."),
    target: str | None = typer.Argument(None, help="Optional file path or source URI. If omitted, provider mode is used."),
    provider: str = typer.Option("coralogix", "--provider", help="Remote log provider when no URI/path target is given."),
    query: str | None = typer.Option(None, "--query", help="Optional provider-native filter. Omit it to let the hunt scan broadly."),
    from_: str | None = typer.Option(None, "--from", help="Start time for the hunt window. Defaults to -24h."),
    to: str = typer.Option("now", "--to", help="End time for the hunt window."),
    baseline_in: Path | None = typer.Option(None, "--baseline-in", help="Compare this hunt against a previous hunt artifact."),
    baseline_out: Path | None = typer.Option(None, "--baseline-out", help="Write a hunt artifact for future diff-based reruns."),
    new_only: bool = typer.Option(False, "--new-only", help="Keep only newly introduced clusters."),
    out_json: Path | None = typer.Option(None, "--out-json", help="Write filtered findings to JSON."),
    out_md: Path | None = typer.Option(None, "--out-md", help="Write a Markdown report."),
    out_csv: Path | None = typer.Option(None, "--out-csv", help="Write a flat CSV export."),
    out_sarif: Path | None = typer.Option(None, "--out-sarif", help="Write SARIF for CI/code-scanning workflows."),
    out_evidence: Path | None = typer.Option(None, "--out-evidence", help="Write an evidence pack zip."),
    unsafe_show_values: bool = typer.Option(False, "--unsafe-show-values", help="Include raw values in exported files."),
) -> None:
    """Run a recipe-driven hunt with artifact output and campaign-level diffing."""
    try:
        _print_command_banner("hunt")
        _validate_recipe(recipe)
        result, target_label, lookback = _load_scan_result(target, provider, query, from_, to, recipe)
        result = prepare_hunt_result(result, recipe_id=recipe, target=target_label, lookback=lookback)
        if baseline_in:
            result = apply_hunt_baseline(result, load_hunt_artifact(str(baseline_in)), new_only=new_only, baseline_source=str(baseline_in))
        _emit_outputs(
            result,
            out_json=out_json,
            out_md=out_md,
            out_csv=out_csv,
            out_sarif=out_sarif,
            out_evidence=out_evidence,
            include_values=unsafe_show_values,
        )
        if baseline_out:
            write_hunt_artifact(result, str(baseline_out))
        _print_summary(result)
    except typer.Exit:
        raise
    except ConfigurationError as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


def _emit_outputs(
    result: ScanResult,
    *,
    out_json: Path | None,
    out_md: Path | None,
    out_csv: Path | None,
    out_sarif: Path | None,
    out_evidence: Path | None,
    include_values: bool,
) -> None:
    if out_json:
        write_json(result, str(out_json), include_values=include_values)
    if out_md:
        write_markdown(result, str(out_md), include_values=include_values)
    if out_csv:
        write_csv(result, str(out_csv), include_values=include_values)
    if out_sarif:
        write_sarif(result, str(out_sarif), include_values=include_values)
    if out_evidence:
        write_evidence_pack(result, str(out_evidence), include_values=include_values)


def _load_scan_result(
    target: str | None,
    provider: str,
    query: str | None,
    from_: str | None,
    to: str,
    recipe: str | None,
) -> tuple[ScanResult, str, str]:
    if is_target_source(target):
        loaded = build_source(target).load()
        result = Pipeline().run(loaded.records, source=loaded.source, metadata=loaded.metadata, recipe_id=recipe)
        return result, target or loaded.source, "n/a"

    provider_name = normalize_provider_name(provider)
    if provider_name not in SUPPORTED_PROVIDERS:
        raise typer.BadParameter(f"provider must be one of {', '.join(SUPPORTED_PROVIDERS)}")
    resolved_query, resolved_from = resolve_provider_scan_options(provider_name, query, from_)
    client = build_provider(provider_name)
    records = client.fetch(query=resolved_query, start=resolved_from, end=to)
    provider_details = getattr(client, "last_fetch_details", {})
    result = Pipeline().run(
        records,
        source=provider_name,
        metadata={
            "mode": "remote",
            "provider": provider_name,
            "query": resolved_query,
            "from": resolved_from,
            "to": to,
            "provider_details": provider_details,
        },
        recipe_id=recipe,
    )
    return result, provider_name, resolved_from


def _print_platform_header() -> None:
    typer.echo(f"{APP_NAME} v{__version__}")
    typer.echo(f"Repo: {REPO_URL}")
    typer.echo(f"Hunt diff signatures: {DIFF_SIGNATURE_FAMILY_COUNT} families")
    typer.echo("")


def _print_command_banner(command: str) -> None:
    typer.echo(f"[{APP_NAME} v{__version__}] {command} | {REPO_URL}")


def _print_summary(result: ScanResult) -> None:
    typer.echo(f"Scanned {result.records_scanned} record(s) from {result.source}.")
    provider_details = result.metadata.get("provider_details")
    if isinstance(provider_details, dict) and provider_details:
        typer.echo("Provider details:")
        for key, value in provider_details.items():
            typer.echo(f"  {key}: {value}")
    counts = result.severity_counts()
    typer.echo(
        "Findings: "
        + ", ".join(f"{severity}={count}" for severity, count in counts.items())
    )
    baseline = result.metadata.get("baseline")
    if isinstance(baseline, dict):
        typer.echo(
            f"Baseline: new={baseline.get('new_findings', 0)}, existing={baseline.get('existing_findings', 0)}"
        )


def _exit_for_threshold(result: ScanResult, threshold: str | None) -> None:
    if threshold is None:
        return
    threshold = threshold.lower()
    if threshold not in {"low", "medium", "high", "critical"}:
        raise typer.BadParameter("fail-on must be one of low, medium, high, critical")
    for finding in result.findings:
        if exceeds_threshold(finding.severity, threshold):
            raise typer.Exit(code=2)


def _apply_baseline_if_requested(
    result: ScanResult,
    *,
    baseline_in: Path | None,
    new_only: bool,
) -> ScanResult:
    if baseline_in:
        return apply_baseline(result, str(baseline_in), new_only=new_only)
    return result


def _validate_recipe(recipe: str | None) -> None:
    if recipe and get_recipe(recipe) is None:
        raise typer.BadParameter("Unknown recipe. Use `pii-leak-hunter recipes` to list built-in recipes.")
