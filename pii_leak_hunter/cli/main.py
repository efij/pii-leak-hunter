from __future__ import annotations

from pathlib import Path

import typer

from pii_leak_hunter.core.baseline import apply_baseline, write_baseline
from pii_leak_hunter.core.models import ScanResult
from pii_leak_hunter.core.pipeline import Pipeline
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

app = typer.Typer(help="Detect PII leaks and masking failures in logs.")


@app.command("scan-file")
def scan_file(
    path: Path,
    out_json: Path | None = typer.Option(None, "--out-json"),
    out_md: Path | None = typer.Option(None, "--out-md"),
    out_csv: Path | None = typer.Option(None, "--out-csv"),
    out_sarif: Path | None = typer.Option(None, "--out-sarif"),
    out_evidence: Path | None = typer.Option(None, "--out-evidence"),
    baseline_in: Path | None = typer.Option(None, "--baseline-in"),
    baseline_out: Path | None = typer.Option(None, "--baseline-out"),
    new_only: bool = typer.Option(False, "--new-only"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    unsafe_show_values: bool = typer.Option(False, "--unsafe-show-values"),
) -> None:
    """Scan a local log file."""
    try:
        loaded = build_source(str(path)).load()
        result = Pipeline().run(loaded.records, source=loaded.source, metadata=loaded.metadata)
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
    target: str | None = typer.Argument(None),
    provider: str = typer.Option("coralogix", "--provider"),
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
    to: str = typer.Option("now", "--to"),
    out_json: Path | None = typer.Option(None, "--out-json"),
    out_md: Path | None = typer.Option(None, "--out-md"),
    out_csv: Path | None = typer.Option(None, "--out-csv"),
    out_sarif: Path | None = typer.Option(None, "--out-sarif"),
    out_evidence: Path | None = typer.Option(None, "--out-evidence"),
    baseline_in: Path | None = typer.Option(None, "--baseline-in"),
    baseline_out: Path | None = typer.Option(None, "--baseline-out"),
    new_only: bool = typer.Option(False, "--new-only"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    unsafe_show_values: bool = typer.Option(False, "--unsafe-show-values"),
) -> None:
    """Scan logs from a supported remote provider or a URI/path target."""
    try:
        if is_target_source(target):
            loaded = build_source(target).load()
            result = Pipeline().run(loaded.records, source=loaded.source, metadata=loaded.metadata)
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
        result = Pipeline().run(
            records,
            source=provider_name,
            metadata={
                "mode": "remote",
                "provider": provider_name,
                "query": resolved_query,
                "from": resolved_from,
                "to": to,
            },
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
    validate: bool = typer.Option(False, "--validate"),
) -> None:
    """Show the least-privilege preset for an integration."""
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


def _print_summary(result: ScanResult) -> None:
    typer.echo(f"Scanned {result.records_scanned} record(s) from {result.source}.")
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
