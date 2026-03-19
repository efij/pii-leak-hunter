from __future__ import annotations

from pathlib import Path

import typer

from pii_leak_hunter.core.models import ScanResult
from pii_leak_hunter.core.pipeline import Pipeline
from pii_leak_hunter.loader.file_loader import load_file
from pii_leak_hunter.output.csv_writer import write_csv
from pii_leak_hunter.output.json_writer import write_json
from pii_leak_hunter.output.markdown_writer import write_markdown
from pii_leak_hunter.output.sarif_writer import write_sarif
from pii_leak_hunter.providers.factory import SUPPORTED_PROVIDERS, build_provider, normalize_provider_name
from pii_leak_hunter.scoring.risk import exceeds_threshold
from pii_leak_hunter.utils.config import ConfigurationError

app = typer.Typer(help="Detect PII leaks and masking failures in logs.")


@app.command("scan-file")
def scan_file(
    path: Path,
    out_json: Path | None = typer.Option(None, "--out-json"),
    out_md: Path | None = typer.Option(None, "--out-md"),
    out_csv: Path | None = typer.Option(None, "--out-csv"),
    out_sarif: Path | None = typer.Option(None, "--out-sarif"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    unsafe_show_values: bool = typer.Option(False, "--unsafe-show-values"),
) -> None:
    """Scan a local log file."""
    try:
        result = Pipeline().run(load_file(str(path)), source=str(path), metadata={"mode": "file"})
        _emit_outputs(
            result,
            out_json=out_json,
            out_md=out_md,
            out_csv=out_csv,
            out_sarif=out_sarif,
            include_values=unsafe_show_values,
        )
        _print_summary(result)
        _exit_for_threshold(result, fail_on)
    except typer.Exit:
        raise
    except Exception as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command("scan")
def scan(
    provider: str = typer.Option("coralogix", "--provider"),
    query: str = typer.Option(..., "--query"),
    from_: str = typer.Option(..., "--from"),
    to: str = typer.Option("now", "--to"),
    out_json: Path | None = typer.Option(None, "--out-json"),
    out_md: Path | None = typer.Option(None, "--out-md"),
    out_csv: Path | None = typer.Option(None, "--out-csv"),
    out_sarif: Path | None = typer.Option(None, "--out-sarif"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    unsafe_show_values: bool = typer.Option(False, "--unsafe-show-values"),
) -> None:
    """Scan logs from a supported remote provider."""
    try:
        provider_name = normalize_provider_name(provider)
        if provider_name not in SUPPORTED_PROVIDERS:
            raise typer.BadParameter(
                f"provider must be one of {', '.join(SUPPORTED_PROVIDERS)}"
            )
        client = build_provider(provider_name)
        records = client.fetch(query=query, start=from_, end=to)
        result = Pipeline().run(
            records,
            source=provider_name,
            metadata={"mode": "remote", "provider": provider_name, "query": query, "from": from_, "to": to},
        )
        _emit_outputs(
            result,
            out_json=out_json,
            out_md=out_md,
            out_csv=out_csv,
            out_sarif=out_sarif,
            include_values=unsafe_show_values,
        )
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


def _emit_outputs(
    result: ScanResult,
    *,
    out_json: Path | None,
    out_md: Path | None,
    out_csv: Path | None,
    out_sarif: Path | None,
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


def _print_summary(result: ScanResult) -> None:
    typer.echo(f"Scanned {result.records_scanned} record(s) from {result.source}.")
    counts = result.severity_counts()
    typer.echo(
        "Findings: "
        + ", ".join(f"{severity}={count}" for severity, count in counts.items())
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
