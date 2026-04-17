from pathlib import Path

from typer.testing import CliRunner

from pii_leak_hunter.cli.main import app
from pii_leak_hunter.core.models import LogRecord


runner = CliRunner()


def test_scan_file_generates_outputs_and_threshold_exit(tmp_path: Path) -> None:
    json_path = tmp_path / "findings.json"
    md_path = tmp_path / "findings.md"

    result = runner.invoke(
        app,
        [
            "scan-file",
            "fixtures/demo_logs.ndjson",
            "--out-json",
            str(json_path),
            "--out-md",
            str(md_path),
            "--fail-on",
            "high",
        ],
    )

    assert result.exit_code == 2
    assert json_path.exists()
    assert md_path.exists()
    assert "Scanned 4 record(s)" in result.stdout


def test_scan_requires_coralogix_configuration() -> None:
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 1
    assert "CORALOGIX_API_KEY" in result.stderr


def test_scan_supports_other_providers(monkeypatch) -> None:
    class FakeProvider:
        last_fetch_details = {"records_parsed": 1, "raw_rows_received": 1}

        def fetch(self, query: str, start: str, end: str):
            assert query == "*"
            assert start == "-24h"
            assert end == "now"
            return [
                LogRecord(
                    timestamp="2026-03-18T00:00:00Z",
                    message="owner@example.test",
                    attributes={"message": "owner@example.test"},
                    source="datadog",
                )
            ]

    monkeypatch.setattr("pii_leak_hunter.cli.main.build_provider", lambda name: FakeProvider())
    result = runner.invoke(
        app,
        ["scan", "--provider", "datadog"],
    )
    assert result.exit_code == 0
    assert "Scanned 1 record(s) from datadog." in result.stdout
    assert "Provider details:" in result.stdout


def test_scan_supports_custom_provider_filters(monkeypatch) -> None:
    class FakeProvider:
        def fetch(self, query: str, start: str, end: str):
            assert query == "service:mailer"
            assert start == "-1h"
            assert end == "now"
            return [
                LogRecord(
                    timestamp="2026-03-18T00:00:00Z",
                    message="owner@example.test",
                    attributes={"message": "owner@example.test"},
                    source="datadog",
                )
            ]

    monkeypatch.setattr("pii_leak_hunter.cli.main.build_provider", lambda name: FakeProvider())
    result = runner.invoke(
        app,
        ["scan", "--provider", "datadog", "--query", "service:mailer", "--from", "-1h"],
    )
    assert result.exit_code == 0
    assert "Scanned 1 record(s) from datadog." in result.stdout


def test_scan_uses_source_logs_default_for_coralogix(monkeypatch) -> None:
    class FakeProvider:
        def fetch(self, query: str, start: str, end: str):
            assert query == "source logs"
            assert start == "-24h"
            assert end == "now"
            return []

    monkeypatch.setattr("pii_leak_hunter.cli.main.build_provider", lambda name: FakeProvider())
    result = runner.invoke(app, ["scan", "--provider", "coralogix"])
    assert result.exit_code == 0
    assert "Scanned 0 record(s) from coralogix." in result.stdout


def test_scan_supports_unified_target_path() -> None:
    result = runner.invoke(
        app,
        ["scan", "fixtures/demo_logs.ndjson"],
    )
    assert result.exit_code == 0
    assert "Scanned 4 record(s)" in result.stdout


def test_cli_version_surface_is_visible() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert "PII Leak Hunter v7.3.0" in result.stdout
    assert "https://github.com/efij/pii-leak-hunter" in result.stdout
    assert "Hunt diff signatures: 80 families" in result.stdout
