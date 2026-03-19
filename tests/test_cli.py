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
    result = runner.invoke(app, ["scan", "--query", "source:api", "--from", "-1h"])
    assert result.exit_code == 1
    assert "CORALOGIX_API_KEY" in result.stderr


def test_scan_supports_other_providers(monkeypatch) -> None:
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
