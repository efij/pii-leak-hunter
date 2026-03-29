import json
import zipfile
from pathlib import Path

from typer.testing import CliRunner

from pii_leak_hunter.cli.main import app
from pii_leak_hunter.core.baseline import apply_baseline, write_baseline
from pii_leak_hunter.core.models import DetectionResult, Finding, ScanResult
from pii_leak_hunter.output.evidence_pack import write_evidence_pack


def test_baseline_marks_existing_and_new_findings(tmp_path: Path) -> None:
    result = ScanResult(
        findings=[
            Finding(
                id="1",
                record_id="r1",
                type="entity_detection",
                severity="high",
                entities=[
                    DetectionResult(
                        entity_type="AWS_ACCESS_KEY_ID",
                        start=0,
                        end=20,
                        score=0.9,
                        value_hash="hash-a",
                        masked_preview="AKIA************",
                    )
                ],
                context={},
                source="unit",
                safe_summary="AWS key detected.",
            )
        ],
        records_scanned=1,
        source="unit",
    )
    baseline_path = tmp_path / "baseline.json"
    write_baseline(result, str(baseline_path))

    updated = apply_baseline(result, str(baseline_path))
    assert updated.findings[0].context["baseline_status"] == "existing"


def test_evidence_pack_zip_contains_expected_files(tmp_path: Path) -> None:
    result = ScanResult(findings=[], records_scanned=0, source="unit")
    evidence_path = tmp_path / "evidence.zip"
    write_evidence_pack(result, str(evidence_path))

    assert evidence_path.exists()
    with zipfile.ZipFile(evidence_path) as archive:
        assert {"summary.json", "report.md", "evidence.json"} <= set(archive.namelist())


def test_least_privilege_command_outputs_preset() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["least-privilege", "notion"])
    assert result.exit_code == 0
    assert "Notion content-read integration" in result.stdout
    assert "read content" in result.stdout


def test_scan_file_supports_baseline_and_evidence_pack(tmp_path: Path) -> None:
    runner = CliRunner()
    baseline_path = tmp_path / "baseline.json"
    evidence_path = tmp_path / "evidence.zip"

    first = runner.invoke(app, ["scan-file", "fixtures/demo_logs.ndjson", "--baseline-out", str(baseline_path)])
    assert first.exit_code == 0
    assert baseline_path.exists()

    second = runner.invoke(
        app,
        [
            "scan-file",
            "fixtures/demo_logs.ndjson",
            "--baseline-in",
            str(baseline_path),
            "--new-only",
            "--out-evidence",
            str(evidence_path),
        ],
    )
    assert second.exit_code == 0
    assert evidence_path.exists()
    assert "Baseline: new=0" in second.stdout
