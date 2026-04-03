import json
import zipfile
from pathlib import Path

from typer.testing import CliRunner

from pii_leak_hunter.analysis.exposure_graph import build_exposure_graph
from pii_leak_hunter.cli.main import app
from pii_leak_hunter.core.baseline import apply_baseline, apply_baseline_payload, write_baseline
from pii_leak_hunter.core.models import DetectionResult, Finding, ScanResult
from pii_leak_hunter.analysis.context import infer_asset_mapping
from pii_leak_hunter.hunts.recipes import apply_recipe, get_recipe, list_recipes
from pii_leak_hunter.output.evidence_pack import write_evidence_pack
from pii_leak_hunter.output.html_writer import write_html_report
from pii_leak_hunter.ui.presentation import build_diff_summary, group_findings


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


def test_baseline_payload_from_safe_scan_tracks_resolved_findings() -> None:
    current = ScanResult(
        findings=[
            Finding(
                id="keep",
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
    baseline = ScanResult(
        findings=[
            current.findings[0],
            Finding(
                id="resolved",
                record_id="r2",
                type="entity_detection",
                severity="medium",
                entities=[
                    DetectionResult(
                        entity_type="EMAIL_ADDRESS",
                        start=0,
                        end=4,
                        score=0.8,
                        value_hash="hash-b",
                        masked_preview="mail=***",
                    )
                ],
                context={},
                source="unit",
                safe_summary="Email detected.",
            ),
        ],
        records_scanned=2,
        source="unit",
    )

    updated = apply_baseline_payload(current, baseline.to_safe_dict())
    diff = build_diff_summary(updated)

    assert updated.findings[0].context["baseline_status"] == "existing"
    assert diff.new == 0
    assert diff.unchanged == 1
    assert diff.resolved == 1


def test_group_findings_clusters_repeated_hashes() -> None:
    findings = [
        Finding(
            id="1",
            record_id="r1",
            type="entity_detection",
            severity="high",
            entities=[
                DetectionResult(
                    entity_type="API_KEY",
                    start=0,
                    end=8,
                    score=0.9,
                    value_hash="same-hash",
                    masked_preview="key=***",
                )
            ],
            context={"exploitability_priority": "P2"},
            source="unit",
            safe_summary="API key detected.",
        ),
        Finding(
            id="2",
            record_id="r2",
            type="entity_detection",
            severity="medium",
            entities=[
                DetectionResult(
                    entity_type="API_KEY",
                    start=0,
                    end=8,
                    score=0.7,
                    value_hash="same-hash",
                    masked_preview="key=***",
                )
            ],
            context={"exploitability_priority": "P3"},
            source="unit",
            safe_summary="API key detected again.",
        ),
    ]

    groups = group_findings(findings)

    assert len(groups) == 1
    assert groups[0].count == 2
    assert groups[0].priority == "P2"


def test_html_report_masks_raw_values_and_renders_risk_context(tmp_path: Path) -> None:
    result = ScanResult(
        findings=[
            Finding(
                id="1",
                record_id="rec-1",
                type="credential_bundle",
                severity="critical",
                entities=[
                    DetectionResult(
                        entity_type="AWS_SECRET_ACCESS_KEY",
                        start=0,
                        end=20,
                        score=0.99,
                        value_hash="hash-secret",
                        masked_preview="aws_secret=****ABCD",
                        raw_value="super-secret-value",
                    )
                ],
                context={
                    "exploitability_priority": "P0",
                    "policy_tags": ["cloud", "credential"],
                    "blast_radius": "cloud-account",
                    "risk_reasons": ["The exposed value grants direct cloud or storage access."],
                    "remediation": ["Rotate the exposed credential or token immediately."],
                },
                source="unit",
                safe_summary="AWS credential material exposed together.",
            )
        ],
        records_scanned=1,
        source="unit",
    )

    report_path = tmp_path / "report.html"
    write_html_report(result, str(report_path), include_values=False)
    html = report_path.read_text(encoding="utf-8")

    assert "PII Leak Hunter Audit Report" in html
    assert "Exploitability Ladder" in html
    assert "Rotate the exposed credential or token immediately." in html
    assert "aws_secret=****ABCD" in html
    assert "super-secret-value" not in html


def test_recipe_registry_contains_expected_hunts() -> None:
    recipe_ids = {recipe.recipe_id for recipe in list_recipes()}
    assert "prod-credentials" in recipe_ids
    assert "secret-plus-pii" in recipe_ids
    assert len(recipe_ids) >= 20


def test_apply_recipe_filters_findings_to_high_signal_subset() -> None:
    result = ScanResult(
        findings=[
            Finding(
                id="a",
                record_id="r1",
                type="credential_bundle",
                severity="critical",
                entities=[
                    DetectionResult(
                        entity_type="AWS_SECRET_ACCESS_KEY",
                        start=0,
                        end=5,
                        score=0.9,
                        value_hash="hash-a",
                        masked_preview="****",
                    )
                ],
                context={"exploitability_priority": "P0"},
                source="unit",
                safe_summary="Bundle",
            ),
            Finding(
                id="b",
                record_id="r2",
                type="entity_detection",
                severity="low",
                entities=[
                    DetectionResult(
                        entity_type="EMAIL_ADDRESS",
                        start=0,
                        end=5,
                        score=0.6,
                        value_hash="hash-b",
                        masked_preview="mail=***",
                    )
                ],
                context={"exploitability_priority": "P4"},
                source="unit",
                safe_summary="Email",
            ),
        ],
        records_scanned=2,
        source="unit",
    )

    filtered = apply_recipe(result, "prod-credentials")

    assert len(filtered.findings) == 1
    assert filtered.metadata["hunt_recipe"]["id"] == "prod-credentials"


def test_exposure_graph_links_sources_records_findings_and_entities() -> None:
    findings = [
        Finding(
            id="1",
            record_id="rec-1",
            type="credential_bundle",
            severity="critical",
            entities=[
                DetectionResult(
                    entity_type="AWS_ACCESS_KEY_ID",
                    start=0,
                    end=20,
                    score=0.9,
                    value_hash="same-hash",
                    masked_preview="AKIA****",
                )
            ],
            context={"exploitability_priority": "P0"},
            source="cloudwatch",
            safe_summary="Key exposed",
        ),
        Finding(
            id="2",
            record_id="rec-2",
            type="entity_detection",
            severity="high",
            entities=[
                DetectionResult(
                    entity_type="AWS_ACCESS_KEY_ID",
                    start=0,
                    end=20,
                    score=0.8,
                    value_hash="same-hash",
                    masked_preview="AKIA****",
                )
            ],
            context={"exploitability_priority": "P1"},
            source="jira",
            safe_summary="Key repeated",
        ),
    ]

    graph = build_exposure_graph(findings)

    assert graph.metadata["repeated_entities"] == 1
    assert graph.metadata["nodes"] >= 5
    assert "digraph ExposureGraph" in graph.to_graphviz()


def test_asset_mapping_pulls_service_env_and_channel_fields() -> None:
    class Record:
        source = "slack:incident-room"
        attributes = {
            "service": "payments-api",
            "environment": "prod",
            "channel": "incident-room",
            "aws_account_id": "123456789012",
        }

    asset = infer_asset_mapping(Record())

    assert asset["service"] == "payments-api"
    assert asset["environment"] == "prod"
    assert asset["channel"] == "incident-room"
    assert asset["account"] == "123456789012"


def test_group_findings_tracks_timeline_and_sources() -> None:
    findings = [
        Finding(
            id="1",
            record_id="r1",
            type="entity_detection",
            severity="high",
            entities=[
                DetectionResult(
                    entity_type="API_KEY",
                    start=0,
                    end=8,
                    score=0.9,
                    value_hash="same-hash",
                    masked_preview="key=***",
                )
            ],
            context={"exploitability_priority": "P2", "record_timestamp": "2026-04-03T10:00:00Z"},
            source="slack",
            safe_summary="API key detected.",
        ),
        Finding(
            id="2",
            record_id="r2",
            type="entity_detection",
            severity="medium",
            entities=[
                DetectionResult(
                    entity_type="API_KEY",
                    start=0,
                    end=8,
                    score=0.7,
                    value_hash="same-hash",
                    masked_preview="key=***",
                )
            ],
            context={"exploitability_priority": "P3", "record_timestamp": "2026-04-04T10:00:00Z"},
            source="googleworkspace",
            safe_summary="API key detected again.",
        ),
    ]

    group = group_findings(findings)[0]

    assert group.first_seen == "2026-04-03T10:00:00Z"
    assert group.last_seen == "2026-04-04T10:00:00Z"
    assert set(group.sources) == {"slack", "googleworkspace"}
