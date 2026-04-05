import json
import zipfile
from pathlib import Path

from typer.testing import CliRunner

from pii_leak_hunter.analysis.clustering import cluster_findings
from pii_leak_hunter.analysis.exposure_graph import build_exposure_graph
from pii_leak_hunter.analysis.timeline import build_timeline
from pii_leak_hunter.analysis.validation import ValidationEngine
from pii_leak_hunter.cli.main import app
from pii_leak_hunter.core.baseline import apply_baseline, apply_baseline_payload, write_baseline
from pii_leak_hunter.core.models import DetectionResult, Finding, ScanResult, ValidationResult
from pii_leak_hunter.analysis.context import infer_asset_mapping
from pii_leak_hunter.hunts.live import apply_hunt_baseline, build_diff_signatures, write_hunt_artifact
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


def test_hunt_command_writes_hunt_artifact(tmp_path: Path) -> None:
    runner = CliRunner()
    artifact_path = tmp_path / "hunt-artifact.json"

    result = runner.invoke(
        app,
        ["hunt", "prod-credentials", "fixtures/demo_logs.ndjson", "--baseline-out", str(artifact_path)],
    )

    assert result.exit_code == 0
    payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert payload["recipe"] == "prod-credentials"
    assert "cluster_signatures" in payload


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

    assert asset.service == "payments-api"
    assert asset.environment == "prod"
    assert asset.channel == "incident-room"
    assert asset.account == "123456789012"
    assert asset.asset_key


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


def test_timeline_validation_and_clustering_enrich_findings(monkeypatch) -> None:
    monkeypatch.setattr(
        "pii_leak_hunter.analysis.validation._aws_sts_check",
        lambda access_key, secret_key: ValidationResult(
            classification="likely_live",
            provider_family="aws",
            entity_type="AWS_SECRET_ACCESS_KEY",
            evidence=["stubbed sts"],
            confidence="high",
            provider_check_run=True,
        ),
    )
    findings = [
        Finding(
            id="1",
            record_id="r1",
            type="credential_bundle",
            severity="critical",
            entities=[
                DetectionResult(
                    entity_type="AWS_ACCESS_KEY_ID",
                    start=0,
                    end=20,
                    score=0.9,
                    value_hash="hash-ak",
                    masked_preview="AKIA****",
                    raw_value="AKIAABCDEFGHIJKLMNOP",
                ),
                DetectionResult(
                    entity_type="AWS_SECRET_ACCESS_KEY",
                    start=21,
                    end=61,
                    score=0.9,
                    value_hash="hash-sk",
                    masked_preview="****ABCD",
                    raw_value="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                ),
            ],
            context={
                "record_timestamp": "2026-04-03T10:00:00Z",
                "asset_summary": "payments-api / prod",
                "asset_key": "payments-api|prod",
                "exploitability_priority": "P0",
            },
            source="github",
            safe_summary="Bundle one",
        ),
        Finding(
            id="2",
            record_id="r2",
            type="credential_bundle",
            severity="critical",
            entities=[
                DetectionResult(
                    entity_type="AWS_ACCESS_KEY_ID",
                    start=0,
                    end=20,
                    score=0.9,
                    value_hash="hash-ak",
                    masked_preview="AKIA****",
                    raw_value="AKIAABCDEFGHIJKLMNOP",
                ),
                DetectionResult(
                    entity_type="AWS_SECRET_ACCESS_KEY",
                    start=21,
                    end=61,
                    score=0.9,
                    value_hash="hash-sk",
                    masked_preview="****ABCD",
                    raw_value="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                ),
            ],
            context={
                "record_timestamp": "2026-04-04T10:00:00Z",
                "asset_summary": "payments-api / prod",
                "asset_key": "payments-api|prod",
                "exploitability_priority": "P0",
            },
            source="slack",
            safe_summary="Bundle two",
        ),
    ]

    validation = ValidationEngine().validate_entities(findings)
    assert validation["families"]["aws"] >= 1
    timeline = build_timeline(findings)
    assert timeline["repeated_entity_groups"] >= 1
    clusters = cluster_findings(findings)

    assert len(clusters) == 1
    assert findings[0].context["timeline"]["source_count"] == 2
    assert findings[0].context["cluster_id"] == clusters[0].cluster_id
    assert findings[0].context["validation"][0]["classification"] in {"paired", "likely_live", "insufficient_scope"}


def test_hunt_artifact_tracks_new_clusters(tmp_path: Path) -> None:
    baseline = ScanResult(
        findings=[],
        records_scanned=0,
        source="unit",
        metadata={
            "cluster_summary": {
                "total_clusters": 1,
                "clusters": [
                    {
                        "cluster_id": "old",
                        "title": "Old Cluster",
                        "finding_type": "entity_detection",
                        "entity_hashes": ["hash-a"],
                        "assets": ["asset-a"],
                        "sources": ["slack"],
                        "timeline": {"first_seen": "", "last_seen": "", "source_count": 1, "asset_count": 1},
                    }
                ],
            }
        },
    )
    baseline_path = tmp_path / "hunt.json"
    write_hunt_artifact(baseline, str(baseline_path))

    result = ScanResult(
        findings=[
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
                        score=0.8,
                        value_hash="hash-b",
                        masked_preview="key=***",
                    )
                ],
                context={
                    "cluster_id": "new",
                    "cluster": {
                        "cluster_id": "new",
                        "title": "New Cluster",
                        "finding_type": "entity_detection",
                        "entity_hashes": ["hash-b"],
                        "assets": ["asset-b"],
                        "sources": ["github"],
                        "timeline": {"first_seen": "", "last_seen": "", "source_count": 1, "asset_count": 1},
                    },
                },
                source="github",
                safe_summary="new",
            )
        ],
        records_scanned=1,
        source="unit",
        metadata={
            "cluster_summary": {
                "total_clusters": 1,
                "clusters": [
                    {
                        "cluster_id": "new",
                        "title": "New Cluster",
                        "finding_type": "entity_detection",
                        "entity_hashes": ["hash-b"],
                        "assets": ["asset-b"],
                        "sources": ["github"],
                        "timeline": {"first_seen": "", "last_seen": "", "source_count": 1, "asset_count": 1},
                    }
                ],
            }
        },
    )

    updated = apply_hunt_baseline(result, json.loads(baseline_path.read_text(encoding="utf-8")))

    assert updated.metadata["hunt_summary"]["new_clusters"] == 1
    assert updated.findings[0].context["hunt_status"] == "new"


def test_build_diff_signatures_exposes_many_signature_families() -> None:
    result = ScanResult(
        findings=[
            Finding(
                id="1",
                record_id="r1",
                type="credential_bundle",
                severity="critical",
                entities=[
                    DetectionResult(
                        entity_type="AWS_SECRET_ACCESS_KEY",
                        start=0,
                        end=40,
                        score=0.9,
                        value_hash="hash-secret",
                        masked_preview="****ABCD",
                    )
                ],
                context={
                    "asset_key": "payments-api|prod",
                    "asset_summary": "payments-api / prod",
                    "asset": {"environment": "prod"},
                    "blast_radius": "cloud-account",
                    "validation": [
                        {
                            "entity_type": "AWS_SECRET_ACCESS_KEY",
                            "classification": "paired",
                            "provider_family": "aws",
                        }
                    ],
                    "cluster": {
                        "title": "Credential Bundle Spread",
                        "finding_type": "credential_bundle",
                        "priority": "P0",
                        "severity": "critical",
                        "entity_hashes": ["hash-secret"],
                        "assets": ["payments-api / prod"],
                        "sources": ["github", "slack"],
                    },
                },
                source="github",
                safe_summary="bundle",
            )
        ],
        records_scanned=1,
        source="github",
        metadata={
            "cluster_summary": {
                "total_clusters": 1,
                "clusters": [
                    {
                        "title": "Credential Bundle Spread",
                        "finding_type": "credential_bundle",
                        "priority": "P0",
                        "severity": "critical",
                        "entity_hashes": ["hash-secret"],
                        "assets": ["payments-api / prod"],
                        "sources": ["github", "slack"],
                    }
                ],
            }
        },
    )

    signatures = build_diff_signatures(result)

    assert len(signatures) == 65
    assert "cluster_exact" in signatures
    assert "validation_classification" in signatures
    assert "asset_environment" in signatures
    assert "provider_family" in signatures
    assert "cluster_seen_count_bucket" in signatures
    assert "entity_type_priority" in signatures
    assert "asset_provider_family" in signatures
    assert "source_validation_classification" in signatures
    assert "finding_type_provider_family" in signatures
