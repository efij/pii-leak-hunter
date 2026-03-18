from pathlib import Path

from pii_leak_hunter.core.pipeline import Pipeline
from pii_leak_hunter.loader.file_loader import load_file


def test_pipeline_detects_composite_findings() -> None:
    fixture = Path("fixtures/demo_logs.ndjson")
    result = Pipeline().run(load_file(str(fixture)), source=str(fixture))

    finding_types = {finding.type for finding in result.findings}
    severities = {finding.severity for finding in result.findings}

    assert result.records_scanned == 4
    assert "entity_detection" in finding_types
    assert "identity_bundle" in finding_types
    assert "masking_failure" in finding_types
    assert "secret_pii_overlap" in finding_types
    assert "critical" in severities
    safe_payload = result.to_safe_dict()
    assert "123-45-6789" not in str(safe_payload)
