from pathlib import Path

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.core.pipeline import Pipeline
from pii_leak_hunter.output.markdown_writer import write_markdown


def test_pipeline_detects_cloud_credential_bundle_and_metadata(tmp_path: Path) -> None:
    records = [
        LogRecord(
            timestamp="2026-03-29T10:00:00Z",
            message=(
                "aws_access_key_id=AKIAABCDEFGHIJKLMNOP "
                "secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY "
                "secret_arn=arn:aws:secretsmanager:eu-west-1:123456789012:secret:prod/app/db-AbCdEf "
                "owner=alice@example.test"
            ),
            attributes={},
            source="unit",
        )
    ]

    result = Pipeline().run(records, source="unit")
    by_type = {finding.type: finding for finding in result.findings}

    assert "credential_bundle" in by_type
    bundle = by_type["credential_bundle"]
    assert bundle.severity == "critical"
    assert bundle.context["blast_radius"] == "cloud-account"
    assert bundle.context["exploitability_priority"] == "P0"
    assert "cloud" in bundle.context["policy_tags"]
    assert any("Rotate" in step or "rotate" in step for step in bundle.context["remediation"])

    md_path = tmp_path / "cloud.md"
    write_markdown(result, str(md_path))
    markdown = md_path.read_text(encoding="utf-8")
    assert "Blast radius" in markdown
    assert "Remediation" in markdown


def test_pipeline_detects_kubernetes_control_plane_secret() -> None:
    records = [
        LogRecord(
            timestamp="2026-03-29T10:01:00Z",
            message=(
                "server=https://k8s.example.internal:6443 "
                "bearer=eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYyJ9."
                "eyJpc3MiOiJrdWJlcm5ldGVzIiwic3ViIjoic3lzOnNlcnZpY2VhY2NvdW50In0."
                "c2lnbmF0dXJl"
            ),
            attributes={},
            source="unit",
        )
    ]

    result = Pipeline().run(records, source="unit")
    by_type = {finding.type: finding for finding in result.findings}

    assert "control_plane_secret" in by_type
    finding = by_type["control_plane_secret"]
    assert finding.severity == "critical"
    assert finding.context["blast_radius"] == "control-plane"
    assert finding.context["exploitability_priority"] == "P0"
    assert "kubernetes" in finding.context["policy_tags"]
