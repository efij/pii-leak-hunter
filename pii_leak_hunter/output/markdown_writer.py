from __future__ import annotations

from pathlib import Path

from pii_leak_hunter.core.models import ScanResult


def write_markdown(result: ScanResult, path: str, include_values: bool = False) -> None:
    lines = [
        "# PII Leak Hunter Report",
        "",
        f"- Source: `{result.source}`",
        f"- Records scanned: `{result.records_scanned}`",
        "",
        "## Severity Counts",
        "",
    ]
    for severity, count in result.severity_counts().items():
        lines.append(f"- {severity}: {count}")

    lines.extend(["", "## Findings", ""])
    if not result.findings:
        lines.append("No findings detected.")
    else:
        for finding in result.findings:
            lines.append(f"### {finding.severity.upper()} - {finding.type}")
            lines.append("")
            lines.append(f"- Record: `{finding.record_id}`")
            lines.append(f"- Source: `{finding.source}`")
            lines.append(f"- Summary: {finding.safe_summary}")
            for entity in finding.entities:
                lines.append(
                    f"- Entity: `{entity.entity_type}` | Hash: `{entity.value_hash[:12]}` | Preview: `{entity.masked_preview}`"
                )
                if include_values and entity.raw_value is not None:
                    lines.append(f"- Raw value: `{entity.raw_value}`")
            lines.append("")

    Path(path).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
