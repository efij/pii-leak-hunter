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
            if finding.context.get("exploitability_priority"):
                lines.append(f"- Exploitability priority: `{finding.context['exploitability_priority']}`")
            if finding.context.get("policy_tags"):
                lines.append(f"- Tags: `{', '.join(finding.context['policy_tags'])}`")
            if finding.context.get("blast_radius"):
                lines.append(f"- Blast radius: `{finding.context['blast_radius']}`")
            if finding.context.get("risk_reasons"):
                lines.append(f"- Risk reasons: {'; '.join(finding.context['risk_reasons'])}")
            if finding.context.get("remediation"):
                lines.append(f"- Remediation: {'; '.join(finding.context['remediation'])}")
            for entity in finding.entities:
                lines.append(
                    f"- Entity: `{entity.entity_type}` | Hash: `{entity.value_hash[:12]}` | Preview: `{entity.masked_preview}`"
                )
                if include_values and entity.raw_value is not None:
                    lines.append(f"- Raw value: `{entity.raw_value}`")
            lines.append("")

    Path(path).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
