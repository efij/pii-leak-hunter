from __future__ import annotations

import json
from pathlib import Path

from pii_leak_hunter.core.models import ScanResult


def write_sarif(result: ScanResult, path: str, include_values: bool = False) -> None:
    rules = []
    seen_types: set[str] = set()
    for finding in result.findings:
        if finding.type in seen_types:
            continue
        seen_types.add(finding.type)
        rules.append(
            {
                "id": finding.type,
                "name": finding.type,
                "shortDescription": {"text": finding.safe_summary},
            }
        )

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pii-leak-hunter",
                        "rules": rules,
                    }
                },
                "results": [
                    {
                        "ruleId": finding.type,
                        "level": _severity_to_level(finding.severity),
                        "message": {"text": _finding_message(finding, include_values=include_values)},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": finding.source},
                                    "region": {"snippet": {"text": finding.safe_summary}},
                                }
                            }
                        ],
                    }
                    for finding in result.findings
                ],
            }
        ],
    }
    Path(path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")


def _severity_to_level(severity: str) -> str:
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }[severity]


def _finding_message(finding, include_values: bool) -> str:
    parts = [finding.safe_summary]
    if finding.entities:
        entity = finding.entities[0]
        parts.append(f"Entity={entity.entity_type}")
        parts.append(f"Hash={entity.value_hash[:12]}")
        if include_values and entity.raw_value:
            parts.append(f"Value={entity.raw_value}")
    return " | ".join(parts)
