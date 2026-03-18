from __future__ import annotations

import csv
from pathlib import Path

from pii_leak_hunter.core.models import ScanResult


def write_csv(result: ScanResult, path: str, include_values: bool = False) -> None:
    fieldnames = [
        "finding_id",
        "record_id",
        "severity",
        "type",
        "source",
        "entity_type",
        "value_hash",
        "masked_preview",
        "raw_value",
    ]
    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for finding in result.findings:
            for entity in finding.entities:
                writer.writerow(
                    {
                        "finding_id": finding.id,
                        "record_id": finding.record_id,
                        "severity": finding.severity,
                        "type": finding.type,
                        "source": finding.source,
                        "entity_type": entity.entity_type,
                        "value_hash": entity.value_hash,
                        "masked_preview": entity.masked_preview,
                        "raw_value": entity.raw_value if include_values else "",
                    }
                )
