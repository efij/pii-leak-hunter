from __future__ import annotations

from dataclasses import dataclass

from pii_leak_hunter.analysis.clustering import cluster_findings
from pii_leak_hunter.analysis.timeline import build_timeline
from pii_leak_hunter.analysis.validation import ValidationEngine
from pii_leak_hunter.core.models import LogRecord, ScanResult
from pii_leak_hunter.hunts.recipes import apply_recipe
from pii_leak_hunter.core.scanner import Scanner


@dataclass(slots=True)
class Pipeline:
    scanner: Scanner | None = None
    validation_engine: ValidationEngine | None = None

    def __post_init__(self) -> None:
        if self.scanner is None:
            self.scanner = Scanner()
        if self.validation_engine is None:
            self.validation_engine = ValidationEngine()

    def run(
        self,
        records: list[LogRecord],
        source: str,
        metadata: dict[str, str] | None = None,
        recipe_id: str | None = None,
    ) -> ScanResult:
        findings = []
        for record in records:
            findings.extend(self.scanner.scan_record(record))
        result = ScanResult(
            findings=findings,
            records_scanned=len(records),
            source=source,
            metadata=metadata or {},
        )
        result = apply_recipe(result, recipe_id)
        result.metadata["validation_summary"] = self.validation_engine.validate_entities(result.findings)
        result.metadata["timeline_summary"] = build_timeline(result.findings)
        clusters = cluster_findings(result.findings)
        result.metadata["cluster_summary"] = {
            "total_clusters": len(clusters),
            "clusters": [cluster.to_safe_dict() for cluster in clusters],
        }
        result.metadata["timeline_summary"] = build_timeline(result.findings)
        return result
