from __future__ import annotations

from dataclasses import dataclass

from pii_leak_hunter.core.models import LogRecord, ScanResult
from pii_leak_hunter.hunts.recipes import apply_recipe
from pii_leak_hunter.core.scanner import Scanner


@dataclass(slots=True)
class Pipeline:
    scanner: Scanner | None = None

    def __post_init__(self) -> None:
        if self.scanner is None:
            self.scanner = Scanner()

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
        return apply_recipe(result, recipe_id)
