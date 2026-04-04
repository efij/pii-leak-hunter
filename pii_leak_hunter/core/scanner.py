from __future__ import annotations

from pii_leak_hunter.analysis.context import enrich_asset_context
from pii_leak_hunter.core.models import Finding, LogRecord
from pii_leak_hunter.core.normalizer import Normalizer
from pii_leak_hunter.correlation.correlator import Correlator
from pii_leak_hunter.detection.engine import DetectionEngine
from pii_leak_hunter.scoring.risk import enrich_finding_context, score
from pii_leak_hunter.utils.hashing import HashingService


class Scanner:
    def __init__(self, hashing_service: HashingService | None = None) -> None:
        hashing = hashing_service or HashingService()
        self.normalizer = Normalizer()
        self.detector = DetectionEngine(hashing_service=hashing)
        self.correlator = Correlator()

    def scan_record(self, record: LogRecord) -> list[Finding]:
        text, field_metadata = self.normalizer.normalize(record)
        detections = self.detector.detect(text, field_metadata=field_metadata)
        findings = self.correlator.correlate(record=record, text=text, detections=detections)
        for finding in findings:
            finding.severity = score(finding)
            enrich_finding_context(finding)
            enrich_asset_context(record, finding)
        return findings
