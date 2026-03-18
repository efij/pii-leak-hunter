from __future__ import annotations

from pii_leak_hunter.core.models import DetectionResult, Finding, LogRecord
from pii_leak_hunter.detection.patterns import (
    HIGH_RISK_ENTITY_TYPES,
    PII_ENTITY_TYPES,
    SECRET_ENTITY_TYPES,
)
from pii_leak_hunter.utils.masking import digits_only, extract_mask_candidates


class Correlator:
    def correlate(
        self,
        *,
        record: LogRecord,
        text: str,
        detections: list[DetectionResult],
    ) -> list[Finding]:
        findings = [self._finding_from_detection(record, detection) for detection in detections]
        findings.extend(self._masking_failures(record, text, detections))
        findings.extend(self._identity_bundles(record, detections))
        findings.extend(self._secret_pii_overlap(record, detections))
        return findings

    def _finding_from_detection(self, record: LogRecord, detection: DetectionResult) -> Finding:
        return Finding(
            id=f"{record.record_id}:{detection.entity_type}:{detection.start}",
            record_id=record.record_id,
            type="entity_detection",
            severity="low",
            entities=[detection],
            context={"entity_type": detection.entity_type},
            source=record.source,
            safe_summary=f"{detection.entity_type} detected in {record.source}.",
        )

    def _masking_failures(
        self,
        record: LogRecord,
        text: str,
        detections: list[DetectionResult],
    ) -> list[Finding]:
        masked_tails = extract_mask_candidates(text)
        if not masked_tails:
            return []
        findings: list[Finding] = []
        for detection in detections:
            if detection.entity_type not in HIGH_RISK_ENTITY_TYPES or not detection.raw_value:
                continue
            candidate = digits_only(detection.raw_value)[-4:]
            if candidate and candidate in masked_tails:
                findings.append(
                    Finding(
                        id=f"{record.record_id}:masking:{detection.entity_type}:{candidate}",
                        record_id=record.record_id,
                        type="masking_failure",
                        severity="low",
                        entities=[detection],
                        context={"matched_tail": candidate},
                        source=record.source,
                        safe_summary=(
                            f"Masked and unmasked {detection.entity_type} variants appear together in one record."
                        ),
                    )
                )
        return findings

    def _identity_bundles(
        self,
        record: LogRecord,
        detections: list[DetectionResult],
    ) -> list[Finding]:
        people = [item for item in detections if item.entity_type == "PERSON"]
        high_risk = [item for item in detections if item.entity_type in HIGH_RISK_ENTITY_TYPES]
        if not people or not high_risk:
            return []
        entities = [people[0], high_risk[0]]
        return [
            Finding(
                id=f"{record.record_id}:identity-bundle",
                record_id=record.record_id,
                type="identity_bundle",
                severity="low",
                entities=entities,
                context={"bundle_size": len(entities)},
                source=record.source,
                safe_summary="Identity bundle detected in a single log record.",
            )
        ]

    def _secret_pii_overlap(
        self,
        record: LogRecord,
        detections: list[DetectionResult],
    ) -> list[Finding]:
        secrets = [item for item in detections if item.entity_type in SECRET_ENTITY_TYPES]
        pii = [
            item
            for item in detections
            if item.entity_type in PII_ENTITY_TYPES and item.entity_type not in SECRET_ENTITY_TYPES
        ]
        if not secrets or not pii:
            return []
        entities = [secrets[0], pii[0]]
        return [
            Finding(
                id=f"{record.record_id}:secret-pii",
                record_id=record.record_id,
                type="secret_pii_overlap",
                severity="low",
                entities=entities,
                context={"entity_types": [entity.entity_type for entity in entities]},
                source=record.source,
                safe_summary="Secret and PII detected together in one record.",
            )
        ]
