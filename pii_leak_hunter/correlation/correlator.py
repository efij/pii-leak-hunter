from __future__ import annotations

from pii_leak_hunter.core.models import DetectionResult, Finding, LogRecord
from pii_leak_hunter.detection.patterns import (
    HIGH_RISK_ENTITY_TYPES,
    INFRA_IDENTIFIER_ENTITY_TYPES,
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
        findings.extend(self._credential_bundles(record, detections))
        findings.extend(self._control_plane_bundles(record, detections))
        return findings

    def _finding_from_detection(self, record: LogRecord, detection: DetectionResult) -> Finding:
        return Finding(
            id=f"{record.record_id}:{detection.entity_type}:{detection.start}",
            record_id=record.record_id,
            type="entity_detection",
            severity="low",
            entities=[detection],
            context={"entity_type": detection.entity_type, "record_timestamp": record.timestamp},
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
                        context={"matched_tail": candidate, "record_timestamp": record.timestamp},
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
                context={"bundle_size": len(entities), "record_timestamp": record.timestamp},
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
                context={"entity_types": [entity.entity_type for entity in entities], "record_timestamp": record.timestamp},
                source=record.source,
                safe_summary="Secret and PII detected together in one record.",
            )
        ]

    def _credential_bundles(
        self,
        record: LogRecord,
        detections: list[DetectionResult],
    ) -> list[Finding]:
        entity_types = {item.entity_type for item in detections}
        bundle_members = [
            item
            for item in detections
            if item.entity_type in {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}
        ]
        if {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} <= entity_types and bundle_members:
            return [
                Finding(
                    id=f"{record.record_id}:credential-bundle",
                    record_id=record.record_id,
                    type="credential_bundle",
                    severity="low",
                    entities=bundle_members,
                    context={"entity_types": sorted({entity.entity_type for entity in bundle_members}), "record_timestamp": record.timestamp},
                    source=record.source,
                    safe_summary="Cloud credential bundle detected in a single record.",
                )
            ]
        return []

    def _control_plane_bundles(
        self,
        record: LogRecord,
        detections: list[DetectionResult],
    ) -> list[Finding]:
        entity_types = {item.entity_type for item in detections}
        if not {"KUBERNETES_BEARER_TOKEN", "KUBERNETES_API_SERVER"} <= entity_types:
            return []
        entities = [
            item
            for item in detections
            if item.entity_type in {"KUBERNETES_BEARER_TOKEN", "KUBERNETES_API_SERVER"}
        ]
        return [
            Finding(
                id=f"{record.record_id}:control-plane-secret",
                record_id=record.record_id,
                type="control_plane_secret",
                severity="low",
                entities=entities,
                context={
                    "entity_types": sorted({entity.entity_type for entity in entities}),
                    "infra_identifiers": [
                        entity.entity_type
                        for entity in entities
                        if entity.entity_type in INFRA_IDENTIFIER_ENTITY_TYPES
                    ],
                    "record_timestamp": record.timestamp,
                },
                source=record.source,
                safe_summary="Kubernetes control plane endpoint and bearer token detected together.",
            )
        ]
