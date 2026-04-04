from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class LogRecord:
    timestamp: str
    message: str
    attributes: dict[str, Any]
    source: str
    record_id: str = ""


@dataclass(slots=True)
class AssetContext:
    service: str = ""
    team: str = ""
    environment: str = ""
    account: str = ""
    project: str = ""
    repository: str = ""
    workspace: str = ""
    cluster: str = ""
    region: str = ""
    channel: str = ""
    table: str = ""
    board: str = ""
    team_space: str = ""
    ticket_queue: str = ""
    source: str = ""
    asset_key: str = ""
    asset_summary: str = ""

    def to_safe_dict(self) -> dict[str, str]:
        return {
            key: value
            for key, value in asdict(self).items()
            if value not in {"", None}
        }


@dataclass(slots=True)
class TimelineSummary:
    first_seen: str = ""
    last_seen: str = ""
    seen_count: int = 0
    source_count: int = 0
    asset_count: int = 0
    spread_sources: list[str] = field(default_factory=list)
    spread_assets: list[str] = field(default_factory=list)
    repeated_hashes: list[str] = field(default_factory=list)

    def to_safe_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ValidationResult:
    classification: str
    provider_family: str
    entity_type: str
    evidence: list[str] = field(default_factory=list)
    confidence: str = "medium"
    provider_check_run: bool = False
    supporting_entity_types: list[str] = field(default_factory=list)

    def to_safe_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ExposureCluster:
    cluster_id: str
    title: str
    priority: str
    severity: str
    member_finding_ids: list[str]
    entity_hashes: list[str]
    assets: list[str]
    sources: list[str]
    timeline: TimelineSummary
    validation: list[ValidationResult] = field(default_factory=list)
    finding_type: str = ""
    seen_count: int = 0

    def to_safe_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "title": self.title,
            "priority": self.priority,
            "severity": self.severity,
            "member_finding_ids": self.member_finding_ids,
            "entity_hashes": self.entity_hashes,
            "assets": self.assets,
            "sources": self.sources,
            "timeline": self.timeline.to_safe_dict(),
            "validation": [item.to_safe_dict() for item in self.validation],
            "finding_type": self.finding_type,
            "seen_count": self.seen_count,
        }


@dataclass(slots=True)
class DetectionResult:
    entity_type: str
    start: int
    end: int
    score: float
    value_hash: str
    masked_preview: str
    raw_value: str | None = None
    field_name: str | None = None
    detection_source: str = "regex"
    is_masked: bool = False
    tags: list[str] = field(default_factory=list)

    def to_safe_dict(self, include_values: bool = False) -> dict[str, Any]:
        payload = asdict(self)
        if not include_values:
            payload.pop("raw_value", None)
        return payload


@dataclass(slots=True)
class Finding:
    id: str
    record_id: str
    type: str
    severity: str
    entities: list[DetectionResult]
    context: dict[str, Any]
    source: str
    safe_summary: str

    def to_safe_dict(self, include_values: bool = False) -> dict[str, Any]:
        return {
            "id": self.id,
            "record_id": self.record_id,
            "type": self.type,
            "severity": self.severity,
            "source": self.source,
            "safe_summary": self.safe_summary,
            "context": self.context,
            "entities": [
                entity.to_safe_dict(include_values=include_values)
                for entity in self.entities
            ],
        }


@dataclass(slots=True)
class ScanResult:
    findings: list[Finding]
    records_scanned: int
    source: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def to_safe_dict(self, include_values: bool = False) -> dict[str, Any]:
        return {
            "source": self.source,
            "records_scanned": self.records_scanned,
            "metadata": self.metadata,
            "severity_counts": self.severity_counts(),
            "findings": [
                finding.to_safe_dict(include_values=include_values)
                for finding in self.findings
            ],
        }
