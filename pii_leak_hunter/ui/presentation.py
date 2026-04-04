from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from pii_leak_hunter.core.models import DetectionResult, Finding, ScanResult
from pii_leak_hunter.scoring.risk import SEVERITY_ORDER


PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
INCIDENT_PRIORITY = {
    "credential_bundle": 0,
    "control_plane_secret": 1,
    "secret_pii_overlap": 2,
    "identity_bundle": 3,
}


@dataclass(slots=True)
class DiffSummary:
    new: int = 0
    unchanged: int = 0
    resolved: int = 0
    total_current: int = 0
    total_baseline: int = 0
    new_only: bool = False

    @property
    def active(self) -> bool:
        return self.total_baseline > 0 or self.new > 0 or self.unchanged > 0 or self.resolved > 0


@dataclass(slots=True)
class PresentationGroup:
    key: str
    title: str
    severity: str
    priority: str
    finding_type: str
    preview: str
    raw_preview: str
    entity_types: list[str]
    hashes: list[str]
    baseline_statuses: list[str]
    sources: list[str]
    first_seen: str
    last_seen: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def record_ids(self) -> list[str]:
        return [finding.record_id for finding in self.findings]


def build_diff_summary(result: ScanResult) -> DiffSummary:
    baseline = result.metadata.get("baseline")
    if not isinstance(baseline, dict):
        return DiffSummary(total_current=len(result.findings))
    return DiffSummary(
        new=int(baseline.get("new_findings", 0)),
        unchanged=int(
            baseline.get("unchanged_findings", baseline.get("existing_findings", 0))
        ),
        resolved=int(baseline.get("resolved_findings", 0)),
        total_current=int(baseline.get("total_current_signatures", len(result.findings))),
        total_baseline=int(baseline.get("total_baseline_signatures", 0)),
        new_only=bool(baseline.get("new_only", False)),
    )


def group_findings(findings: list[Finding]) -> list[PresentationGroup]:
    grouped: dict[str, PresentationGroup] = {}
    for finding in findings:
        key, title = _group_identity(finding)
        group = grouped.get(key)
        cluster = finding.context.get("cluster", {})
        cluster_timeline = cluster.get("timeline", {}) if isinstance(cluster, dict) else {}
        entity_types = sorted({entity.entity_type for entity in finding.entities})
        hashes = sorted({entity.value_hash[:12] for entity in finding.entities})
        statuses = [str(finding.context.get("baseline_status", "current"))]
        if group is None:
            group = PresentationGroup(
                key=key,
                title=str(cluster.get("title", title)),
                severity=str(cluster.get("severity", finding.severity)),
                priority=str(cluster.get("priority", finding.context.get("exploitability_priority", "P4"))),
                finding_type=str(cluster.get("finding_type", finding.type)),
                preview=_best_preview(finding.entities, include_values=False),
                raw_preview=_best_preview(finding.entities, include_values=True),
                entity_types=entity_types,
                hashes=hashes,
                baseline_statuses=statuses,
                sources=sorted({finding.source}),
                first_seen=str(cluster_timeline.get("first_seen", finding.context.get("record_timestamp", ""))),
                last_seen=str(cluster_timeline.get("last_seen", finding.context.get("record_timestamp", ""))),
                findings=[finding],
            )
            grouped[key] = group
            continue
        group.findings.append(finding)
        group.severity = _max_severity(group.severity, finding.severity)
        group.priority = _min_priority(group.priority, str(finding.context.get("exploitability_priority", "P4")))
        group.entity_types = sorted(set(group.entity_types) | set(entity_types))
        group.hashes = sorted(set(group.hashes) | set(hashes))
        group.baseline_statuses = sorted(set(group.baseline_statuses) | set(statuses))
        group.sources = sorted(set(group.sources) | {finding.source})
        timestamp = str(finding.context.get("record_timestamp", ""))
        if timestamp and (not group.first_seen or timestamp < group.first_seen):
            group.first_seen = timestamp
        if timestamp and (not group.last_seen or timestamp > group.last_seen):
            group.last_seen = timestamp
        masked_preview = _best_preview(finding.entities, include_values=False)
        raw_preview = _best_preview(finding.entities, include_values=True)
        if len(group.preview) < len(masked_preview):
            group.preview = masked_preview
        if len(group.raw_preview) < len(raw_preview):
            group.raw_preview = raw_preview
    return sorted(grouped.values(), key=_group_sort_key)


def build_findings_rows(groups: list[PresentationGroup], *, include_values: bool = False) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for group in groups:
        rows.append(
            {
                "group": group.title,
                "severity": group.severity,
                "priority": group.priority,
                "occurrences": group.count,
                "baseline": ", ".join(group.baseline_statuses),
                "entities": ", ".join(group.entity_types),
                "preview": group.raw_preview if include_values else group.preview,
                "records": ", ".join(group.record_ids[:3]),
                "sources": ", ".join(group.sources[:3]),
                "first_seen": group.first_seen,
                "last_seen": group.last_seen,
            }
        )
    return rows


def top_entity_families(findings: list[Finding], limit: int = 5) -> list[tuple[str, int]]:
    counts: Counter[str] = Counter()
    for finding in findings:
        counts.update(entity.entity_type for entity in finding.entities)
    return counts.most_common(limit)


def exploitability_counts(findings: list[Finding]) -> list[tuple[str, int]]:
    counts: Counter[str] = Counter()
    for finding in findings:
        counts.update([str(finding.context.get("exploitability_priority", "P4"))])
    ordered = sorted(counts.items(), key=lambda item: PRIORITY_ORDER.get(item[0], 99))
    return ordered


def top_triage_rows(findings: list[Finding], limit: int = 10) -> list[dict[str, object]]:
    ranked = sorted(
        findings,
        key=lambda finding: (
            -int(finding.context.get("exploitability_score", 0)),
            PRIORITY_ORDER.get(str(finding.context.get("exploitability_priority", "P4")), 99),
            -SEVERITY_ORDER.get(finding.severity, 0),
        ),
    )
    rows: list[dict[str, object]] = []
    for finding in ranked[:limit]:
        rows.append(
            {
                "priority": finding.context.get("exploitability_priority", "P4"),
                "score": finding.context.get("exploitability_score", 0),
                "bucket": finding.context.get("triage_bucket", "review"),
                "severity": finding.severity,
                "type": finding.type,
                "source": finding.source,
                "record_id": finding.record_id,
                "summary": finding.safe_summary,
            }
        )
    return rows


def top_growing_clusters(result: ScanResult, limit: int = 10) -> list[dict[str, object]]:
    cluster_summary = result.metadata.get("cluster_summary", {})
    if not isinstance(cluster_summary, dict):
        return []
    clusters = cluster_summary.get("clusters", [])
    if not isinstance(clusters, list):
        return []
    ranked = sorted(
        (
            cluster
            for cluster in clusters
            if isinstance(cluster, dict)
        ),
        key=lambda cluster: (
            PRIORITY_ORDER.get(str(cluster.get("priority", "P4")), 99),
            -int(cluster.get("seen_count", 0)),
            -SEVERITY_ORDER.get(str(cluster.get("severity", "low")), 0),
        ),
    )
    rows: list[dict[str, object]] = []
    for cluster in ranked[:limit]:
        timeline = cluster.get("timeline", {}) if isinstance(cluster.get("timeline"), dict) else {}
        rows.append(
            {
                "cluster": cluster.get("title", cluster.get("cluster_id", "")),
                "priority": cluster.get("priority", "P4"),
                "severity": cluster.get("severity", "low"),
                "seen_count": cluster.get("seen_count", 0),
                "source_count": timeline.get("source_count", 0),
                "asset_count": timeline.get("asset_count", 0),
                "first_seen": timeline.get("first_seen", ""),
                "last_seen": timeline.get("last_seen", ""),
            }
        )
    return rows


def finding_matches_filters(
    finding: Finding,
    *,
    severities: set[str],
    priorities: set[str],
    baseline_statuses: set[str],
) -> bool:
    severity = finding.severity
    priority = str(finding.context.get("exploitability_priority", "P4"))
    baseline_status = str(finding.context.get("hunt_status", finding.context.get("baseline_status", "current")))
    return (
        severity in severities
        and priority in priorities
        and baseline_status in baseline_statuses
    )


def _group_identity(finding: Finding) -> tuple[str, str]:
    cluster_id = str(finding.context.get("cluster_id", "") or "")
    if cluster_id:
        cluster = finding.context.get("cluster", {})
        title = str(cluster.get("title", finding.type.replace("_", " ").title())) if isinstance(cluster, dict) else finding.type.replace("_", " ").title()
        return f"cluster:{cluster_id}", title
    entity_types = sorted({entity.entity_type for entity in finding.entities})
    if finding.type in INCIDENT_PRIORITY:
        key = f"type:{finding.type}:{','.join(entity_types)}"
        title = finding.type.replace("_", " ").title()
        return key, title
    if finding.entities:
        first = finding.entities[0]
        key = f"entity:{first.entity_type}:{first.value_hash}"
        title = first.entity_type.replace("_", " ").title()
        return key, title
    return f"type:{finding.type}", finding.type.replace("_", " ").title()


def _best_preview(entities: list[DetectionResult], *, include_values: bool) -> str:
    for entity in entities:
        if include_values and entity.raw_value:
            return entity.raw_value
        if entity.masked_preview:
            return entity.masked_preview
    return ""


def _group_sort_key(group: PresentationGroup) -> tuple[int, int, int, str]:
    finding_priority = INCIDENT_PRIORITY.get(group.finding_type, 99)
    severity_rank = -SEVERITY_ORDER.get(group.severity, -1)
    exploitability_rank = PRIORITY_ORDER.get(group.priority, 99)
    return (finding_priority, exploitability_rank, severity_rank, group.title)


def _max_severity(left: str, right: str) -> str:
    return left if SEVERITY_ORDER[left] >= SEVERITY_ORDER[right] else right


def _min_priority(left: str, right: str) -> str:
    return left if PRIORITY_ORDER.get(left, 99) <= PRIORITY_ORDER.get(right, 99) else right
