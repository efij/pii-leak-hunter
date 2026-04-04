from __future__ import annotations

from collections import defaultdict

from pii_leak_hunter.core.models import ExposureCluster, Finding, TimelineSummary, ValidationResult
from pii_leak_hunter.scoring.risk import SEVERITY_ORDER


PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}


def cluster_findings(findings: list[Finding]) -> list[ExposureCluster]:
    groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        key = _cluster_key(finding)
        groups[key].append(finding)

    clusters: list[ExposureCluster] = []
    for findings_group in groups.values():
        cluster = _build_cluster(findings_group)
        clusters.append(cluster)
        for finding in findings_group:
            finding.context["cluster_id"] = cluster.cluster_id
            finding.context["cluster"] = cluster.to_safe_dict()
    return sorted(clusters, key=_cluster_sort_key)


def _build_cluster(findings: list[Finding]) -> ExposureCluster:
    first = findings[0]
    title = _cluster_title(findings)
    priority = min(
        (str(finding.context.get("exploitability_priority", "P4")) for finding in findings),
        key=lambda value: PRIORITY_ORDER.get(value, 99),
    )
    severity = max(
        (finding.severity for finding in findings),
        key=lambda value: SEVERITY_ORDER.get(value, -1),
    )
    assets = sorted(
        {
            str(finding.context.get("asset_summary", ""))
            for finding in findings
            if str(finding.context.get("asset_summary", ""))
        }
    )
    sources = sorted({finding.source for finding in findings})
    entity_hashes = sorted(
        {
            entity.value_hash[:12]
            for finding in findings
            for entity in finding.entities
        }
    )
    validation = _merge_validation(findings)
    timeline = _cluster_timeline(findings)
    cluster_id = _cluster_key(first)
    return ExposureCluster(
        cluster_id=cluster_id,
        title=title,
        priority=priority,
        severity=severity,
        member_finding_ids=[finding.id for finding in findings],
        entity_hashes=entity_hashes,
        assets=assets,
        sources=sources,
        timeline=timeline,
        validation=validation,
        finding_type=first.type,
        seen_count=len(findings),
    )


def _cluster_key(finding: Finding) -> str:
    hashes = ",".join(sorted(entity.value_hash[:12] for entity in finding.entities))
    entity_types = ",".join(sorted(entity.entity_type for entity in finding.entities))
    asset_key = str(finding.context.get("asset_key", ""))
    return f"{finding.type}|{entity_types}|{hashes}|{asset_key}"


def _cluster_title(findings: list[Finding]) -> str:
    first = findings[0]
    timeline = first.context.get("timeline", {})
    if isinstance(timeline, dict) and timeline.get("source_count", 0) > 1:
        return f"{first.type.replace('_', ' ').title()} Spread"
    return first.type.replace("_", " ").title()


def _merge_validation(findings: list[Finding]) -> list[ValidationResult]:
    merged: dict[tuple[str, str], ValidationResult] = {}
    for finding in findings:
        validation = finding.context.get("validation", [])
        if not isinstance(validation, list):
            continue
        for item in validation:
            if not isinstance(item, dict):
                continue
            key = (str(item.get("entity_type", "")), str(item.get("classification", "")))
            if key not in merged:
                merged[key] = ValidationResult(
                    classification=str(item.get("classification", "not_supported")),
                    provider_family=str(item.get("provider_family", "generic")),
                    entity_type=str(item.get("entity_type", "")),
                    evidence=[str(entry) for entry in item.get("evidence", []) if entry],
                    confidence=str(item.get("confidence", "medium")),
                    provider_check_run=bool(item.get("provider_check_run", False)),
                    supporting_entity_types=[str(entry) for entry in item.get("supporting_entity_types", []) if entry],
                )
    return list(merged.values())


def _cluster_timeline(findings: list[Finding]) -> TimelineSummary:
    timestamps = sorted(
        str(finding.context.get("record_timestamp", ""))
        for finding in findings
        if str(finding.context.get("record_timestamp", ""))
    )
    sources = sorted({finding.source for finding in findings})
    assets = sorted(
        {
            str(finding.context.get("asset_summary", ""))
            for finding in findings
            if str(finding.context.get("asset_summary", ""))
        }
    )
    repeated_hashes = sorted(
        {
            entity.value_hash[:12]
            for finding in findings
            for entity in finding.entities
        }
    )
    return TimelineSummary(
        first_seen=timestamps[0] if timestamps else "",
        last_seen=timestamps[-1] if timestamps else "",
        seen_count=len(findings),
        source_count=len(sources),
        asset_count=len(assets),
        spread_sources=sources,
        spread_assets=assets,
        repeated_hashes=repeated_hashes,
    )


def _cluster_sort_key(cluster: ExposureCluster) -> tuple[int, int, int, str]:
    return (
        PRIORITY_ORDER.get(cluster.priority, 99),
        -SEVERITY_ORDER.get(cluster.severity, -1),
        -cluster.seen_count,
        cluster.title,
    )
