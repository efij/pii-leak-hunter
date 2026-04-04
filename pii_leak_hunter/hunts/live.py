from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pii_leak_hunter.core.models import ScanResult

DIFF_SIGNATURE_FAMILIES = (
    "cluster_exact",
    "cluster_hashes",
    "cluster_assets",
    "cluster_sources",
    "cluster_type_asset",
    "cluster_type_source",
    "cluster_priority",
    "cluster_severity",
    "cluster_hash_asset",
    "cluster_hash_source",
    "cluster_asset_source",
    "cluster_type_priority",
    "cluster_type_severity",
    "cluster_first_seen_day",
    "cluster_last_seen_day",
    "cluster_asset_count_bucket",
    "cluster_source_count_bucket",
    "cluster_seen_count_bucket",
    "cluster_priority_severity",
    "cluster_type_asset_count",
    "cluster_type_source_count",
    "cluster_validation_classification",
    "cluster_validation_family_classification",
    "cluster_provider_family",
    "entity_hash",
    "entity_type_hash",
    "entity_type_asset",
    "entity_type_source",
    "entity_type_asset_source",
    "entity_type_priority",
    "entity_type_severity",
    "asset_key",
    "asset_source",
    "asset_environment",
    "asset_priority",
    "asset_severity",
    "asset_blast_radius",
    "asset_provider_family",
    "asset_validation_classification",
    "blast_radius",
    "validation_classification",
    "validation_family_classification",
    "provider_family",
    "finding_type_source",
    "finding_type_asset",
    "finding_type_environment",
    "finding_type_priority",
    "finding_type_severity",
    "source_priority",
    "source_severity",
)


def apply_hunt_baseline(
    result: ScanResult,
    payload: dict[str, Any],
    *,
    new_only: bool = False,
    baseline_source: str = "uploaded",
) -> ScanResult:
    known_signatures = extract_diff_signatures(payload)
    known_clusters = known_signatures.get("cluster_exact", set())
    cluster_summary = result.metadata.get("cluster_summary", {})
    clusters = cluster_summary.get("clusters", []) if isinstance(cluster_summary, dict) else []
    current_signatures = build_diff_signatures(result)
    current_clusters = {
        _cluster_signature(cluster): cluster
        for cluster in clusters
        if isinstance(cluster, dict)
    }
    for finding in result.findings:
        cluster = finding.context.get("cluster", {})
        if not isinstance(cluster, dict):
            continue
        signature = _cluster_signature(cluster)
        status = "existing" if signature in known_clusters else "new"
        finding.context["hunt_status"] = status
        finding.context["diff_signatures"] = _finding_diff_signatures(finding)
    if new_only:
        result.findings = [finding for finding in result.findings if finding.context.get("hunt_status") == "new"]
    result.metadata["hunt_summary"] = {
        "baseline_source": baseline_source,
        "new_clusters": len(set(signature for signature in current_clusters if signature not in known_clusters)),
        "existing_clusters": len(set(signature for signature in current_clusters if signature in known_clusters)),
        "resolved_clusters": len(known_clusters - set(current_clusters)),
        "total_current_clusters": len(current_clusters),
        "total_baseline_clusters": len(known_clusters),
        "diff_signature_summary": _diff_signature_summary(current_signatures, known_signatures),
        "new_only": new_only,
    }
    return result


def write_hunt_artifact(result: ScanResult, path: str) -> None:
    diff_signatures = build_diff_signatures(result)
    payload = {
        "recipe": result.metadata.get("hunt_summary", {}).get("recipe"),
        "source": result.source,
        "metadata": result.metadata,
        "cluster_signatures": sorted(diff_signatures.get("cluster_exact", set())),
        "diff_signatures": {
            name: sorted(values)
            for name, values in diff_signatures.items()
        },
        "findings": result.to_safe_dict().get("findings", []),
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_hunt_artifact(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def extract_cluster_signatures(payload: dict[str, Any]) -> set[str]:
    return extract_diff_signatures(payload).get("cluster_exact", set())


def extract_diff_signatures(payload: dict[str, Any]) -> dict[str, set[str]]:
    diff_signatures = payload.get("diff_signatures")
    if isinstance(diff_signatures, dict):
        return {
            str(name): {str(item) for item in values if item}
            for name, values in diff_signatures.items()
            if isinstance(values, list)
        }
    cluster_signatures = payload.get("cluster_signatures")
    if isinstance(cluster_signatures, list):
        return {"cluster_exact": {str(item) for item in cluster_signatures}}
    metadata = payload.get("metadata", {})
    if isinstance(metadata, dict):
        cluster_summary = metadata.get("cluster_summary", {})
        if isinstance(cluster_summary, dict):
            clusters = cluster_summary.get("clusters", [])
            if isinstance(clusters, list):
                return {
                    "cluster_exact": {
                        _cluster_signature(cluster)
                        for cluster in clusters
                        if isinstance(cluster, dict)
                    }
                }
    return {"cluster_exact": set()}


def prepare_hunt_result(
    result: ScanResult,
    *,
    recipe_id: str,
    target: str,
    lookback: str,
) -> ScanResult:
    summary = dict(result.metadata.get("hunt_summary", {})) if isinstance(result.metadata.get("hunt_summary"), dict) else {}
    summary.update(
        {
            "recipe": recipe_id,
            "target": target,
            "lookback": lookback,
        }
    )
    result.metadata["hunt_summary"] = summary
    return result


def _cluster_signature(cluster: dict[str, Any]) -> str:
    title = str(cluster.get("title", ""))
    finding_type = str(cluster.get("finding_type", ""))
    hashes = ",".join(sorted(str(item) for item in cluster.get("entity_hashes", []) if item))
    assets = ",".join(sorted(str(item) for item in cluster.get("assets", []) if item))
    sources = ",".join(sorted(str(item) for item in cluster.get("sources", []) if item))
    return f"{finding_type}|{title}|{hashes}|{assets}|{sources}"


def build_diff_signatures(result: ScanResult) -> dict[str, set[str]]:
    signatures: dict[str, set[str]] = {name: set() for name in DIFF_SIGNATURE_FAMILIES}
    cluster_summary = result.metadata.get("cluster_summary", {})
    clusters = cluster_summary.get("clusters", []) if isinstance(cluster_summary, dict) else []
    for cluster in clusters:
        if not isinstance(cluster, dict):
            continue
        finding_type = str(cluster.get("finding_type", ""))
        priority = str(cluster.get("priority", ""))
        severity = str(cluster.get("severity", ""))
        hashes = sorted(str(item) for item in cluster.get("entity_hashes", []) if item)
        assets = sorted(str(item) for item in cluster.get("assets", []) if item)
        sources = sorted(str(item) for item in cluster.get("sources", []) if item)
        timeline = cluster.get("timeline", {}) if isinstance(cluster.get("timeline"), dict) else {}
        first_seen_day = str(timeline.get("first_seen", "")).split("T", 1)[0]
        last_seen_day = str(timeline.get("last_seen", "")).split("T", 1)[0]
        source_count_bucket = _count_bucket(int(timeline.get("source_count", len(sources) or 0)))
        asset_count_bucket = _count_bucket(int(timeline.get("asset_count", len(assets) or 0)))
        seen_count_bucket = _count_bucket(int(cluster.get("seen_count", 0)))
        signatures["cluster_exact"].add(_cluster_signature(cluster))
        if hashes:
            signatures["cluster_hashes"].add(f"{finding_type}|{','.join(hashes)}")
        if assets:
            signatures["cluster_assets"].add(f"{finding_type}|{','.join(assets)}")
        if sources:
            signatures["cluster_sources"].add(f"{finding_type}|{','.join(sources)}")
        for asset in assets:
            signatures["cluster_type_asset"].add(f"{finding_type}|{asset}")
        for source in sources:
            signatures["cluster_type_source"].add(f"{finding_type}|{source}")
        if priority:
            signatures["cluster_priority"].add(f"{finding_type}|{priority}")
            signatures["cluster_type_priority"].add(f"{finding_type}|{priority}")
        if severity:
            signatures["cluster_severity"].add(f"{finding_type}|{severity}")
            signatures["cluster_type_severity"].add(f"{finding_type}|{severity}")
        if priority and severity:
            signatures["cluster_priority_severity"].add(f"{priority}|{severity}")
        for hash_value in hashes:
            for asset in assets:
                signatures["cluster_hash_asset"].add(f"{hash_value}|{asset}")
            for source in sources:
                signatures["cluster_hash_source"].add(f"{hash_value}|{source}")
        for asset in assets:
            for source in sources:
                signatures["cluster_asset_source"].add(f"{asset}|{source}")
        if first_seen_day:
            signatures["cluster_first_seen_day"].add(f"{finding_type}|{first_seen_day}")
        if last_seen_day:
            signatures["cluster_last_seen_day"].add(f"{finding_type}|{last_seen_day}")
        if asset_count_bucket:
            signatures["cluster_asset_count_bucket"].add(f"{finding_type}|{asset_count_bucket}")
            signatures["cluster_type_asset_count"].add(f"{finding_type}|{asset_count_bucket}")
        if source_count_bucket:
            signatures["cluster_source_count_bucket"].add(f"{finding_type}|{source_count_bucket}")
            signatures["cluster_type_source_count"].add(f"{finding_type}|{source_count_bucket}")
        if seen_count_bucket:
            signatures["cluster_seen_count_bucket"].add(f"{finding_type}|{seen_count_bucket}")
        validations = cluster.get("validation", [])
        if isinstance(validations, list):
            for item in validations:
                if not isinstance(item, dict):
                    continue
                classification = str(item.get("classification", ""))
                family = str(item.get("provider_family", ""))
                if classification:
                    signatures["cluster_validation_classification"].add(f"{finding_type}|{classification}")
                if family and classification:
                    signatures["cluster_validation_family_classification"].add(f"{family}|{classification}")
                if family:
                    signatures["cluster_provider_family"].add(family)

    for finding in result.findings:
        for key, values in _finding_diff_signatures(finding).items():
            signatures.setdefault(key, set()).update(values)
    return signatures


def _finding_diff_signatures(finding) -> dict[str, set[str]]:
    signatures: dict[str, set[str]] = {
        "entity_hash": set(),
        "entity_type_hash": set(),
        "entity_type_asset": set(),
        "entity_type_source": set(),
        "entity_type_asset_source": set(),
        "entity_type_priority": set(),
        "entity_type_severity": set(),
        "asset_key": set(),
        "asset_source": set(),
        "asset_environment": set(),
        "asset_priority": set(),
        "asset_severity": set(),
        "asset_blast_radius": set(),
        "asset_provider_family": set(),
        "asset_validation_classification": set(),
        "blast_radius": set(),
        "validation_classification": set(),
        "validation_family_classification": set(),
        "provider_family": set(),
        "finding_type_source": set(),
        "finding_type_asset": set(),
        "finding_type_environment": set(),
        "finding_type_priority": set(),
        "finding_type_severity": set(),
        "source_priority": set(),
        "source_severity": set(),
    }
    asset_key = str(finding.context.get("asset_key", ""))
    asset_summary = str(finding.context.get("asset_summary", ""))
    environment = ""
    asset = finding.context.get("asset", {})
    if isinstance(asset, dict):
        environment = str(asset.get("environment", ""))
    if asset_key:
        signatures["asset_key"].add(asset_key)
        signatures["asset_source"].add(f"{asset_key}|{finding.source}")
    elif asset_summary:
        signatures["asset_key"].add(asset_summary)
        signatures["asset_source"].add(f"{asset_summary}|{finding.source}")
    effective_asset = asset_key or asset_summary
    if environment:
        signatures["asset_environment"].add(f"{finding.type}|{environment}")
        signatures["finding_type_environment"].add(f"{finding.type}|{environment}")
    priority = str(finding.context.get("exploitability_priority", ""))
    if effective_asset and priority:
        signatures["asset_priority"].add(f"{effective_asset}|{priority}")
    if effective_asset and finding.severity:
        signatures["asset_severity"].add(f"{effective_asset}|{finding.severity}")
        signatures["finding_type_severity"].add(f"{finding.type}|{finding.severity}")
        signatures["source_severity"].add(f"{finding.source}|{finding.severity}")
    if priority:
        signatures["finding_type_priority"].add(f"{finding.type}|{priority}")
        signatures["source_priority"].add(f"{finding.source}|{priority}")
    blast_radius = str(finding.context.get("blast_radius", ""))
    if blast_radius:
        signatures["blast_radius"].add(f"{finding.type}|{blast_radius}")
        if effective_asset:
            signatures["asset_blast_radius"].add(f"{effective_asset}|{blast_radius}")
    signatures["finding_type_source"].add(f"{finding.type}|{finding.source}")
    if effective_asset:
        signatures["finding_type_asset"].add(f"{finding.type}|{effective_asset}")
    validations = finding.context.get("validation", [])
    if isinstance(validations, list):
        for item in validations:
            if not isinstance(item, dict):
                continue
            entity_type = str(item.get("entity_type", ""))
            classification = str(item.get("classification", ""))
            family = str(item.get("provider_family", ""))
            if entity_type and classification:
                signatures["validation_classification"].add(f"{entity_type}|{classification}")
                if effective_asset:
                    signatures["asset_validation_classification"].add(f"{effective_asset}|{classification}")
            if family and classification:
                signatures["validation_family_classification"].add(f"{family}|{classification}")
            if family:
                signatures["provider_family"].add(family)
                if effective_asset:
                    signatures["asset_provider_family"].add(f"{effective_asset}|{family}")
    for entity in finding.entities:
        signatures["entity_hash"].add(entity.value_hash[:12])
        signatures["entity_type_hash"].add(f"{entity.entity_type}|{entity.value_hash[:12]}")
        signatures["entity_type_source"].add(f"{entity.entity_type}|{finding.source}")
        if priority:
            signatures["entity_type_priority"].add(f"{entity.entity_type}|{priority}")
        if finding.severity:
            signatures["entity_type_severity"].add(f"{entity.entity_type}|{finding.severity}")
        if effective_asset:
            signatures["entity_type_asset"].add(f"{entity.entity_type}|{effective_asset}")
            signatures["entity_type_asset_source"].add(f"{entity.entity_type}|{effective_asset}|{finding.source}")
    return signatures


def _diff_signature_summary(
    current: dict[str, set[str]],
    known: dict[str, set[str]],
) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}
    for name, current_values in current.items():
        previous_values = known.get(name, set())
        summary[name] = {
            "new": len(current_values - previous_values),
            "existing": len(current_values & previous_values),
            "resolved": len(previous_values - current_values),
            "total_current": len(current_values),
            "total_baseline": len(previous_values),
        }
    return summary


def _count_bucket(value: int) -> str:
    if value <= 0:
        return ""
    if value == 1:
        return "1"
    if value <= 3:
        return "2-3"
    if value <= 5:
        return "4-5"
    if value <= 10:
        return "6-10"
    return "11+"
