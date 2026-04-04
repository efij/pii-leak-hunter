from __future__ import annotations

from collections import defaultdict

from pii_leak_hunter.core.models import Finding, TimelineSummary


def build_timeline(findings: list[Finding]) -> dict[str, object]:
    hash_groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        for entity in finding.entities:
            hash_groups[entity.value_hash].append(finding)

    repeated_entity_count = 0
    for finding in findings:
        summaries = [_group_summary(group) for entity in finding.entities if (group := hash_groups.get(entity.value_hash))]
        if not summaries:
            continue
        merged = _merge_summaries(summaries)
        finding.context["timeline"] = merged.to_safe_dict()
        repeated_hashes = [entity.value_hash[:12] for entity in finding.entities if len(hash_groups.get(entity.value_hash, [])) > 1]
        if repeated_hashes:
            repeated_entity_count += len(set(repeated_hashes))
            finding.context["timeline"]["repeated_hashes"] = sorted(set(repeated_hashes))

    clusters: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        cluster_id = str(finding.context.get("cluster_id", "") or "")
        if cluster_id:
            clusters[cluster_id].append(finding)
    cluster_summaries = {
        cluster_id: _group_summary(group).to_safe_dict()
        for cluster_id, group in clusters.items()
    }
    return {
        "repeated_entity_groups": sum(1 for group in hash_groups.values() if len(group) > 1),
        "repeated_entity_hits": repeated_entity_count,
        "clusters": cluster_summaries,
    }


def _group_summary(findings: list[Finding]) -> TimelineSummary:
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
    hashes = sorted(
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
        repeated_hashes=hashes,
    )


def _merge_summaries(summaries: list[TimelineSummary]) -> TimelineSummary:
    timestamps = sorted(
        [summary.first_seen for summary in summaries if summary.first_seen]
        + [summary.last_seen for summary in summaries if summary.last_seen]
    )
    sources = sorted({source for summary in summaries for source in summary.spread_sources})
    assets = sorted({asset for summary in summaries for asset in summary.spread_assets})
    hashes = sorted({value for summary in summaries for value in summary.repeated_hashes})
    return TimelineSummary(
        first_seen=timestamps[0] if timestamps else "",
        last_seen=timestamps[-1] if timestamps else "",
        seen_count=max(summary.seen_count for summary in summaries),
        source_count=len(sources),
        asset_count=len(assets),
        spread_sources=sources,
        spread_assets=assets,
        repeated_hashes=hashes,
    )
