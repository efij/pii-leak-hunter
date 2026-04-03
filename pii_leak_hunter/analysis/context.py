from __future__ import annotations

from typing import Any

from pii_leak_hunter.core.models import Finding, LogRecord


def enrich_operational_context(record: LogRecord, finding: Finding) -> None:
    finding.context.setdefault("record_timestamp", record.timestamp)
    asset = infer_asset_mapping(record)
    finding.context.setdefault("asset", asset)
    finding.context.setdefault("asset_summary", _asset_summary(asset))


def infer_asset_mapping(record: LogRecord) -> dict[str, str]:
    attributes = record.attributes or {}
    service = _pick(attributes, "service", "service.name", "app", "application", "subsystemName", "component")
    team = _pick(attributes, "team", "owner_team", "squad", "group")
    environment = _pick(attributes, "env", "environment", "stage", "deployment.environment")
    account = _pick(attributes, "account", "account_id", "aws_account_id", "subscription_id", "project_id")
    project = _pick(attributes, "project", "project_id", "repository", "repo", "workspace")
    cluster = _pick(attributes, "cluster", "cluster_name", "k8s.cluster.name")
    region = _pick(attributes, "region", "awsRegion", "location")
    channel = _pick(attributes, "channel", "channel_name")
    table = _pick(attributes, "table", "schema")
    values = {
        "service": service,
        "team": team,
        "environment": environment,
        "account": account,
        "project": project,
        "cluster": cluster,
        "region": region,
        "channel": channel,
        "table": table,
        "source": record.source,
    }
    return {key: value for key, value in values.items() if value}


def _asset_summary(asset: dict[str, str]) -> str:
    ordered = [
        asset.get("service"),
        asset.get("project"),
        asset.get("environment"),
        asset.get("account"),
        asset.get("cluster"),
        asset.get("channel"),
        asset.get("table"),
    ]
    summary = " / ".join(part for part in ordered if part)
    return summary or asset.get("source", "unknown-source")


def _pick(attributes: dict[str, Any], *keys: str) -> str:
    for key in keys:
        if key in attributes and attributes[key] not in {None, ""}:
            return str(attributes[key])
    lower_map = {str(key).lower(): value for key, value in attributes.items()}
    for key in keys:
        lowered = key.lower()
        if lowered in lower_map and lower_map[lowered] not in {None, ""}:
            return str(lower_map[lowered])
    return ""
