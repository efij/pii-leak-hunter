from __future__ import annotations

from typing import Any

from pii_leak_hunter.core.models import AssetContext, Finding, LogRecord


def enrich_asset_context(record: LogRecord, finding: Finding) -> None:
    finding.context.setdefault("record_timestamp", record.timestamp)
    asset = infer_asset_mapping(record)
    finding.context["asset"] = asset.to_safe_dict()
    finding.context["asset_key"] = asset.asset_key
    finding.context["asset_summary"] = asset.asset_summary


def infer_asset_mapping(record: LogRecord) -> AssetContext:
    attributes = record.attributes or {}
    source_prefix = record.source.split(":", 1)[0].lower()

    asset = AssetContext(
        service=_pick(attributes, "service", "service.name", "app", "application", "subsystemName", "component"),
        team=_pick(attributes, "team", "owner_team", "squad", "group"),
        environment=_pick(attributes, "env", "environment", "stage", "deployment.environment"),
        account=_pick(attributes, "account", "account_id", "aws_account_id", "subscription_id", "project_id"),
        project=_pick(attributes, "project", "project_id", "workspace"),
        repository=_pick(attributes, "repository", "repo"),
        workspace=_pick(attributes, "workspace", "space"),
        cluster=_pick(attributes, "cluster", "cluster_name", "k8s.cluster.name"),
        region=_pick(attributes, "region", "awsRegion", "location"),
        channel=_pick(attributes, "channel", "channel_name"),
        table=_pick(attributes, "table", "schema"),
        board=_pick(attributes, "board"),
        team_space=_pick(attributes, "team_space", "team"),
        ticket_queue=_pick(attributes, "queue", "ticket_queue", "project_key"),
        source=record.source,
    )

    if source_prefix == "github":
        asset.repository = asset.repository or _source_segment(record.source, 1)
        asset.project = asset.project or asset.repository
        asset.workspace = asset.workspace or _pick(attributes, "owner")
    elif source_prefix == "azuredevops":
        asset.workspace = asset.workspace or _pick(attributes, "organization", "organization_url")
        asset.project = asset.project or _pick(attributes, "project", "project_name")
        asset.repository = asset.repository or _pick(attributes, "repository")
    elif source_prefix == "slack":
        asset.workspace = asset.workspace or _pick(attributes, "team", "workspace")
        asset.channel = asset.channel or _pick(attributes, "channel")
    elif source_prefix == "googleworkspace":
        asset.workspace = asset.workspace or _pick(attributes, "driveId")
        asset.project = asset.project or _pick(attributes, "name")
    elif source_prefix == "monday":
        asset.board = asset.board or _pick(attributes, "board")
        asset.workspace = asset.workspace or "monday"
        asset.project = asset.project or asset.board
    elif source_prefix == "teams":
        asset.team_space = asset.team_space or _pick(attributes, "team")
        asset.channel = asset.channel or _pick(attributes, "channel")
        asset.workspace = asset.workspace or "teams"
    elif source_prefix in {"zendesk", "jira", "servicenow"}:
        asset.ticket_queue = asset.ticket_queue or _pick(attributes, "queue", "project", "table")
        asset.project = asset.project or _pick(attributes, "project", "key")
        asset.table = asset.table or _pick(attributes, "table")
    elif source_prefix == "snowflake":
        asset.table = asset.table or _pick(attributes, "table")
        asset.project = asset.project or _pick(attributes, "database")

    asset.asset_key = _asset_key(asset)
    asset.asset_summary = _asset_summary(asset)
    return asset


def _asset_summary(asset: AssetContext) -> str:
    ordered = [
        asset.service,
        asset.project or asset.repository or asset.workspace,
        asset.environment,
        asset.account,
        asset.cluster,
        asset.channel or asset.board or asset.team_space,
        asset.table or asset.ticket_queue,
    ]
    summary = " / ".join(part for part in ordered if part)
    return summary or asset.source or "unknown-source"


def _asset_key(asset: AssetContext) -> str:
    ordered = [
        asset.service,
        asset.team,
        asset.environment,
        asset.account,
        asset.project,
        asset.repository,
        asset.workspace,
        asset.cluster,
        asset.region,
        asset.channel,
        asset.table,
        asset.board,
        asset.team_space,
        asset.ticket_queue,
        asset.source.split(":", 1)[0],
    ]
    return "|".join(part for part in ordered if part) or asset.source


def _source_segment(source: str, index: int) -> str:
    parts = source.split(":")
    if len(parts) > index:
        return parts[index]
    return ""


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
