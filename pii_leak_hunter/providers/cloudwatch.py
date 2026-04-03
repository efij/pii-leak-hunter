from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.providers.base import BaseProvider
from pii_leak_hunter.providers.coralogix import _parse_time_value
from pii_leak_hunter.utils.config import CloudWatchConfig, ConfigurationError


class CloudWatchProvider(BaseProvider):
    def __init__(
        self,
        config: CloudWatchConfig,
        client: Any | None = None,
        page_size: int = 1000,
    ) -> None:
        super().__init__()
        self.config = config
        self.client = client or _build_boto_client(config)
        self.page_size = min(page_size, 10000)

    def fetch(self, query: str, start: str, end: str) -> list[LogRecord]:
        start_dt, end_dt = _parse_time_value(start, now=datetime.now(timezone.utc)), _parse_time_value(
            end, now=datetime.now(timezone.utc)
        )
        start_ms = int(start_dt.timestamp() * 1000)
        end_ms = int(end_dt.timestamp() * 1000)
        log_groups = self._list_log_groups()
        records: list[LogRecord] = []
        for log_group in log_groups:
            next_token: str | None = None
            while True:
                params: dict[str, Any] = {
                    "logGroupName": log_group,
                    "startTime": start_ms,
                    "endTime": end_ms,
                    "limit": self.page_size,
                }
                if query.strip() and query.strip() != "*":
                    params["filterPattern"] = query.strip()
                if next_token:
                    params["nextToken"] = next_token
                response = self.client.filter_log_events(**params)
                events = response.get("events", [])
                for event in events:
                    if isinstance(event, dict):
                        records.append(self._to_record(log_group, event))
                next_token = response.get("nextToken")
                if not next_token:
                    break
        self.last_fetch_details = {
            "provider": "cloudwatch",
            "log_groups_scanned": len(log_groups),
            "query": query,
            "from": start,
            "to": end,
            "records_parsed": len(records),
        }
        return records

    def _list_log_groups(self) -> list[str]:
        if self.config.log_groups:
            return self.config.log_groups[: self.config.max_log_groups]
        groups: list[str] = []
        token: str | None = None
        while len(groups) < self.config.max_log_groups:
            params: dict[str, Any] = {"limit": min(50, self.config.max_log_groups - len(groups))}
            if self.config.log_group_prefix:
                params["logGroupNamePrefix"] = self.config.log_group_prefix
            if token:
                params["nextToken"] = token
            response = self.client.describe_log_groups(**params)
            for group in response.get("logGroups", []):
                if isinstance(group, dict) and group.get("logGroupName"):
                    groups.append(str(group["logGroupName"]))
                    if len(groups) >= self.config.max_log_groups:
                        break
            token = response.get("nextToken")
            if not token:
                break
        return groups

    def _to_record(self, log_group: str, event: dict[str, Any]) -> LogRecord:
        timestamp_ms = int(event.get("timestamp", 0) or 0)
        timestamp = (
            datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")
            if timestamp_ms
            else ""
        )
        attributes = {
            "log_group": log_group,
            "log_stream": event.get("logStreamName"),
            "event_id": event.get("eventId"),
            **event,
        }
        return LogRecord(
            timestamp=timestamp,
            message=str(event.get("message") or ""),
            attributes=attributes,
            source="cloudwatch",
        )


def _build_boto_client(config: CloudWatchConfig) -> Any:
    try:
        import boto3
    except ModuleNotFoundError as exc:  # pragma: no cover - dependency handled by project
        raise ConfigurationError("boto3 is required for CloudWatch scans. Install project dependencies first.") from exc
    kwargs = {"service_name": "logs"}
    if config.region:
        kwargs["region_name"] = config.region
    return boto3.client(**kwargs)
