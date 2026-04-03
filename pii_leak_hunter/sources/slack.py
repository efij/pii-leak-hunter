from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.sources.base import BaseSource, LoadedSource
from pii_leak_hunter.sources.http_utils import request_json_with_retries
from pii_leak_hunter.utils.config import SlackConfig


class SlackSource(BaseSource):
    def __init__(
        self,
        uri: str,
        client: httpx.Client | None = None,
        config: SlackConfig | None = None,
    ) -> None:
        self.uri = uri
        self.client = client or httpx.Client(timeout=10.0)
        self.config = config or SlackConfig.from_env()
        parsed = _parse_slack_uri(uri)
        self.channel_query = parsed["channel_query"]
        self.channel_ids = parsed["channel_ids"]
        self.limit = parsed["limit"]
        self.include_private = parsed["include_private"]
        self.base_url = self.config.base_url

    def load(self) -> LoadedSource:
        channels = self._resolve_channels()
        records: list[LogRecord] = []
        for channel in channels:
            channel_id = str(channel.get("id") or "")
            channel_name = str(channel.get("name") or channel_id)
            if not channel_id:
                continue
            payload = request_json_with_retries(
                self.client,
                method="GET",
                url=f"{self.base_url}/conversations.history",
                label="Slack",
                headers=self._headers(),
                params={"channel": channel_id, "limit": str(self.limit)},
            )
            for message in payload.get("messages", []):
                if isinstance(message, dict):
                    records.append(self._to_record(channel_name, message))
        return LoadedSource(
            records=records,
            source="slack",
            metadata={
                "mode": "saas",
                "provider": "slack",
                "channel_query": self.channel_query,
                "least_privilege_preset": "slack-read-only-history",
            },
        )

    def _resolve_channels(self) -> list[dict[str, Any]]:
        if self.channel_ids:
            return [{"id": channel_id, "name": channel_id} for channel_id in self.channel_ids]
        types = "public_channel,private_channel" if self.include_private else "public_channel"
        payload = request_json_with_retries(
            self.client,
            method="GET",
            url=f"{self.base_url}/conversations.list",
            label="Slack",
            headers=self._headers(),
            params={"types": types, "limit": "1000"},
        )
        channels = payload.get("channels", [])
        if not isinstance(channels, list):
            return []
        if not self.channel_query:
            return [channel for channel in channels if isinstance(channel, dict)]
        needle = self.channel_query.lower()
        return [
            channel
            for channel in channels
            if isinstance(channel, dict) and needle in str(channel.get("name", "")).lower()
        ]

    def _to_record(self, channel_name: str, message: dict[str, Any]) -> LogRecord:
        text = str(message.get("text") or "")
        timestamp = str(message.get("ts") or "")
        attributes = {
            "channel": channel_name,
            "user": message.get("user"),
            "thread_ts": message.get("thread_ts"),
            **message,
        }
        return LogRecord(
            timestamp=timestamp,
            message=text,
            attributes=attributes,
            source=f"slack:{channel_name}",
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.config.token}",
        }


def _parse_slack_uri(uri: str) -> dict[str, object]:
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    channel_query = params.get("channel_query", [""])[0]
    channel_ids = [item.strip() for item in params.get("channels", [""])[0].split(",") if item.strip()]
    limit = int(params.get("limit", ["200"])[0])
    include_private = params.get("include_private", ["false"])[0].lower() == "true"
    return {
        "channel_query": channel_query,
        "channel_ids": channel_ids,
        "limit": limit,
        "include_private": include_private,
    }
