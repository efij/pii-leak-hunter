from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.sources.base import BaseSource, LoadedSource
from pii_leak_hunter.sources.http_utils import request_json_with_retries
from pii_leak_hunter.utils.config import TeamsConfig


class TeamsSource(BaseSource):
    def __init__(
        self,
        uri: str,
        client: httpx.Client | None = None,
        config: TeamsConfig | None = None,
    ) -> None:
        self.uri = uri
        self.client = client or httpx.Client(timeout=20.0)
        self.config = config or TeamsConfig.from_env()
        parsed = _parse_teams_uri(uri)
        self.team_query = parsed["team_query"]
        self.team_ids = parsed["team_ids"]
        self.channel_query = parsed["channel_query"]
        self.limit = parsed["limit"]
        self.include_replies = parsed["include_replies"]
        self.base_url = self.config.graph_base_url

    def load(self) -> LoadedSource:
        records: list[LogRecord] = []
        for team in self._resolve_teams():
            team_id = str(team.get("id") or "")
            team_name = str(team.get("displayName") or team_id)
            if not team_id:
                continue
            channels = request_json_with_retries(
                self.client,
                method="GET",
                url=f"{self.base_url}/teams/{team_id}/channels",
                label="Microsoft Teams",
                headers=self._headers(),
                params={"$top": str(self.limit)},
            ).get("value", [])
            for channel in channels:
                if not isinstance(channel, dict):
                    continue
                channel_id = str(channel.get("id") or "")
                channel_name = str(channel.get("displayName") or channel_id)
                if not channel_id:
                    continue
                if self.channel_query and self.channel_query.lower() not in channel_name.lower():
                    continue
                payload = request_json_with_retries(
                    self.client,
                    method="GET",
                    url=f"{self.base_url}/teams/{team_id}/channels/{channel_id}/messages",
                    label="Microsoft Teams",
                    headers=self._headers(),
                    params={"$top": str(self.limit)},
                )
                messages = payload.get("value", [])
                for message in messages:
                    if not isinstance(message, dict):
                        continue
                    message_id = str(message.get("id") or "")
                    records.append(self._to_message_record(team_name, channel_name, message))
                    if self.include_replies and message_id:
                        records.extend(self._load_replies(team_id, channel_id, team_name, channel_name, message_id))
        return LoadedSource(
            records=records,
            source="teams",
            metadata={
                "mode": "saas",
                "provider": "teams",
                "team_query": self.team_query,
                "least_privilege_preset": "teams",
            },
        )

    def _resolve_teams(self) -> list[dict[str, Any]]:
        if self.team_ids:
            return [{"id": team_id, "displayName": team_id} for team_id in self.team_ids]
        payload = request_json_with_retries(
            self.client,
            method="GET",
            url=f"{self.base_url}/me/joinedTeams",
            label="Microsoft Teams",
            headers=self._headers(),
            params={"$top": str(self.limit)},
        )
        teams = payload.get("value", [])
        if not isinstance(teams, list):
            return []
        if not self.team_query:
            return [team for team in teams if isinstance(team, dict)]
        needle = self.team_query.lower()
        return [
            team
            for team in teams
            if isinstance(team, dict)
            and needle in str(team.get("displayName") or "").lower()
        ]

    def _load_replies(
        self,
        team_id: str,
        channel_id: str,
        team_name: str,
        channel_name: str,
        message_id: str,
    ) -> list[LogRecord]:
        payload = request_json_with_retries(
            self.client,
            method="GET",
            url=f"{self.base_url}/teams/{team_id}/channels/{channel_id}/messages/{message_id}/replies",
            label="Microsoft Teams",
            headers=self._headers(),
            params={"$top": str(self.limit)},
        )
        return [
            self._to_message_record(team_name, channel_name, item, prefix=f"teams:reply:{message_id}")
            for item in payload.get("value", [])
            if isinstance(item, dict)
        ]

    def _to_message_record(
        self,
        team_name: str,
        channel_name: str,
        message: dict[str, Any],
        *,
        prefix: str = "teams:message",
    ) -> LogRecord:
        body = message.get("body", {}) if isinstance(message.get("body"), dict) else {}
        content = str(body.get("content") or "")
        return LogRecord(
            timestamp=str(message.get("lastModifiedDateTime") or message.get("createdDateTime") or ""),
            message=" | ".join(part for part in (team_name, channel_name, content) if part),
            attributes={"team": team_name, "channel": channel_name, **message},
            source=f"{prefix}:{channel_name}:{message.get('id', '')}",
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.config.token}",
        }


def _parse_teams_uri(uri: str) -> dict[str, object]:
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    team_query = params.get("team_query", [""])[0]
    team_ids = [item.strip() for item in params.get("teams", [""])[0].split(",") if item.strip()]
    channel_query = params.get("channel_query", [""])[0]
    limit = int(params.get("limit", ["50"])[0])
    include_replies = params.get("include_replies", ["true"])[0].lower() != "false"
    return {
        "team_query": team_query,
        "team_ids": team_ids,
        "channel_query": channel_query,
        "limit": limit,
        "include_replies": include_replies,
    }
