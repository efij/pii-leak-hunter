from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.sources.base import BaseSource, LoadedSource
from pii_leak_hunter.sources.http_utils import request_json_with_retries
from pii_leak_hunter.utils.config import ZendeskConfig


class ZendeskSource(BaseSource):
    def __init__(
        self,
        uri: str,
        client: httpx.Client | None = None,
        config: ZendeskConfig | None = None,
    ) -> None:
        self.uri = uri
        self.client = client or httpx.Client(timeout=10.0)
        parsed = _parse_zendesk_uri(uri)
        self.query = parsed["query"]
        self.limit = parsed["limit"]
        self.config = config or ZendeskConfig.from_env()
        self.base_url = str(parsed["base_url"] or self.config.base_url)
        self.include_comments = parsed["include_comments"]

    def load(self) -> LoadedSource:
        payload = request_json_with_retries(
            self.client,
            method="GET",
            url=f"{self.base_url}/api/v2/search.json",
            label="Zendesk",
            headers=self._headers(),
            auth=self._auth(),
            params={"query": self.query},
        )
        records: list[LogRecord] = []
        for item in payload.get("results", [])[: self.limit]:
            if not isinstance(item, dict):
                continue
            records.append(self._to_record(item))
            if self.include_comments and item.get("id"):
                records.extend(self._load_comments(str(item["id"])))
        return LoadedSource(
            records=records,
            source="zendesk",
            metadata={
                "mode": "saas",
                "provider": "zendesk",
                "query": self.query,
                "least_privilege_preset": "zendesk-read-tickets",
            },
        )

    def _load_comments(self, ticket_id: str) -> list[LogRecord]:
        payload = request_json_with_retries(
            self.client,
            method="GET",
            url=f"{self.base_url}/api/v2/tickets/{ticket_id}/comments.json",
            label="Zendesk",
            headers=self._headers(),
            auth=self._auth(),
        )
        return [
            LogRecord(
                timestamp=str(item.get("created_at") or ""),
                message=str(item.get("body") or item.get("html_body") or ""),
                attributes=item,
                source=f"zendesk:comment:{ticket_id}:{item.get('id', '')}",
            )
            for item in payload.get("comments", [])
            if isinstance(item, dict)
        ]

    def _to_record(self, item: dict[str, Any]) -> LogRecord:
        message = " | ".join(
            part
            for part in (
                str(item.get("subject") or ""),
                str(item.get("description") or ""),
            )
            if part
        )
        return LogRecord(
            timestamp=str(item.get("updated_at") or item.get("created_at") or ""),
            message=message,
            attributes=item,
            source=f"zendesk:ticket:{item.get('id', '')}",
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.config.bearer_token:
            headers["Authorization"] = f"Bearer {self.config.bearer_token}"
        return headers

    def _auth(self) -> tuple[str, str] | None:
        if self.config.email and self.config.api_token:
            return (f"{self.config.email}/token", self.config.api_token)
        return None


def _parse_zendesk_uri(uri: str) -> dict[str, object]:
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    fallback_base_url = None if parsed.netloc in {"", "workspace"} else f"https://{parsed.netloc}"
    base_url = params.get("base_url", [fallback_base_url or ""])[0].rstrip("/") or None
    query = params.get("query", ["type:ticket updated>1day"])[0]
    limit = int(params.get("limit", ["25"])[0])
    include_comments = params.get("include_comments", ["true"])[0].lower() != "false"
    return {"base_url": base_url, "query": query, "limit": limit, "include_comments": include_comments}
