from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.sources.base import BaseSource, LoadedSource
from pii_leak_hunter.sources.http_utils import request_json_with_retries
from pii_leak_hunter.utils.config import ConfluenceConfig


class ConfluenceSource(BaseSource):
    def __init__(
        self,
        uri: str,
        client: httpx.Client | None = None,
        config: ConfluenceConfig | None = None,
    ) -> None:
        self.uri = uri
        self.client = client or httpx.Client(timeout=10.0)
        parsed = _parse_confluence_uri(uri)
        self.config = config or ConfluenceConfig.from_env()
        self.cql = parsed["cql"]
        self.limit = parsed["limit"]
        self.base_url = str(parsed["base_url"] or self.config.base_url)

    def load(self) -> LoadedSource:
        records: list[LogRecord] = []
        search = request_json_with_retries(
            self.client,
            method="GET",
            url=f"{self.base_url}/rest/api/search",
            label="Confluence",
            headers=self._headers(),
            auth=self._auth(),
            params={"cql": self.cql, "limit": str(self.limit)},
        )
        for item in search.get("results", []):
            if not isinstance(item, dict):
                continue
            record = self._to_record(item)
            records.append(record)
            content = item.get("content", {})
            if isinstance(content, dict) and content.get("id"):
                records.extend(self._load_page(str(content["id"]), title=record.message))
        return LoadedSource(
            records=records,
            source="confluence",
            metadata={
                "mode": "saas",
                "provider": "confluence",
                "query": self.cql,
                "least_privilege_preset": "confluence-read-content",
            },
        )

    def _load_page(self, page_id: str, *, title: str) -> list[LogRecord]:
        payload = request_json_with_retries(
            self.client,
            method="GET",
            url=f"{self.base_url}/rest/api/content/{page_id}",
            label="Confluence",
            headers=self._headers(),
            auth=self._auth(),
            params={"expand": "body.storage,version"},
        )
        body_storage = payload.get("body", {}).get("storage", {}) if isinstance(payload.get("body"), dict) else {}
        html = body_storage.get("value", "") if isinstance(body_storage, dict) else ""
        if not html:
            return []
        return [
            LogRecord(
                timestamp=str(payload.get("version", {}).get("when") or ""),
                message=f"{title} | {html}",
                attributes=payload,
                source=f"confluence:page:{page_id}",
            )
        ]

    def _to_record(self, item: dict[str, Any]) -> LogRecord:
        content = item.get("content", {}) if isinstance(item.get("content"), dict) else {}
        title = str(content.get("title") or item.get("title") or "")
        excerpt = str(item.get("excerpt") or "")
        return LogRecord(
            timestamp="",
            message=" | ".join(part for part in (title, excerpt) if part),
            attributes=item,
            source=f"confluence:search:{content.get('id', '')}",
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.config.bearer_token:
            headers["Authorization"] = f"Bearer {self.config.bearer_token}"
        return headers

    def _auth(self) -> tuple[str, str] | None:
        if self.config.email and self.config.api_token:
            return (self.config.email, self.config.api_token)
        return None


def _parse_confluence_uri(uri: str) -> dict[str, object]:
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    cql = params.get("cql", ['type = "page" ORDER BY lastmodified DESC'])[0]
    limit = int(params.get("limit", ["25"])[0])
    fallback_base_url = None if parsed.netloc in {"", "workspace"} else f"https://{parsed.netloc}{parsed.path.rstrip('/')}"
    base_url = params.get("base_url", [fallback_base_url or ""])[0].rstrip("/") or None
    return {"cql": cql, "limit": limit, "base_url": base_url}
