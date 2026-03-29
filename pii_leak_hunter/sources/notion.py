from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.sources.base import BaseSource, LoadedSource
from pii_leak_hunter.utils.config import NotionConfig


class NotionSource(BaseSource):
    def __init__(
        self,
        uri: str,
        client: httpx.Client | None = None,
        config: NotionConfig | None = None,
    ) -> None:
        self.uri = uri
        self.client = client or httpx.Client(timeout=10.0)
        self.config = config or NotionConfig.from_env()
        self.query, self.page_size = _parse_notion_uri(uri)

    def load(self) -> LoadedSource:
        search_results = self._search()
        records: list[LogRecord] = []
        for item in search_results:
            if not isinstance(item, dict):
                continue
            records.append(self._to_record(item))
            block_id = item.get("id")
            if block_id:
                records.extend(self._load_block_children(str(block_id), title=_title_for_item(item)))
        return LoadedSource(
            records=records,
            source="notion",
            metadata={
                "mode": "saas",
                "provider": "notion",
                "query": self.query,
                "least_privilege_preset": "notion-read-content",
            },
        )

    def _search(self) -> list[dict[str, Any]]:
        payload = {"page_size": self.page_size}
        if self.query:
            payload["query"] = self.query
        body = self._request_with_retries("POST", "https://api.notion.com/v1/search", json=payload)
        results = body.get("results", [])
        return [item for item in results if isinstance(item, dict)]

    def _load_block_children(self, block_id: str, title: str) -> list[LogRecord]:
        body = self._request_with_retries(
            "GET",
            f"https://api.notion.com/v1/blocks/{block_id}/children",
            params={"page_size": "100"},
        )
        results = body.get("results", [])
        records: list[LogRecord] = []
        for index, item in enumerate(results, start=1):
            if not isinstance(item, dict):
                continue
            text = _extract_notion_text(item)
            if not text:
                continue
            records.append(
                LogRecord(
                    timestamp=str(item.get("last_edited_time") or item.get("created_time") or ""),
                    message=text,
                    attributes={"title": title, "block": item},
                    source=f"notion:block:{block_id}:{index}",
                )
            )
        return records

    def _to_record(self, item: dict[str, Any]) -> LogRecord:
        title = _title_for_item(item)
        message = title or json.dumps(item, sort_keys=True)
        return LogRecord(
            timestamp=str(item.get("last_edited_time") or item.get("created_time") or ""),
            message=message,
            attributes=item,
            source=f"notion:{item.get('object', 'page')}:{item.get('id', '')}",
        )

    def _request_with_retries(
        self,
        method: str,
        url: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                response = self.client.request(
                    method,
                    url,
                    headers={
                        "Authorization": f"Bearer {self.config.api_key}",
                        "Notion-Version": self.config.notion_version,
                        "Content-Type": "application/json",
                    },
                    json=json,
                    params=params,
                )
                if response.status_code in {429, 500, 502, 503, 504}:
                    raise httpx.HTTPStatusError(
                        f"Retryable Notion response: {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict):
                    raise ValueError("Notion response must be a JSON object.")
                return payload
            except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError, ValueError) as exc:
                last_error = exc
                if attempt >= 3:
                    break
                time.sleep(0.2 * attempt)
        raise RuntimeError(f"Notion fetch failed after 3 attempts: {last_error}") from last_error


def _parse_notion_uri(uri: str) -> tuple[str, int]:
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    query = params.get("query", [""])[0]
    page_size = int(params.get("page_size", ["25"])[0])
    return query, page_size


def _title_for_item(item: dict[str, Any]) -> str:
    if "properties" in item and isinstance(item["properties"], dict):
        title_parts: list[str] = []
        for value in item["properties"].values():
            if isinstance(value, dict) and value.get("type") == "title":
                for part in value.get("title", []):
                    if isinstance(part, dict):
                        title_parts.append(part.get("plain_text", ""))
        title = "".join(title_parts).strip()
        if title:
            return title
    if isinstance(item.get("title"), list):
        return "".join(part.get("plain_text", "") for part in item["title"] if isinstance(part, dict)).strip()
    return ""


def _extract_notion_text(item: dict[str, Any]) -> str:
    block_type = item.get("type")
    content = item.get(block_type, {}) if isinstance(block_type, str) else {}
    if not isinstance(content, dict):
        return ""
    if "rich_text" in content and isinstance(content["rich_text"], list):
        text = "".join(part.get("plain_text", "") for part in content["rich_text"] if isinstance(part, dict)).strip()
        if text:
            return text
    if "caption" in content and isinstance(content["caption"], list):
        text = "".join(part.get("plain_text", "") for part in content["caption"] if isinstance(part, dict)).strip()
        if text:
            return text
    return ""
