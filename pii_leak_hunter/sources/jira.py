from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.sources.base import BaseSource, LoadedSource
from pii_leak_hunter.sources.http_utils import request_json_with_retries
from pii_leak_hunter.utils.config import JiraConfig


class JiraSource(BaseSource):
    def __init__(
        self,
        uri: str,
        client: httpx.Client | None = None,
        config: JiraConfig | None = None,
    ) -> None:
        self.uri = uri
        self.client = client or httpx.Client(timeout=10.0)
        parsed = _parse_jira_uri(uri)
        self.config = config or JiraConfig.from_env()
        self.jql = parsed["jql"]
        self.limit = parsed["limit"]
        self.base_url = str(parsed["base_url"] or self.config.base_url)

    def load(self) -> LoadedSource:
        payload = request_json_with_retries(
            self.client,
            method="POST",
            url=f"{self.base_url}/rest/api/3/search",
            label="Jira",
            headers=self._headers(),
            auth=self._auth(),
            json_body={
                "jql": self.jql,
                "maxResults": self.limit,
                "fields": ["summary", "description", "comment", "created", "updated"],
            },
        )
        records: list[LogRecord] = []
        for issue in payload.get("issues", []):
            if isinstance(issue, dict):
                records.append(self._to_record(issue))
        return LoadedSource(
            records=records,
            source="jira",
            metadata={
                "mode": "saas",
                "provider": "jira",
                "query": self.jql,
                "least_privilege_preset": "jira-read-issues",
            },
        )

    def _to_record(self, issue: dict[str, Any]) -> LogRecord:
        fields = issue.get("fields", {}) if isinstance(issue.get("fields"), dict) else {}
        comments = fields.get("comment", {}).get("comments", []) if isinstance(fields.get("comment"), dict) else []
        comment_text = " ".join(
            _jira_rich_text_to_text(comment.get("body"))
            for comment in comments
            if isinstance(comment, dict)
        )
        message = " | ".join(
            part
            for part in (
                str(fields.get("summary") or ""),
                _jira_rich_text_to_text(fields.get("description")),
                comment_text,
            )
            if part
        )
        return LogRecord(
            timestamp=str(fields.get("updated") or fields.get("created") or ""),
            message=message,
            attributes=issue,
            source=f"jira:issue:{issue.get('key', issue.get('id', ''))}",
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.config.bearer_token:
            headers["Authorization"] = f"Bearer {self.config.bearer_token}"
        return headers

    def _auth(self) -> tuple[str, str] | None:
        if self.config.email and self.config.api_token:
            return (self.config.email, self.config.api_token)
        return None


def _jira_rich_text_to_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        return ""
    content = value.get("content", [])
    parts: list[str] = []
    if isinstance(content, list):
        for item in content:
            if not isinstance(item, dict):
                continue
            text = item.get("text")
            if isinstance(text, str):
                parts.append(text)
            parts.append(_jira_rich_text_to_text(item))
    return " ".join(part for part in parts if part).strip()


def _parse_jira_uri(uri: str) -> dict[str, object]:
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    jql = params.get("jql", ["ORDER BY updated DESC"])[0]
    limit = int(params.get("limit", ["25"])[0])
    fallback_base_url = None if parsed.netloc in {"", "workspace"} else f"https://{parsed.netloc}"
    base_url = params.get("base_url", [fallback_base_url or ""])[0].rstrip("/") or None
    return {"jql": jql, "limit": limit, "base_url": base_url}
