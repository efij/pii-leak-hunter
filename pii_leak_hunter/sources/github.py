from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.sources.base import BaseSource, LoadedSource
from pii_leak_hunter.sources.http_utils import request_json_with_retries
from pii_leak_hunter.utils.config import GitHubSourceConfig


class GitHubSource(BaseSource):
    def __init__(
        self,
        uri: str,
        client: httpx.Client | None = None,
        config: GitHubSourceConfig | None = None,
    ) -> None:
        self.uri = uri
        self.client = client or httpx.Client(timeout=10.0)
        parsed = _parse_github_uri(uri)
        self.owner = parsed["owner"]
        self.repo = parsed["repo"]
        self.state = parsed["state"]
        self.limit = parsed["limit"]
        self.include_comments = parsed["include_comments"]
        self.include_review_comments = parsed["include_review_comments"]
        self.config = config or GitHubSourceConfig.from_env()

    def load(self) -> LoadedSource:
        records: list[LogRecord] = []
        repositories = self._resolve_repositories()
        for repo in repositories:
            payload = request_json_with_retries(
                self.client,
                method="GET",
                url=f"{self.config.api_base_url}/repos/{self.owner}/{repo}/issues",
                label="GitHub",
                headers=self._headers(),
                params={"state": self.state, "per_page": str(self.limit)},
                allow_list=True,
            )
            items = payload if isinstance(payload, list) else payload.get("items", [])
            for issue in items:
                if not isinstance(issue, dict):
                    continue
                records.append(self._to_record(repo, issue))
                issue_number = str(issue.get("number", ""))
                if self.include_comments and issue.get("comments_url"):
                    records.extend(self._load_comments(str(issue["comments_url"]), issue_number=issue_number, repo=repo))
                if self.include_review_comments and issue.get("pull_request") and issue_number:
                    records.extend(self._load_review_comments(repo, pull_number=issue_number))
        return LoadedSource(
            records=records,
            source="github",
            metadata={
                "mode": "saas",
                "provider": "github",
                "repository": f"{self.owner}/{self.repo}" if self.repo else f"{self.owner}/*",
                "repository_count": len(repositories),
                "least_privilege_preset": "github-issues-and-prs",
            },
        )

    def _resolve_repositories(self) -> list[str]:
        if self.repo:
            return [self.repo]
        for scope in ("orgs", "users"):
            response = self.client.get(
                f"{self.config.api_base_url}/{scope}/{self.owner}/repos",
                headers=self._headers(),
                params={"per_page": str(self.limit)},
            )
            if response.status_code == 404:
                continue
            response.raise_for_status()
            payload = response.json()
            if isinstance(payload, list):
                return [
                    str(item.get("name") or "")
                    for item in payload
                    if isinstance(item, dict) and item.get("name")
                ][: self.limit]
        return []

    def _load_comments(self, comments_url: str, *, issue_number: str, repo: str) -> list[LogRecord]:
        payload = request_json_with_retries(
            self.client,
            method="GET",
            url=comments_url,
            label="GitHub",
            headers=self._headers(),
            params={"per_page": "100"},
            allow_list=True,
        )
        return [
            LogRecord(
                timestamp=str(item.get("updated_at") or item.get("created_at") or ""),
                message=str(item.get("body") or ""),
                attributes={"repository": repo, **item},
                source=f"github:{repo}:comment:{issue_number}:{item.get('id', '')}",
            )
            for item in payload
            if isinstance(item, dict)
        ]

    def _load_review_comments(self, repo: str, *, pull_number: str) -> list[LogRecord]:
        payload = request_json_with_retries(
            self.client,
            method="GET",
            url=f"{self.config.api_base_url}/repos/{self.owner}/{repo}/pulls/{pull_number}/comments",
            label="GitHub",
            headers=self._headers(),
            params={"per_page": "100"},
            allow_list=True,
        )
        return [
            LogRecord(
                timestamp=str(item.get("updated_at") or item.get("created_at") or ""),
                message=str(item.get("body") or ""),
                attributes={"repository": repo, **item},
                source=f"github:{repo}:review-comment:{pull_number}:{item.get('id', '')}",
            )
            for item in payload
            if isinstance(item, dict)
        ]

    def _to_record(self, repo: str, issue: dict[str, Any]) -> LogRecord:
        body = str(issue.get("body") or "")
        title = str(issue.get("title") or "")
        kind = "pull-request" if issue.get("pull_request") else "issue"
        return LogRecord(
            timestamp=str(issue.get("updated_at") or issue.get("created_at") or ""),
            message=" | ".join(part for part in (title, body) if part),
            attributes={"repository": repo, "owner": self.owner, **issue},
            source=f"github:{repo}:{kind}:{issue.get('number', '')}",
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.config.token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }


def _parse_github_uri(uri: str) -> dict[str, object]:
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    owner = parsed.netloc
    repo = parsed.path.strip("/")
    state = params.get("state", ["all"])[0]
    limit = int(params.get("limit", ["25"])[0])
    include_comments = params.get("include_comments", ["true"])[0].lower() != "false"
    include_review_comments = params.get("include_review_comments", ["true"])[0].lower() != "false"
    return {
        "owner": owner,
        "repo": repo,
        "state": state,
        "limit": limit,
        "include_comments": include_comments,
        "include_review_comments": include_review_comments,
    }
