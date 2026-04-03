from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.sources.base import BaseSource, LoadedSource
from pii_leak_hunter.sources.http_utils import basic_auth_header, request_json_with_retries
from pii_leak_hunter.utils.config import AzureDevOpsConfig


class AzureDevOpsSource(BaseSource):
    def __init__(
        self,
        uri: str,
        client: httpx.Client | None = None,
        config: AzureDevOpsConfig | None = None,
    ) -> None:
        self.uri = uri
        self.client = client or httpx.Client(timeout=10.0)
        parsed = _parse_ado_uri(uri)
        self.config = config or AzureDevOpsConfig.from_env()
        self.organization_url = str(parsed["organization_url"] or self.config.organization_url)
        self.project = parsed["project"]
        self.wiql = parsed["wiql"]
        self.limit = parsed["limit"]
        self.include_pull_requests = parsed["include_pull_requests"]
        self.repository_query = parsed["repository_query"]
        self.pr_limit = parsed["pr_limit"]

    def load(self) -> LoadedSource:
        wiql_payload = request_json_with_retries(
            self.client,
            method="POST",
            url=f"{self.organization_url}/{self.project}/_apis/wit/wiql",
            label="Azure DevOps",
            headers=self._headers(),
            params={"api-version": "7.1"},
            json_body={"query": self.wiql},
        )
        work_items = wiql_payload.get("workItems", [])
        ids = [str(item["id"]) for item in work_items[: self.limit] if isinstance(item, dict) and item.get("id")]
        if not ids:
            return LoadedSource(records=[], source="azuredevops", metadata={"mode": "saas", "provider": "azuredevops", "query": self.wiql})
        items_payload = request_json_with_retries(
            self.client,
            method="GET",
            url=f"{self.organization_url}/_apis/wit/workitems",
            label="Azure DevOps",
            headers=self._headers(),
            params={"ids": ",".join(ids), "$expand": "all", "api-version": "7.1"},
        )
        records = [self._to_record(item) for item in items_payload.get("value", []) if isinstance(item, dict)]
        repository_count = 0
        if self.include_pull_requests:
            repositories = self._resolve_repositories()
            repository_count = len(repositories)
            for repository in repositories:
                records.extend(self._load_pull_requests(repository))
        return LoadedSource(
            records=records,
            source="azuredevops",
            metadata={
                "mode": "saas",
                "provider": "azuredevops",
                "project": self.project,
                "query": self.wiql,
                "repository_query": self.repository_query,
                "repository_count": repository_count,
                "least_privilege_preset": "azure-devops-work-items",
            },
        )

    def _resolve_repositories(self) -> list[dict[str, Any]]:
        payload = request_json_with_retries(
            self.client,
            method="GET",
            url=f"{self.organization_url}/{self.project}/_apis/git/repositories",
            label="Azure DevOps",
            headers=self._headers(),
            params={"api-version": "7.1"},
        )
        repositories = payload.get("value", [])
        if not isinstance(repositories, list):
            return []
        if not self.repository_query:
            return [repo for repo in repositories if isinstance(repo, dict)]
        needle = self.repository_query.lower()
        return [
            repo
            for repo in repositories
            if isinstance(repo, dict)
            and needle in str(repo.get("name") or repo.get("id") or "").lower()
        ]

    def _load_pull_requests(self, repository: dict[str, Any]) -> list[LogRecord]:
        repository_id = str(repository.get("id") or "")
        repository_name = str(repository.get("name") or repository_id)
        if not repository_id:
            return []
        payload = request_json_with_retries(
            self.client,
            method="GET",
            url=f"{self.organization_url}/{self.project}/_apis/git/repositories/{repository_id}/pullrequests",
            label="Azure DevOps",
            headers=self._headers(),
            params={
                "searchCriteria.status": "all",
                "$top": str(self.pr_limit),
                "api-version": "7.1",
            },
        )
        records: list[LogRecord] = []
        for item in payload.get("value", []):
            if not isinstance(item, dict):
                continue
            pull_request_id = str(item.get("pullRequestId") or "")
            if not pull_request_id:
                continue
            records.append(self._to_pull_request_record(repository_name, item))
            records.extend(self._load_pull_request_threads(repository_id, repository_name, pull_request_id))
        return records

    def _load_pull_request_threads(
        self,
        repository_id: str,
        repository_name: str,
        pull_request_id: str,
    ) -> list[LogRecord]:
        payload = request_json_with_retries(
            self.client,
            method="GET",
            url=f"{self.organization_url}/{self.project}/_apis/git/repositories/{repository_id}/pullRequests/{pull_request_id}/threads",
            label="Azure DevOps",
            headers=self._headers(),
            params={"api-version": "7.1"},
        )
        records: list[LogRecord] = []
        for thread in payload.get("value", []):
            if not isinstance(thread, dict):
                continue
            comments = thread.get("comments", [])
            if not isinstance(comments, list):
                continue
            for comment in comments:
                if not isinstance(comment, dict):
                    continue
                records.append(
                    LogRecord(
                        timestamp=str(comment.get("publishedDate") or comment.get("lastUpdatedDate") or ""),
                        message=str(comment.get("content") or ""),
                        attributes={
                            "repository": repository_name,
                            "pull_request_id": pull_request_id,
                            **comment,
                        },
                        source=f"azuredevops:pr-comment:{repository_name}:{pull_request_id}:{comment.get('id', '')}",
                    )
                )
        return records

    def _to_record(self, item: dict[str, Any]) -> LogRecord:
        fields = item.get("fields", {}) if isinstance(item.get("fields"), dict) else {}
        message = " | ".join(
            part
            for part in (
                str(fields.get("System.Title") or ""),
                str(fields.get("System.Description") or ""),
                str(fields.get("Microsoft.VSTS.TCM.ReproSteps") or ""),
                str(fields.get("System.History") or ""),
            )
            if part
        )
        return LogRecord(
            timestamp=str(fields.get("System.ChangedDate") or fields.get("System.CreatedDate") or ""),
            message=message,
            attributes=item,
            source=f"azuredevops:workitem:{item.get('id', '')}",
        )

    def _to_pull_request_record(self, repository_name: str, item: dict[str, Any]) -> LogRecord:
        message = " | ".join(
            part
            for part in (
                str(item.get("title") or ""),
                str(item.get("description") or ""),
            )
            if part
        )
        return LogRecord(
            timestamp=str(item.get("creationDate") or item.get("closedDate") or ""),
            message=message,
            attributes={"repository": repository_name, **item},
            source=f"azuredevops:pullrequest:{repository_name}:{item.get('pullRequestId', '')}",
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": basic_auth_header("", self.config.pat),
        }


def _parse_ado_uri(uri: str) -> dict[str, object]:
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    fallback_org = None if parsed.netloc in {"", "workspace"} else f"https://{parsed.netloc}"
    organization_url = params.get("organization_url", [fallback_org or ""])[0].rstrip("/") or None
    project = params.get("project", [parsed.path.strip("/") or ""])[0]
    wiql = params.get("wiql", ["Select [System.Id] From WorkItems Order By [System.ChangedDate] Desc"])[0]
    limit = int(params.get("limit", ["25"])[0])
    include_pull_requests = params.get("include_pull_requests", ["true"])[0].lower() != "false"
    repository_query = params.get("repository_query", [""])[0]
    pr_limit = int(params.get("pr_limit", [str(min(limit, 25))])[0])
    return {
        "organization_url": organization_url,
        "project": project,
        "wiql": wiql,
        "limit": limit,
        "include_pull_requests": include_pull_requests,
        "repository_query": repository_query,
        "pr_limit": pr_limit,
    }
