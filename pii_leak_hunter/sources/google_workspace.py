from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, quote, urlparse

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.sources.base import BaseSource, LoadedSource
from pii_leak_hunter.sources.http_utils import request_json_with_retries
from pii_leak_hunter.utils.config import GoogleWorkspaceConfig


_NATIVE_EXPORTS = {
    "application/vnd.google-apps.document": "text/plain",
    "application/vnd.google-apps.spreadsheet": "text/csv",
    "application/vnd.google-apps.presentation": "text/plain",
}


class GoogleWorkspaceSource(BaseSource):
    def __init__(
        self,
        uri: str,
        client: httpx.Client | None = None,
        config: GoogleWorkspaceConfig | None = None,
    ) -> None:
        self.uri = uri
        self.client = client or httpx.Client(timeout=20.0)
        self.config = config or GoogleWorkspaceConfig.from_env()
        parsed = _parse_google_workspace_uri(uri)
        self.query = parsed["query"]
        self.limit = parsed["limit"]
        self.include_shared_drives = parsed["include_shared_drives"]
        self.base_url = self.config.drive_base_url

    def load(self) -> LoadedSource:
        payload = request_json_with_retries(
            self.client,
            method="GET",
            url=f"{self.base_url}/files",
            label="Google Workspace",
            headers=self._headers(),
            params=self._files_params(),
        )
        records: list[LogRecord] = []
        for item in payload.get("files", [])[: self.limit]:
            if not isinstance(item, dict):
                continue
            records.append(self._to_metadata_record(item))
            content = self._fetch_file_content(item)
            if content:
                records.append(
                    LogRecord(
                        timestamp=str(item.get("modifiedTime") or item.get("createdTime") or ""),
                        message=content,
                        attributes=item,
                        source=f"googleworkspace:file:{item.get('id', '')}",
                    )
                )
        return LoadedSource(
            records=records,
            source="googleworkspace",
            metadata={
                "mode": "saas",
                "provider": "googleworkspace",
                "query": self.query,
                "least_privilege_preset": "google-workspace-drive-read",
            },
        )

    def _files_params(self) -> dict[str, str]:
        params = {
            "pageSize": str(self.limit),
            "fields": "files(id,name,mimeType,modifiedTime,createdTime,owners/displayName,driveId,webViewLink)",
            "q": self.query or "trashed = false",
        }
        if self.include_shared_drives:
            params["supportsAllDrives"] = "true"
            params["includeItemsFromAllDrives"] = "true"
        return params

    def _fetch_file_content(self, item: dict[str, Any]) -> str:
        file_id = str(item.get("id") or "")
        mime_type = str(item.get("mimeType") or "")
        if not file_id:
            return ""
        headers = self._headers()
        if mime_type in _NATIVE_EXPORTS:
            export_mime = _NATIVE_EXPORTS[mime_type]
            response = self.client.get(
                f"{self.base_url}/files/{quote(file_id)}/export",
                headers=headers,
                params={"mimeType": export_mime},
            )
            response.raise_for_status()
            return response.text
        response = self.client.get(
            f"{self.base_url}/files/{quote(file_id)}",
            headers=headers,
            params={"alt": "media", "supportsAllDrives": str(self.include_shared_drives).lower()},
        )
        if response.status_code >= 400:
            return ""
        content_type = response.headers.get("content-type", "")
        if "json" in content_type or "text" in content_type or "csv" in content_type or not content_type:
            return response.text
        return ""

    def _to_metadata_record(self, item: dict[str, Any]) -> LogRecord:
        owners = item.get("owners", [])
        owner_names = ", ".join(
            str(owner.get("displayName") or "")
            for owner in owners
            if isinstance(owner, dict) and owner.get("displayName")
        )
        message = " | ".join(
            part
            for part in (
                str(item.get("name") or ""),
                str(item.get("mimeType") or ""),
                owner_names,
                str(item.get("webViewLink") or ""),
            )
            if part
        )
        return LogRecord(
            timestamp=str(item.get("modifiedTime") or item.get("createdTime") or ""),
            message=message,
            attributes=item,
            source=f"googleworkspace:metadata:{item.get('id', '')}",
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.config.token}",
        }


def _parse_google_workspace_uri(uri: str) -> dict[str, object]:
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    query = params.get("query", ["trashed = false"])[0]
    limit = int(params.get("limit", ["25"])[0])
    include_shared_drives = params.get("include_shared_drives", ["true"])[0].lower() != "false"
    return {
        "query": query,
        "limit": limit,
        "include_shared_drives": include_shared_drives,
    }
