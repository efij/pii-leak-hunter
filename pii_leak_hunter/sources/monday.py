from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.sources.base import BaseSource, LoadedSource
from pii_leak_hunter.sources.http_utils import request_json_with_retries
from pii_leak_hunter.utils.config import MondayConfig


class MondaySource(BaseSource):
    def __init__(
        self,
        uri: str,
        client: httpx.Client | None = None,
        config: MondayConfig | None = None,
    ) -> None:
        self.uri = uri
        self.client = client or httpx.Client(timeout=20.0)
        self.config = config or MondayConfig.from_env()
        parsed = _parse_monday_uri(uri)
        self.query = parsed["query"]
        self.limit = parsed["limit"]
        self.include_updates = parsed["include_updates"]
        self.api_url = self.config.api_url

    def load(self) -> LoadedSource:
        payload = request_json_with_retries(
            self.client,
            method="POST",
            url=self.api_url,
            label="monday.com",
            headers=self._headers(),
            json_body={
                "query": """
                    query ScanBoards($limit: Int!, $itemLimit: Int!) {
                      boards(limit: $limit) {
                        id
                        name
                        state
                        items_page(limit: $itemLimit) {
                          items {
                            id
                            name
                            updated_at
                            column_values {
                              id
                              text
                            }
                            updates(limit: 25) {
                              id
                              body
                              text_body
                              created_at
                              updated_at
                            }
                          }
                        }
                      }
                    }
                """,
                "variables": {"limit": self.limit, "itemLimit": self.limit},
            },
        )
        boards = payload.get("data", {}).get("boards", [])
        records: list[LogRecord] = []
        for board in boards:
            if not isinstance(board, dict):
                continue
            board_name = str(board.get("name") or "")
            items = board.get("items_page", {}).get("items", []) if isinstance(board.get("items_page"), dict) else []
            for item in items:
                if not isinstance(item, dict):
                    continue
                if self.query and self.query.lower() not in _item_search_text(board_name, item).lower():
                    continue
                records.append(self._to_item_record(board_name, item))
                if not self.include_updates:
                    continue
                updates = item.get("updates", [])
                if not isinstance(updates, list):
                    continue
                for update in updates:
                    if isinstance(update, dict):
                        records.append(self._to_update_record(board_name, str(item.get("id") or ""), item.get("name"), update))
        return LoadedSource(
            records=records,
            source="monday",
            metadata={
                "mode": "saas",
                "provider": "monday",
                "query": self.query,
                "least_privilege_preset": "monday",
            },
        )

    def _to_item_record(self, board_name: str, item: dict[str, Any]) -> LogRecord:
        column_values = item.get("column_values", [])
        column_text = " | ".join(
            str(value.get("text") or "")
            for value in column_values
            if isinstance(value, dict) and value.get("text")
        )
        message = " | ".join(part for part in (board_name, str(item.get("name") or ""), column_text) if part)
        return LogRecord(
            timestamp=str(item.get("updated_at") or ""),
            message=message,
            attributes={"board": board_name, **item},
            source=f"monday:item:{item.get('id', '')}",
        )

    def _to_update_record(
        self,
        board_name: str,
        item_id: str,
        item_name: Any,
        update: dict[str, Any],
    ) -> LogRecord:
        message = " | ".join(
            part
            for part in (
                board_name,
                str(item_name or ""),
                str(update.get("text_body") or update.get("body") or ""),
            )
            if part
        )
        return LogRecord(
            timestamp=str(update.get("updated_at") or update.get("created_at") or ""),
            message=message,
            attributes={"board": board_name, "item_id": item_id, **update},
            source=f"monday:update:{item_id}:{update.get('id', '')}",
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": self.config.token,
        }


def _item_search_text(board_name: str, item: dict[str, Any]) -> str:
    parts = [board_name, str(item.get("name") or "")]
    column_values = item.get("column_values", [])
    if isinstance(column_values, list):
        parts.extend(
            str(value.get("text") or "")
            for value in column_values
            if isinstance(value, dict)
        )
    updates = item.get("updates", [])
    if isinstance(updates, list):
        parts.extend(
            str(update.get("text_body") or update.get("body") or "")
            for update in updates
            if isinstance(update, dict)
        )
    return " ".join(part for part in parts if part)


def _parse_monday_uri(uri: str) -> dict[str, object]:
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    query = params.get("query", [""])[0]
    limit = int(params.get("limit", ["25"])[0])
    include_updates = params.get("include_updates", ["true"])[0].lower() != "false"
    return {
        "query": query,
        "limit": limit,
        "include_updates": include_updates,
    }
