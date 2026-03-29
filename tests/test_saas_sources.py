import httpx

from pii_leak_hunter.sources.notion import NotionSource
from pii_leak_hunter.sources.servicenow import ServiceNowSource
from pii_leak_hunter.utils.config import NotionConfig, ServiceNowConfig


def test_servicenow_source_scans_table_records() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/now/table/incident"
        assert request.url.params["sysparm_query"] == "active=true"
        return httpx.Response(
            200,
            json={
                "result": [
                    {
                        "sys_id": "abc123",
                        "short_description": "Leaked kube token",
                        "description": "bearer=eyJhbGciOiJSUzI1NiJ9.payload.signature",
                        "sys_updated_on": "2026-03-29 10:00:00",
                    }
                ]
            },
        )

    source = ServiceNowSource(
        "servicenow://acme.service-now.com?table=incident&query=active=true&page_size=10",
        client=httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0),
        config=ServiceNowConfig(username="user", password="pass"),
    )
    loaded = source.load()

    assert loaded.source == "servicenow"
    assert loaded.metadata["least_privilege_preset"] == "servicenow-read-only"
    assert len(loaded.records) == 1


def test_notion_source_scans_search_results_and_blocks() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/search":
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "object": "page",
                            "id": "page-1",
                            "last_edited_time": "2026-03-29T10:00:00Z",
                            "properties": {
                                "title": {
                                    "type": "title",
                                    "title": [{"plain_text": "Prod Runbook"}],
                                }
                            },
                        }
                    ]
                },
            )
        assert request.url.path == "/v1/blocks/page-1/children"
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "type": "paragraph",
                        "created_time": "2026-03-29T10:01:00Z",
                        "paragraph": {
                            "rich_text": [{"plain_text": "AWS key AKIAABCDEFGHIJKLMNOP"}]
                        },
                    }
                ]
            },
        )

    source = NotionSource(
        "notion://workspace?query=prod&page_size=5",
        client=httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0),
        config=NotionConfig(api_key="token", notion_version="2026-03-11"),
    )
    loaded = source.load()

    assert loaded.source == "notion"
    assert loaded.metadata["least_privilege_preset"] == "notion-read-content"
    assert len(loaded.records) == 2
