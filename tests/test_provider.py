import httpx

from pii_leak_hunter.providers.coralogix import CoralogixProvider
from pii_leak_hunter.utils.config import CoralogixConfig


def test_coralogix_provider_retries_and_paginates() -> None:
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        if attempts["count"] == 1:
            return httpx.Response(429, json={"message": "rate limited"})
        if attempts["count"] == 2:
            return httpx.Response(
                200,
                json={
                    "records": [{"timestamp": "2026-03-18T00:00:00Z", "message": "alice@example.test"}],
                    "nextPageToken": "page-2",
                },
            )
        return httpx.Response(
            200,
            json={
                "records": [{"timestamp": "2026-03-18T00:01:00Z", "message": "done"}],
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0)
    provider = CoralogixProvider(
        CoralogixConfig(api_key="token", region="eu1", base_url="https://api.eu1.coralogix.com"),
        client=client,
        page_size=1,
    )

    records = provider.fetch(query="source:api", start="-1h", end="now")

    assert attempts["count"] == 3
    assert len(records) == 2
    assert records[0].source == "coralogix"
