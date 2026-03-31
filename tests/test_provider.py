import httpx

from pii_leak_hunter.providers.coralogix import CoralogixProvider
from pii_leak_hunter.providers.datadog import DatadogProvider
from pii_leak_hunter.providers.dynatrace import DynatraceProvider
from pii_leak_hunter.providers.new_relic import NewRelicProvider
from pii_leak_hunter.providers.splunk import SplunkProvider
from pii_leak_hunter.utils.config import (
    CoralogixConfig,
    DatadogConfig,
    DynatraceConfig,
    NewRelicConfig,
    SplunkConfig,
    _build_base_url,
)


def test_coralogix_provider_uses_dataprime_query_endpoint() -> None:
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        assert request.url.path == "/api/v1/dataprime/query"
        body = request.read().decode("utf-8")
        assert '"syntax":"QUERY_SYNTAX_LUCENE"' in body or '"syntax": "QUERY_SYNTAX_LUCENE"' in body
        assert '"query":"source:api"' in body or '"query": "source:api"' in body
        if attempts["count"] == 1:
            return httpx.Response(429, json={"message": "rate limited"})
        return httpx.Response(
            200,
            text="\n".join(
                [
                    '{"result":{"timestamp":"2026-03-18T00:00:00Z","message":"alice@example.test"}}',
                    '{"result":{"timestamp":"2026-03-18T00:01:00Z","message":"done"}}',
                ]
            ),
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0)
    provider = CoralogixProvider(
        CoralogixConfig(api_key="token", region="eu1", base_url="https://api.eu1.coralogix.com"),
        client=client,
        page_size=1,
    )

    records = provider.fetch(query="source:api", start="-1h", end="now")

    assert attempts["count"] == 2
    assert len(records) == 2
    assert records[0].source == "coralogix"


def test_coralogix_region_builder_accepts_app_hosts() -> None:
    assert _build_base_url("https://your-team.app.coralogix.us") == "https://api.us1.coralogix.com"
    assert _build_base_url("your-team.app.coralogix.us") == "https://api.us1.coralogix.com"


def test_datadog_provider_uses_logs_list_api() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v2/logs/events/search"
        body = request.read().decode("utf-8")
        assert '"query":"service:mailer"' in body or '"query": "service:mailer"' in body
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "attributes": {
                            "message": "api_key=sk_live_FAKESECRET123 email=owner@example.test",
                            "timestamp": "2026-03-18T00:00:00Z",
                            "attributes": {"service": "mailer-service"},
                        }
                    }
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0)
    provider = DatadogProvider(
        DatadogConfig(
            api_key="api",
            app_key="app",
            site="datadoghq.com",
            base_url="https://api.datadoghq.com",
        ),
        client=client,
    )
    records = provider.fetch(query="service:mailer", start="-1h", end="now")
    assert len(records) == 1
    assert records[0].source == "datadog"
    assert records[0].attributes["service"] == "mailer-service"


def test_datadog_provider_omits_query_for_all_logs_mode() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read().decode("utf-8")
        assert "/api/v2/logs/events/search" in str(request.url)
        assert '"query"' not in body
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "attributes": {
                            "message": "token=abc",
                            "timestamp": "2026-03-18T00:00:00Z",
                        }
                    }
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0)
    provider = DatadogProvider(
        DatadogConfig(
            api_key="api",
            app_key="app",
            site="datadoghq.com",
            base_url="https://api.datadoghq.com",
        ),
        client=client,
    )
    records = provider.fetch(query="*", start="-24h", end="now")
    assert len(records) == 1


def test_dynatrace_provider_uses_next_page_key() -> None:
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        if calls["count"] == 1:
            assert request.url.path == "/api/v2/logs/export"
            return httpx.Response(
                200,
                json={
                    "results": [{"content": "first", "timestamp": "2026-03-18T00:00:00Z"}],
                    "nextPageKey": "next-page",
                },
            )
        assert "nextPageKey=next-page" in str(request.url)
        return httpx.Response(
            200,
            json={"results": [{"content": "second", "timestamp": "2026-03-18T00:00:01Z"}]},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0)
    provider = DynatraceProvider(
        DynatraceConfig(api_token="token", environment_url="https://tenant.live.dynatrace.com"),
        client=client,
    )
    records = provider.fetch(query='contains(content, "mailer")', start="-1h", end="now")
    assert len(records) == 2
    assert records[1].source == "dynatrace"


def test_splunk_provider_parses_export_stream() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/services/search/v2/jobs/export"
        body = request.read().decode("utf-8")
        assert "search=search+index%3Dmain" in body
        return httpx.Response(
            200,
            text='\n'.join(
                [
                    '{"result":{"_raw":"customer_ssn=123-45-6789","_time":"2026-03-18T00:00:00Z"}}',
                    '{"result":{"_raw":"done","_time":"2026-03-18T00:00:01Z"}}',
                ]
            ),
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0)
    provider = SplunkProvider(
        SplunkConfig(base_url="https://splunk.example.com:8089", token="token"),
        client=client,
    )
    records = provider.fetch(query="index=main", start="-1h", end="now")
    assert len(records) == 2
    assert records[0].source == "splunk"


def test_new_relic_provider_builds_nrql_query() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://api.newrelic.com/graphql"
        payload = request.read().decode("utf-8")
        assert "SELECT * FROM Log WHERE `service.name` = 'mailer-service' SINCE 24 hours ago UNTIL NOW LIMIT 200" in payload
        return httpx.Response(
            200,
            json={
                "data": {
                    "actor": {
                        "account": {
                            "nrql": {
                                "results": [
                                    {"message": "owner@example.test", "timestamp": "2026-03-18T00:00:00Z"}
                                ]
                            }
                        }
                    }
                }
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0)
    provider = NewRelicProvider(
        NewRelicConfig(api_key="api-key", account_id=12345, region="us", base_url="https://api.newrelic.com/graphql"),
        client=client,
    )
    records = provider.fetch(query="`service.name` = 'mailer-service'", start="-24h", end="now")
    assert len(records) == 1
    assert records[0].source == "newrelic"


def test_new_relic_provider_supports_all_logs_default_query() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = request.read().decode("utf-8")
        assert "SELECT * FROM Log SINCE 24 hours ago UNTIL NOW LIMIT 200" in payload
        assert "WHERE *" not in payload
        return httpx.Response(
            200,
            json={
                "data": {
                    "actor": {
                        "account": {
                            "nrql": {
                                "results": [
                                    {"message": "token=abc", "timestamp": "2026-03-18T00:00:00Z"}
                                ]
                            }
                        }
                    }
                }
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0)
    provider = NewRelicProvider(
        NewRelicConfig(api_key="api-key", account_id=12345, region="us", base_url="https://api.newrelic.com/graphql"),
        client=client,
    )
    records = provider.fetch(query="*", start="-24h", end="now")
    assert len(records) == 1
    assert records[0].source == "newrelic"
