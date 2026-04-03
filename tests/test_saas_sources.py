import httpx

from pii_leak_hunter.sources.azure_devops import AzureDevOpsSource
from pii_leak_hunter.sources.confluence import ConfluenceSource
from pii_leak_hunter.sources.github import GitHubSource
from pii_leak_hunter.sources.jira import JiraSource
from pii_leak_hunter.sources.monday import MondaySource
from pii_leak_hunter.sources.notion import NotionSource
from pii_leak_hunter.sources.google_workspace import GoogleWorkspaceSource
from pii_leak_hunter.sources.servicenow import ServiceNowSource
from pii_leak_hunter.sources.slack import SlackSource
from pii_leak_hunter.sources.snowflake import SnowflakeSource
from pii_leak_hunter.sources.teams import TeamsSource
from pii_leak_hunter.sources.zendesk import ZendeskSource
from pii_leak_hunter.utils.config import (
    AzureDevOpsConfig,
    ConfluenceConfig,
    GitHubSourceConfig,
    GoogleWorkspaceConfig,
    JiraConfig,
    MondayConfig,
    NotionConfig,
    ServiceNowConfig,
    SlackConfig,
    SnowflakeConfig,
    TeamsConfig,
    ZendeskConfig,
)


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


def test_confluence_source_scans_search_results_and_page_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/rest/api/search"):
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "excerpt": "Runbook excerpt",
                            "content": {"id": "42", "title": "Prod Runbook"},
                        }
                    ]
                },
            )
        assert request.url.path.endswith("/rest/api/content/42")
        return httpx.Response(
            200,
            json={"body": {"storage": {"value": "aws_secret=super-secret-value"}}, "version": {"when": "2026-04-01T10:00:00Z"}},
        )

    source = ConfluenceSource(
        "confluence://workspace?base_url=https://example.atlassian.net/wiki&limit=10",
        client=httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0),
        config=ConfluenceConfig(base_url="https://example.atlassian.net/wiki", bearer_token="token"),
    )
    loaded = source.load()

    assert loaded.source == "confluence"
    assert loaded.metadata["least_privilege_preset"] == "confluence-read-content"
    assert len(loaded.records) == 2


def test_jira_source_scans_issue_bodies_and_comments() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "issues": [
                    {
                        "key": "SEC-1",
                        "fields": {
                            "summary": "Prod secret leak",
                            "description": {"content": [{"text": "api_key=sk_live_fake"}]},
                            "comment": {"comments": [{"body": {"content": [{"text": "owner email=user@example.invalid"}]}}],
                            },
                            "updated": "2026-04-01T11:00:00Z",
                        },
                    }
                ]
            },
        )

    source = JiraSource(
        "jira://workspace?base_url=https://example.atlassian.net&limit=10",
        client=httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0),
        config=JiraConfig(base_url="https://example.atlassian.net", bearer_token="token"),
    )
    loaded = source.load()

    assert loaded.source == "jira"
    assert loaded.metadata["least_privilege_preset"] == "jira-read-issues"
    assert "Prod secret leak" in loaded.records[0].message


def test_azure_devops_source_scans_work_items_and_pr_threads() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/_apis/wit/wiql"):
            return httpx.Response(200, json={"workItems": [{"id": 1001}]})
        if request.url.path.endswith("/_apis/git/repositories"):
            return httpx.Response(200, json={"value": [{"id": "repo-1", "name": "app"}]})
        if request.url.path.endswith("/pullrequests"):
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "pullRequestId": 5,
                            "title": "Credential in PR",
                            "description": "AKIAABCDEFGHIJKLMNOP",
                            "creationDate": "2026-04-01T12:10:00Z",
                        }
                    ]
                },
            )
        if request.url.path.endswith("/threads"):
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "comments": [
                                {
                                    "id": 71,
                                    "content": "review found user@example.invalid",
                                    "publishedDate": "2026-04-01T12:12:00Z",
                                }
                            ]
                        }
                    ]
                },
            )
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": 1001,
                        "fields": {
                            "System.Title": "Leaked token in bug",
                            "System.Description": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
                            "System.ChangedDate": "2026-04-01T12:00:00Z",
                        },
                    }
                ]
            },
        )

    source = AzureDevOpsSource(
        "azuredevops://workspace?organization_url=https://dev.azure.com/org&project=security&limit=10",
        client=httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0),
        config=AzureDevOpsConfig(organization_url="https://dev.azure.com/org", pat="pat"),
    )
    loaded = source.load()

    assert loaded.source == "azuredevops"
    assert loaded.metadata["least_privilege_preset"] == "azure-devops-work-items"
    assert len(loaded.records) == 3


def test_github_source_scans_issues_comments_and_review_comments() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/openai/demo/issues":
            return httpx.Response(
                200,
                json=[
                    {
                        "number": 7,
                        "title": "Credential in issue",
                        "body": "AKIAABCDEFGHIJKLMNOP",
                        "pull_request": {"url": "https://api.github.com/repos/openai/demo/pulls/7"},
                        "comments_url": "https://api.github.com/repos/openai/demo/issues/7/comments",
                        "updated_at": "2026-04-01T13:00:00Z",
                    }
                ],
            )
        if request.url.path == "/repos/openai/demo/pulls/7/comments":
            return httpx.Response(
                200,
                json=[{"id": 78, "body": "review body secret=sk_live_fake", "created_at": "2026-04-01T13:06:00Z"}],
            )
        return httpx.Response(
            200,
            json=[{"id": 77, "body": "owner=user@example.invalid", "created_at": "2026-04-01T13:05:00Z"}],
        )

    source = GitHubSource(
        "github://openai/demo?limit=10&include_comments=true",
        client=httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0),
        config=GitHubSourceConfig(token="token", api_base_url="https://api.github.com"),
    )
    loaded = source.load()

    assert loaded.source == "github"
    assert loaded.metadata["least_privilege_preset"] == "github-issues-and-prs"
    assert len(loaded.records) == 3


def test_github_source_scans_all_visible_repositories_for_owner() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/orgs/openai/repos":
            return httpx.Response(200, json=[{"name": "demo"}, {"name": "demo-two"}])
        if request.url.path == "/repos/openai/demo/issues":
            return httpx.Response(200, json=[{"number": 1, "title": "first", "body": "token=abc"}])
        if request.url.path == "/repos/openai/demo-two/issues":
            return httpx.Response(200, json=[{"number": 2, "title": "second", "body": "user@example.invalid"}])
        return httpx.Response(200, json=[])

    source = GitHubSource(
        "github://openai?limit=10&include_comments=false&include_review_comments=false",
        client=httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0),
        config=GitHubSourceConfig(token="token", api_base_url="https://api.github.com"),
    )
    loaded = source.load()

    assert loaded.metadata["repository"] == "openai/*"
    assert loaded.metadata["repository_count"] == 2
    assert len(loaded.records) == 2


def test_zendesk_source_scans_tickets_and_comments() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2/search.json":
            return httpx.Response(
                200,
                json={"results": [{"id": 22, "subject": "Customer token", "description": "token=abc", "updated_at": "2026-04-01T14:00:00Z"}]},
            )
        return httpx.Response(
            200,
            json={"comments": [{"id": 221, "body": "customer email=user@example.invalid", "created_at": "2026-04-01T14:05:00Z"}]},
        )

    source = ZendeskSource(
        "zendesk://workspace?base_url=https://example.zendesk.com&limit=10",
        client=httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0),
        config=ZendeskConfig(base_url="https://example.zendesk.com", bearer_token="token"),
    )
    loaded = source.load()

    assert loaded.source == "zendesk"
    assert loaded.metadata["least_privilege_preset"] == "zendesk-read-tickets"
    assert len(loaded.records) == 2


def test_snowflake_source_scans_statement_results() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v2/statements"
        return httpx.Response(
            200,
            json={
                "resultSetMetaData": {"rowType": [{"name": "EMAIL"}, {"name": "SECRET"}]},
                "data": [["user@example.invalid", "sk_live_fake"]],
            },
        )

    source = SnowflakeSource(
        "snowflake://workspace?account_url=https://acct.snowflakecomputing.com&statement=select+1&limit=10",
        client=httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0),
        config=SnowflakeConfig(account_url="https://acct.snowflakecomputing.com", token="pat"),
    )
    loaded = source.load()

    assert loaded.source == "snowflake"
    assert loaded.metadata["least_privilege_preset"] == "snowflake-query-read-only"
    assert len(loaded.records) == 1


def test_slack_source_scans_channel_history() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/conversations.list"):
            return httpx.Response(200, json={"channels": [{"id": "C123", "name": "incident-room"}]})
        return httpx.Response(
            200,
            json={"messages": [{"ts": "1712236800.000100", "text": "token=abc owner=user@example.invalid", "user": "U1"}]},
        )

    source = SlackSource(
        "slack://workspace?channel_query=incident&limit=50",
        client=httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0),
        config=SlackConfig(token="xoxb-test", base_url="https://slack.com/api"),
    )
    loaded = source.load()

    assert loaded.source == "slack"
    assert loaded.metadata["least_privilege_preset"] == "slack-read-only-history"
    assert len(loaded.records) == 1
    assert loaded.records[0].attributes["channel"] == "incident-room"


def test_google_workspace_source_scans_drive_metadata_and_exported_content() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/files"):
            return httpx.Response(
                200,
                json={
                    "files": [
                        {
                            "id": "file-1",
                            "name": "Prod Runbook",
                            "mimeType": "application/vnd.google-apps.document",
                            "modifiedTime": "2026-04-03T10:00:00Z",
                            "owners": [{"displayName": "SecOps"}],
                            "webViewLink": "https://docs.google.com/document/d/file-1/edit",
                        }
                    ]
                },
            )
        assert request.url.path.endswith("/files/file-1/export")
        return httpx.Response(200, text="AKIAABCDEFGHIJKLMNOP")

    source = GoogleWorkspaceSource(
        "googleworkspace://drive?query=trashed%20%3D%20false&limit=5",
        client=httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0),
        config=GoogleWorkspaceConfig(token="ya29.test", drive_base_url="https://www.googleapis.com/drive/v3"),
    )
    loaded = source.load()

    assert loaded.source == "googleworkspace"
    assert loaded.metadata["least_privilege_preset"] == "google-workspace-drive-read"
    assert len(loaded.records) == 2
    assert "Prod Runbook" in loaded.records[0].message


def test_monday_source_scans_boards_items_and_updates() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v2"
        return httpx.Response(
            200,
            json={
                "data": {
                    "boards": [
                        {
                            "id": "b1",
                            "name": "Security Board",
                            "items_page": {
                                "items": [
                                    {
                                        "id": "i1",
                                        "name": "Leak triage",
                                        "updated_at": "2026-04-03T12:00:00Z",
                                        "column_values": [{"id": "text", "text": "owner=user@example.invalid"}],
                                        "updates": [
                                            {
                                                "id": "u1",
                                                "text_body": "secret=sk_live_fake",
                                                "created_at": "2026-04-03T12:10:00Z",
                                            }
                                        ],
                                    }
                                ]
                            },
                        }
                    ]
                }
            },
        )

    source = MondaySource(
        "monday://workspace?query=security&limit=10&include_updates=true",
        client=httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0),
        config=MondayConfig(token="token", api_url="https://api.monday.com/v2"),
    )
    loaded = source.load()

    assert loaded.source == "monday"
    assert loaded.metadata["least_privilege_preset"] == "monday"
    assert len(loaded.records) == 2


def test_teams_source_scans_channels_and_replies() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1.0/me/joinedTeams":
            return httpx.Response(200, json={"value": [{"id": "t1", "displayName": "Incident Response"}]})
        if request.url.path == "/v1.0/teams/t1/channels":
            return httpx.Response(200, json={"value": [{"id": "c1", "displayName": "war-room"}]})
        if request.url.path == "/v1.0/teams/t1/channels/c1/messages":
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "m1",
                            "body": {"content": "token=abc"},
                            "createdDateTime": "2026-04-03T13:00:00Z",
                        }
                    ]
                },
            )
        assert request.url.path == "/v1.0/teams/t1/channels/c1/messages/m1/replies"
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "r1",
                        "body": {"content": "owner=user@example.invalid"},
                        "createdDateTime": "2026-04-03T13:05:00Z",
                    }
                ]
            },
        )

    source = TeamsSource(
        "teams://workspace?team_query=Incident&limit=20&include_replies=true",
        client=httpx.Client(transport=httpx.MockTransport(handler), timeout=10.0),
        config=TeamsConfig(token="token", graph_base_url="https://graph.microsoft.com/v1.0"),
    )
    loaded = source.load()

    assert loaded.source == "teams"
    assert loaded.metadata["least_privilege_preset"] == "teams"
    assert len(loaded.records) == 2
