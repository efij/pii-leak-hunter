from __future__ import annotations

import json
import os
import tempfile
import zipfile
from contextlib import contextmanager
from datetime import datetime
from io import BytesIO
from pathlib import Path
from urllib.parse import quote, urlencode

from pii_leak_hunter import __version__
from pii_leak_hunter.analysis.exposure_graph import build_exposure_graph
from pii_leak_hunter.core.baseline import apply_baseline_payload, write_baseline
from pii_leak_hunter.core.models import Finding, ScanResult
from pii_leak_hunter.core.pipeline import Pipeline
from pii_leak_hunter.hunts import DIFF_SIGNATURE_FAMILIES, apply_hunt_baseline, prepare_hunt_result, write_hunt_artifact
from pii_leak_hunter.hunts.recipes import get_recipe, list_recipes
from pii_leak_hunter.loader.file_loader import load_file
from pii_leak_hunter.output.csv_writer import write_csv
from pii_leak_hunter.output.evidence_pack import write_evidence_pack
from pii_leak_hunter.output.html_writer import write_html_report
from pii_leak_hunter.output.json_writer import write_json
from pii_leak_hunter.output.markdown_writer import write_markdown
from pii_leak_hunter.output.sarif_writer import write_sarif
from pii_leak_hunter.providers.factory import (
    DEFAULT_PROVIDER_LOOKBACK,
    SUPPORTED_PROVIDERS,
    build_provider,
    normalize_provider_name,
    provider_query_hint,
    resolve_provider_scan_options,
)
from pii_leak_hunter.security.least_privilege import PRESETS, get_preset
from pii_leak_hunter.sources.registry import build_source
from pii_leak_hunter.ui.presentation import (
    build_diff_summary,
    build_findings_rows,
    exploitability_counts,
    finding_matches_filters,
    group_findings,
    top_triage_rows,
    top_growing_clusters,
    top_entity_families,
)
from pii_leak_hunter.utils.config import ConfigurationError

try:
    import streamlit as st
except Exception as exc:  # pragma: no cover - import depends on runtime env
    raise RuntimeError("Streamlit is required to run the UI.") from exc

REPO_URL = "https://github.com/efij/pii-leak-hunter"
DIFF_SIGNATURE_FAMILY_COUNT = len(DIFF_SIGNATURE_FAMILIES)


def run_app() -> None:
    st.set_page_config(page_title="PII Leak Hunter", layout="wide")
    _inject_styles()
    _initialize_state()
    _render_hero()

    show_raw_values, export_raw_values, selected_recipe = _render_sidebar()

    top_left, top_right = st.columns([1.6, 1])
    with top_left:
        st.subheader("1. Run a Scan")
        st.caption(
            "Choose one source, add session-only credentials if needed, run a read-only scan, then review grouped campaigns and export reports."
        )
        st.caption("Start simple: `Providers` for log platforms, `Platforms & Targets` for SaaS/URI scans, or `Files` for local artifacts.")
    with top_right:
        baseline_upload = st.file_uploader(
            "Optional compare-to baseline",
            type=["json", "zip"],
            key="baseline-uploader",
            help="Upload a prior safe scan JSON, baseline JSON, or evidence pack zip to compare new vs unchanged findings.",
        )

    remote_tab, target_tab, upload_tab, guide_tab = st.tabs(
        ["Providers", "Platforms & Targets", "Files", "Least Privilege"]
    )

    with remote_tab:
        _render_remote_provider_tab(baseline_upload)
    with target_tab:
        _render_target_tab(baseline_upload)
    with upload_tab:
        _render_local_upload_tab(baseline_upload)
    with guide_tab:
        _render_least_privilege_tab()

    result = st.session_state.get("scan_result")
    if isinstance(result, ScanResult):
        _render_result(
            result,
            show_raw_values=show_raw_values,
            export_raw_values=export_raw_values,
            selected_recipe=selected_recipe,
        )
    else:
        st.info("Run a scan to unlock the overview, grouped findings, audit report, and evidence exports.")


def _initialize_state() -> None:
    st.session_state.setdefault("scan_result", None)
    st.session_state.setdefault("scan_history", [])
    st.session_state.setdefault("coralogix_resume", None)
    st.session_state.setdefault("selected_recipe", "")


def _render_sidebar() -> tuple[bool, bool, str | None]:
    sidebar = st.sidebar
    sidebar.subheader("Session")
    sidebar.caption(f"Version: `v{__version__}`")
    sidebar.markdown(f"[Repository]({REPO_URL})")
    sidebar.caption(f"Hunt diff signatures: `{DIFF_SIGNATURE_FAMILY_COUNT}` families")
    show_raw_values = sidebar.checkbox(
        "Show raw values in GUI",
        value=True,
        help="Enabled by default so you can validate findings directly in the app.",
    )
    export_raw_values = sidebar.checkbox(
        "Unsafe: include raw values in exports",
        value=False,
        help="Leave this off unless you intentionally want downloads to contain raw values.",
    )
    recipe_options = [""] + [recipe.recipe_id for recipe in list_recipes()]
    selected_recipe = sidebar.selectbox(
        "Optional hunt recipe",
        options=recipe_options,
        format_func=lambda value: "All findings" if not value else value,
        key="selected_recipe",
        help="Optional high-signal recipe to focus the scan and triage view.",
    )
    if selected_recipe:
        recipe = get_recipe(selected_recipe)
        if recipe is not None:
            sidebar.caption(recipe.description)
    result = st.session_state.get("scan_result")
    if isinstance(result, ScanResult):
        sidebar.markdown("#### Current Result")
        sidebar.write(f"Source: `{result.source}`")
        sidebar.write(f"Records: `{result.records_scanned}`")
        sidebar.write(f"Findings: `{len(result.findings)}`")
    history = st.session_state.get("scan_history", [])
    if history:
        sidebar.markdown("#### Recent Runs")
        sidebar.dataframe(history[:8], use_container_width=True, hide_index=True)
    sidebar.caption("Credentials entered in this app stay in the current Streamlit session only.")
    return show_raw_values, export_raw_values, selected_recipe or None


def _render_remote_provider_tab(baseline_upload) -> None:
    left, right = st.columns([1.1, 1])
    with left:
        provider_name = st.selectbox(
            "Provider",
            options=list(SUPPORTED_PROVIDERS),
            key="remote-provider-name",
        )
        remote_scope = st.radio(
            "Remote scope",
            ["All logs for leaks", "Custom provider filter"],
            horizontal=True,
            key="remote-scope",
        )
        custom_query = ""
        if remote_scope == "Custom provider filter":
            custom_query = st.text_input(
                "Provider filter",
                value="",
                placeholder=provider_query_hint(provider_name),
                help="Optional provider-native filter when you want to narrow scope.",
                key=f"remote-query-{provider_name}",
            )
        else:
            st.info(
                f"We'll scan all available {provider_name} logs in the selected time window and hunt for secrets, PII, masking failures, and risky combinations automatically."
            )
        time_left, time_right = st.columns(2)
        with time_left:
            start = st.text_input(
                "From",
                value=DEFAULT_PROVIDER_LOOKBACK,
                help="Defaults to the past 24 hours.",
                key=f"remote-from-{provider_name}",
            )
        with time_right:
            end = st.text_input("To", value="now", key=f"remote-to-{provider_name}")
        if st.button(f"Scan {provider_name.title()} for leaks", type="primary", key=f"run-remote-{provider_name}"):
            env_overrides = _provider_env_overrides(provider_name)
            resolved_query, resolved_start = resolve_provider_scan_options(
                provider_name,
                custom_query if remote_scope == "Custom provider filter" else None,
                start,
            )
            _execute_scan(
                label=f"{provider_name} remote scan",
                baseline_upload=baseline_upload,
                env_overrides=env_overrides,
                runner=lambda progress_callback: _run_remote_provider_scan(
                    provider_name,
                    resolved_query,
                    resolved_start,
                    end,
                    progress_callback=progress_callback,
                ),
            )
        if provider_name == "coralogix":
            resume_bundle = st.session_state.get("coralogix_resume")
            if isinstance(resume_bundle, dict):
                st.warning("A partial Coralogix scan is available. You can resume it or discard it.")
                controls = st.columns(2)
                with controls[0]:
                    if st.button("Resume Partial Coralogix Scan", key="resume-coralogix-scan"):
                        env_overrides = _provider_env_overrides(provider_name)
                        _execute_scan(
                            label="coralogix remote scan",
                            baseline_upload=baseline_upload,
                            env_overrides=env_overrides,
                            runner=lambda progress_callback: _run_remote_provider_scan(
                                provider_name,
                                str(resume_bundle["query"]),
                                str(resume_bundle["from"]),
                                str(resume_bundle["to"]),
                                progress_callback=progress_callback,
                                resume=True,
                            ),
                        )
                with controls[1]:
                    if st.button("Discard Partial Scan", key="discard-coralogix-scan"):
                        st.session_state["coralogix_resume"] = None
                        st.info("Discarded the stored partial Coralogix scan.")
    with right:
        st.markdown("#### Connection Details")
        st.caption("These values are used for the current session scan and do not need to be exported as shell env vars first.")
        _render_provider_credentials(provider_name)


def _render_target_tab(baseline_upload) -> None:
    left, right = st.columns([1.15, 1])
    with left:
        target_mode = st.selectbox(
            "Target Type",
            options=[
                "Local path",
                "Raw target",
                "Postgres",
                "S3",
                "ServiceNow",
                "Notion",
                "Confluence",
                "Jira",
                "Azure DevOps",
                "GitHub",
                "Slack",
                "Google Workspace",
                "Monday",
                "Microsoft Teams",
                "Zendesk",
                "Snowflake",
            ],
            key="target-mode",
        )
        target, env_overrides, helper = _build_target_configuration(target_mode)
        st.markdown("#### Target Preview")
        st.code(target or "Target not ready yet.", language="text")
        if helper:
            st.caption(helper)
        if st.button("Scan target", type="primary", key=f"scan-target-{target_mode}"):
            if not target:
                st.error("Please complete the target details before starting the scan.")
            else:
                _execute_scan(
                    label=f"{target_mode} scan",
                    baseline_upload=baseline_upload,
                    env_overrides=env_overrides,
                    runner=lambda progress_callback: _run_target_scan(target),
                )
    with right:
        st.markdown("#### Builder Notes")
        st.write("- `Local path` scans files or directories that already exist on the host running Streamlit.")
        st.write("- `Raw target` accepts a full path or URI such as `postgres://...`, `slack://...`, `googleworkspace://...`, `monday://...`, `teams://...`, or `snowflake://...`.")
        st.write("- Collaboration and SaaS builders use session-only credentials so you do not need to preconfigure shell env vars.")
        st.write("- `S3` credentials are optional if the runtime already has AWS identity available.")


def _render_local_upload_tab(baseline_upload) -> None:
    uploaded = st.file_uploader(
        "Upload .log, .json, .ndjson, .gz, .bz2, or .zip",
        type=["log", "json", "ndjson", "gz", "bz2", "zip"],
        key="scan-source-uploader",
    )
    if uploaded:
        st.caption(f"Selected file: `{uploaded.name}`")
    if uploaded and st.button("Scan uploaded file", type="primary", key="scan-local-upload"):
        _execute_scan(
            label=f"Uploaded file scan ({uploaded.name})",
            baseline_upload=baseline_upload,
            env_overrides={},
            runner=lambda progress_callback: _scan_uploaded_file(uploaded),
        )


def _render_least_privilege_tab() -> None:
    preset_name = st.selectbox(
        "Integration preset",
        options=[""] + sorted(PRESETS),
        format_func=lambda value: "Select an integration" if not value else value,
        key="least-privilege-select",
    )
    if preset_name:
        _render_preset(preset_name)


def _render_provider_credentials(provider_name: str) -> None:
    provider = normalize_provider_name(provider_name)
    if provider == "coralogix":
        _secret_input("CORALOGIX_API_KEY", "API key", prefix="provider")
        _text_input("CORALOGIX_REGION", "Region, app host, or API host", prefix="provider", default="")
        st.caption("Use a short region like `us1`, an API host, or paste your full Coralogix app URL.")
    elif provider == "cloudwatch":
        _text_input("AWS_REGION", "Region", prefix="provider", default="")
        _text_input("AWS_CLOUDWATCH_LOG_GROUP_PREFIX", "Log group prefix", prefix="provider", default="")
        _text_input("AWS_CLOUDWATCH_LOG_GROUPS", "Explicit log groups (comma-separated)", prefix="provider", default="")
        _text_input("AWS_CLOUDWATCH_MAX_LOG_GROUPS", "Max log groups", prefix="provider", default="50")
        _text_input("AWS_ACCESS_KEY_ID", "Access key ID", prefix="provider")
        _secret_input("AWS_SECRET_ACCESS_KEY", "Secret access key", prefix="provider")
        _secret_input("AWS_SESSION_TOKEN", "Session token", prefix="provider")
    elif provider == "datadog":
        _secret_input("DATADOG_API_KEY", "API key", prefix="provider")
        _secret_input("DATADOG_APP_KEY", "Application key", prefix="provider")
        _text_input("DATADOG_SITE", "Site", prefix="provider", default="")
    elif provider == "dynatrace":
        _secret_input("DYNATRACE_API_TOKEN", "API token", prefix="provider")
        _text_input("DYNATRACE_ENV_URL", "Environment URL", prefix="provider", default="")
    elif provider == "splunk":
        _text_input("SPLUNK_BASE_URL", "Base URL", prefix="provider", default="")
        auth_mode = st.radio(
            "Splunk auth",
            ["Bearer token", "Username / password"],
            horizontal=True,
            key="provider-splunk-auth-mode",
        )
        if auth_mode == "Bearer token":
            _secret_input("SPLUNK_TOKEN", "Token", prefix="provider")
        else:
            _text_input("SPLUNK_USERNAME", "Username", prefix="provider")
            _secret_input("SPLUNK_PASSWORD", "Password", prefix="provider")
    elif provider == "newrelic":
        _secret_input("NEW_RELIC_API_KEY", "User API key", prefix="provider")
        _text_input("NEW_RELIC_ACCOUNT_ID", "Account ID", prefix="provider")
        st.selectbox("Region", options=["us", "eu"], key="provider-NEW_RELIC_REGION")


def _provider_env_overrides(provider_name: str) -> dict[str, str | None]:
    provider = normalize_provider_name(provider_name)
    if provider == "coralogix":
        return _env_values(["CORALOGIX_API_KEY", "CORALOGIX_REGION"], prefix="provider")
    if provider == "cloudwatch":
        overrides = _env_values(
            [
                "AWS_REGION",
                "AWS_CLOUDWATCH_LOG_GROUP_PREFIX",
                "AWS_CLOUDWATCH_LOG_GROUPS",
                "AWS_CLOUDWATCH_MAX_LOG_GROUPS",
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
            ],
            prefix="provider",
        )
        overrides["AWS_DEFAULT_REGION"] = overrides.get("AWS_REGION")
        return overrides
    if provider == "datadog":
        return _env_values(["DATADOG_API_KEY", "DATADOG_APP_KEY", "DATADOG_SITE"], prefix="provider")
    if provider == "dynatrace":
        return _env_values(["DYNATRACE_API_TOKEN", "DYNATRACE_ENV_URL"], prefix="provider")
    if provider == "splunk":
        overrides = _env_values(["SPLUNK_BASE_URL"], prefix="provider")
        auth_mode = st.session_state.get("provider-splunk-auth-mode", "Bearer token")
        if auth_mode == "Bearer token":
            overrides.update(_env_values(["SPLUNK_TOKEN"], prefix="provider"))
            overrides["SPLUNK_USERNAME"] = None
            overrides["SPLUNK_PASSWORD"] = None
        else:
            overrides.update(_env_values(["SPLUNK_USERNAME", "SPLUNK_PASSWORD"], prefix="provider"))
            overrides["SPLUNK_TOKEN"] = None
        return overrides
    if provider == "newrelic":
        return _env_values(["NEW_RELIC_API_KEY", "NEW_RELIC_ACCOUNT_ID", "NEW_RELIC_REGION"], prefix="provider")
    return {}


def _build_target_configuration(target_mode: str) -> tuple[str, dict[str, str | None], str]:
    if target_mode == "Local path":
        path = st.text_input("Path", value="", placeholder="/var/log/app or ./fixtures/demo_logs.ndjson", key="target-local-path")
        return path.strip(), {}, "Paths are read from the machine running Streamlit."
    if target_mode == "Raw target":
        target = st.text_input(
            "Target",
            value="",
            placeholder="postgres://... | s3://... | jira://... | github://... | snowflake://...",
            key="target-raw-uri",
        )
        return target.strip(), {}, "Use this when you already know the exact path or URI."
    if target_mode == "Postgres":
        host_col, db_col = st.columns(2)
        with host_col:
            host = st.text_input("Host", value="localhost", key="target-pg-host")
        with db_col:
            database = st.text_input("Database", value="app", key="target-pg-db")
        auth_col, secret_col = st.columns(2)
        with auth_col:
            user = st.text_input("User", value="postgres", key="target-pg-user")
        with secret_col:
            password = st.text_input("Password", value="", type="password", key="target-pg-password")
        option_col, table_col = st.columns(2)
        with option_col:
            schema = st.text_input("Schema", value="public", key="target-pg-schema")
            row_limit = st.number_input("Row limit per table", min_value=1, value=1000, step=100, key="target-pg-row-limit")
        with table_col:
            port = st.number_input("Port", min_value=1, value=5432, step=1, key="target-pg-port")
            tables = st.text_input("Tables (comma-separated, optional)", value="", key="target-pg-tables")
        query = {"schema": schema, "row_limit": str(int(row_limit))}
        if tables.strip():
            query["tables"] = tables.strip()
        userinfo = quote(user, safe="")
        if password:
            userinfo = f"{userinfo}:{quote(password, safe='')}"
        target = f"postgres://{userinfo}@{host}:{int(port)}/{database}?{urlencode(query)}"
        return target, {}, "Connection details are embedded in the URI for the current session only."
    if target_mode == "S3":
        bucket = st.text_input("Bucket", value="", key="target-s3-bucket")
        prefix = st.text_input("Prefix / key", value="", key="target-s3-prefix")
        st.markdown("#### AWS Credentials")
        _text_input("AWS_ACCESS_KEY_ID", "Access key ID", prefix="target")
        _secret_input("AWS_SECRET_ACCESS_KEY", "Secret access key", prefix="target")
        _secret_input("AWS_SESSION_TOKEN", "Session token", prefix="target")
        _text_input("AWS_REGION", "Region", prefix="target")
        normalized_prefix = prefix.lstrip("/")
        target = f"s3://{bucket}/{normalized_prefix}" if normalized_prefix else f"s3://{bucket}/"
        env_overrides = _env_values(
            ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION"],
            prefix="target",
        )
        env_overrides["AWS_DEFAULT_REGION"] = env_overrides.get("AWS_REGION")
        return target if bucket.strip() else "", env_overrides, "Optional AWS credentials override the runtime identity for this session."
    if target_mode == "ServiceNow":
        instance = st.text_input("Instance host", value="", key="target-snow-instance")
        table = st.text_input("Table", value="incident", key="target-snow-table")
        query = st.text_input("Query", value="active=true", key="target-snow-query")
        page_size = st.number_input("Page size", min_value=1, value=100, step=25, key="target-snow-page-size")
        auth_mode = st.radio(
            "ServiceNow auth",
            ["Bearer token", "Username / password"],
            horizontal=True,
            key="target-snow-auth-mode",
        )
        if auth_mode == "Bearer token":
            _secret_input("SERVICENOW_BEARER_TOKEN", "Bearer token", prefix="target")
            env_overrides = _env_values(["SERVICENOW_BEARER_TOKEN"], prefix="target")
            env_overrides["SERVICENOW_USERNAME"] = None
            env_overrides["SERVICENOW_PASSWORD"] = None
        else:
            _text_input("SERVICENOW_USERNAME", "Username", prefix="target")
            _secret_input("SERVICENOW_PASSWORD", "Password", prefix="target")
            env_overrides = _env_values(["SERVICENOW_USERNAME", "SERVICENOW_PASSWORD"], prefix="target")
            env_overrides["SERVICENOW_BEARER_TOKEN"] = None
        params = urlencode({"table": table, "query": query, "page_size": str(int(page_size))})
        target = f"servicenow://{instance}?{params}" if instance.strip() else ""
        return target, env_overrides, "Use the builder if you want session-only ServiceNow auth without shell env vars."
    if target_mode == "Notion":
        query = st.text_input("Search query", value="", key="target-notion-query")
        page_size = st.number_input("Page size", min_value=1, value=25, step=5, key="target-notion-page-size")
        _secret_input("NOTION_API_KEY", "API key", prefix="target")
        _text_input("NOTION_VERSION", "Notion API version", prefix="target", default="2026-03-11")
        target = f"notion://workspace?{urlencode({'query': query, 'page_size': str(int(page_size))})}"
        env_overrides = _env_values(["NOTION_API_KEY", "NOTION_VERSION"], prefix="target")
        return target, env_overrides, "The builder will scan page titles and block content returned by the Notion search API."
    if target_mode == "Confluence":
        base_url = st.text_input("Base URL", value="", placeholder="https://your-domain.atlassian.net/wiki", key="target-confluence-base")
        cql = st.text_input("CQL", value='type = "page" ORDER BY lastmodified DESC', key="target-confluence-cql")
        limit = st.number_input("Limit", min_value=1, value=25, step=5, key="target-confluence-limit")
        auth_mode = st.radio("Confluence auth", ["Bearer token", "Email / API token"], horizontal=True, key="target-confluence-auth")
        if auth_mode == "Bearer token":
            _secret_input("CONFLUENCE_BEARER_TOKEN", "Bearer token", prefix="target")
            env_overrides = _env_values(["CONFLUENCE_BEARER_TOKEN"], prefix="target")
            env_overrides["CONFLUENCE_EMAIL"] = None
            env_overrides["CONFLUENCE_API_TOKEN"] = None
        else:
            _text_input("CONFLUENCE_EMAIL", "Email", prefix="target")
            _secret_input("CONFLUENCE_API_TOKEN", "API token", prefix="target")
            env_overrides = _env_values(["CONFLUENCE_EMAIL", "CONFLUENCE_API_TOKEN"], prefix="target")
            env_overrides["CONFLUENCE_BEARER_TOKEN"] = None
        env_overrides["CONFLUENCE_BASE_URL"] = base_url.strip() or None
        target = f"confluence://workspace?{urlencode({'base_url': base_url, 'cql': cql, 'limit': str(int(limit))})}" if base_url.strip() else ""
        return target, env_overrides, "Searches Confluence pages and then fetches matching page bodies for deeper scanning."
    if target_mode == "Jira":
        base_url = st.text_input("Base URL", value="", placeholder="https://your-domain.atlassian.net", key="target-jira-base")
        jql = st.text_input("JQL", value="ORDER BY updated DESC", key="target-jira-jql")
        limit = st.number_input("Limit", min_value=1, value=25, step=5, key="target-jira-limit")
        auth_mode = st.radio("Jira auth", ["Bearer token", "Email / API token"], horizontal=True, key="target-jira-auth")
        if auth_mode == "Bearer token":
            _secret_input("JIRA_BEARER_TOKEN", "Bearer token", prefix="target")
            env_overrides = _env_values(["JIRA_BEARER_TOKEN"], prefix="target")
            env_overrides["JIRA_EMAIL"] = None
            env_overrides["JIRA_API_TOKEN"] = None
        else:
            _text_input("JIRA_EMAIL", "Email", prefix="target")
            _secret_input("JIRA_API_TOKEN", "API token", prefix="target")
            env_overrides = _env_values(["JIRA_EMAIL", "JIRA_API_TOKEN"], prefix="target")
            env_overrides["JIRA_BEARER_TOKEN"] = None
        env_overrides["JIRA_BASE_URL"] = base_url.strip() or None
        target = f"jira://workspace?{urlencode({'base_url': base_url, 'jql': jql, 'limit': str(int(limit))})}" if base_url.strip() else ""
        return target, env_overrides, "Scans issue titles, descriptions, and comments from the Jira search API."
    if target_mode == "Azure DevOps":
        organization_url = st.text_input("Organization URL", value="", placeholder="https://dev.azure.com/org", key="target-ado-org")
        project = st.text_input("Project", value="", key="target-ado-project")
        wiql = st.text_input(
            "WIQL",
            value="Select [System.Id] From WorkItems Order By [System.ChangedDate] Desc",
            key="target-ado-wiql",
        )
        limit = st.number_input("Limit", min_value=1, value=25, step=5, key="target-ado-limit")
        repository_query = st.text_input(
            "Repository filter (optional)",
            value="",
            key="target-ado-repository-query",
        )
        include_pull_requests = st.checkbox(
            "Include pull requests and review threads",
            value=True,
            key="target-ado-include-prs",
        )
        pr_limit = st.number_input("Pull requests per repo", min_value=1, value=15, step=5, key="target-ado-pr-limit")
        _secret_input("AZURE_DEVOPS_PAT", "Personal Access Token", prefix="target")
        env_overrides = _env_values(["AZURE_DEVOPS_PAT"], prefix="target")
        env_overrides["AZURE_DEVOPS_ORG_URL"] = organization_url.strip() or None
        target = (
            f"azuredevops://workspace?{urlencode({'organization_url': organization_url, 'project': project, 'wiql': wiql, 'limit': str(int(limit)), 'repository_query': repository_query, 'include_pull_requests': str(include_pull_requests).lower(), 'pr_limit': str(int(pr_limit))})}"
            if organization_url.strip() and project.strip()
            else ""
        )
        return target, env_overrides, "Scans Azure DevOps work items plus pull request titles, descriptions, and review threads across matching repos in the project."
    if target_mode == "GitHub":
        owner = st.text_input("Owner", value="", key="target-github-owner")
        repo = st.text_input("Repository (optional)", value="", key="target-github-repo")
        state = st.selectbox("State", options=["all", "open", "closed"], key="target-github-state")
        limit = st.number_input("Limit", min_value=1, value=25, step=5, key="target-github-limit")
        include_comments = st.checkbox("Include issue / PR comments", value=True, key="target-github-comments")
        include_review_comments = st.checkbox("Include PR review comments", value=True, key="target-github-review-comments")
        _secret_input("GITHUB_TOKEN", "Token", prefix="target")
        _text_input("GITHUB_API_URL", "API base URL", prefix="target", default="https://api.github.com")
        env_overrides = _env_values(["GITHUB_TOKEN", "GITHUB_API_URL"], prefix="target")
        target = (
            f"github://{owner}/{repo}?{urlencode({'state': state, 'limit': str(int(limit)), 'include_comments': str(include_comments).lower(), 'include_review_comments': str(include_review_comments).lower()})}"
            if owner.strip() and repo.strip()
            else f"github://{owner}?{urlencode({'state': state, 'limit': str(int(limit)), 'include_comments': str(include_comments).lower(), 'include_review_comments': str(include_review_comments).lower()})}"
            if owner.strip()
            else ""
        )
        return target, env_overrides, "Scans GitHub issues, pull requests, issue comments, and PR review comments. Leave repository blank to scan all repos visible under the owner."
    if target_mode == "Slack":
        channel_query = st.text_input("Channel name filter", value="", key="target-slack-channel-query")
        channel_ids = st.text_input("Explicit channels (comma-separated, optional)", value="", key="target-slack-channel-ids")
        limit = st.number_input("Messages per channel", min_value=1, value=200, step=50, key="target-slack-limit")
        include_private = st.checkbox("Include private channels", value=False, key="target-slack-private")
        _secret_input("SLACK_BOT_TOKEN", "Bot token", prefix="target")
        _text_input("SLACK_API_URL", "API base URL", prefix="target", default="https://slack.com/api")
        env_overrides = _env_values(["SLACK_BOT_TOKEN", "SLACK_API_URL"], prefix="target")
        params = {"limit": str(int(limit)), "include_private": str(include_private).lower()}
        if channel_query.strip():
            params["channel_query"] = channel_query.strip()
        if channel_ids.strip():
            params["channels"] = channel_ids.strip()
        target = f"slack://workspace?{urlencode(params)}"
        return target, env_overrides, "Scans channel history from Slack conversations. Start with public channels and add private access only if truly needed."
    if target_mode == "Google Workspace":
        query = st.text_input("Drive query", value="trashed = false", key="target-googleworkspace-query")
        limit = st.number_input("Files limit", min_value=1, value=25, step=5, key="target-googleworkspace-limit")
        include_shared_drives = st.checkbox("Include shared drives", value=True, key="target-googleworkspace-shared")
        _secret_input("GOOGLE_WORKSPACE_TOKEN", "OAuth access token", prefix="target")
        _text_input(
            "GOOGLE_WORKSPACE_DRIVE_API_URL",
            "Drive API base URL",
            prefix="target",
            default="https://www.googleapis.com/drive/v3",
        )
        env_overrides = _env_values(["GOOGLE_WORKSPACE_TOKEN", "GOOGLE_WORKSPACE_DRIVE_API_URL"], prefix="target")
        target = f"googleworkspace://drive?{urlencode({'query': query, 'limit': str(int(limit)), 'include_shared_drives': str(include_shared_drives).lower()})}"
        return target, env_overrides, "Starts with Drive/Docs/Sheets content. This complements Google DLP by correlating Workspace findings with all the other systems you scan here."
    if target_mode == "Monday":
        query = st.text_input("Board or item filter", value="", key="target-monday-query")
        limit = st.number_input("Boards / items limit", min_value=1, value=25, step=5, key="target-monday-limit")
        include_updates = st.checkbox("Include item updates", value=True, key="target-monday-updates")
        _secret_input("MONDAY_API_TOKEN", "API token", prefix="target")
        _text_input("MONDAY_API_URL", "API URL", prefix="target", default="https://api.monday.com/v2")
        env_overrides = _env_values(["MONDAY_API_TOKEN", "MONDAY_API_URL"], prefix="target")
        target = f"monday://workspace?{urlencode({'query': query, 'limit': str(int(limit)), 'include_updates': str(include_updates).lower()})}"
        return target, env_overrides, "Scans monday boards, items, and updates for pasted secrets and sensitive data."
    if target_mode == "Microsoft Teams":
        team_query = st.text_input("Team filter", value="", key="target-teams-team-query")
        team_ids = st.text_input("Explicit teams (comma-separated, optional)", value="", key="target-teams-team-ids")
        channel_query = st.text_input("Channel filter", value="", key="target-teams-channel-query")
        limit = st.number_input("Messages per channel", min_value=1, value=50, step=10, key="target-teams-limit")
        include_replies = st.checkbox("Include replies", value=True, key="target-teams-replies")
        _secret_input("TEAMS_GRAPH_TOKEN", "Microsoft Graph token", prefix="target")
        _text_input("TEAMS_GRAPH_API_URL", "Graph API base URL", prefix="target", default="https://graph.microsoft.com/v1.0")
        env_overrides = _env_values(["TEAMS_GRAPH_TOKEN", "TEAMS_GRAPH_API_URL"], prefix="target")
        params = {
            "limit": str(int(limit)),
            "include_replies": str(include_replies).lower(),
        }
        if team_query.strip():
            params["team_query"] = team_query.strip()
        if team_ids.strip():
            params["teams"] = team_ids.strip()
        if channel_query.strip():
            params["channel_query"] = channel_query.strip()
        target = f"teams://workspace?{urlencode(params)}"
        return target, env_overrides, "Scans Microsoft Teams channels and replies across joined teams, or narrow it with team and channel filters."
    if target_mode == "Zendesk":
        base_url = st.text_input("Base URL", value="", placeholder="https://your-org.zendesk.com", key="target-zendesk-base")
        query = st.text_input("Search query", value="type:ticket updated>1day", key="target-zendesk-query")
        limit = st.number_input("Limit", min_value=1, value=25, step=5, key="target-zendesk-limit")
        include_comments = st.checkbox("Include ticket comments", value=True, key="target-zendesk-comments")
        auth_mode = st.radio("Zendesk auth", ["Bearer token", "Email / API token"], horizontal=True, key="target-zendesk-auth")
        if auth_mode == "Bearer token":
            _secret_input("ZENDESK_BEARER_TOKEN", "Bearer token", prefix="target")
            env_overrides = _env_values(["ZENDESK_BEARER_TOKEN"], prefix="target")
            env_overrides["ZENDESK_EMAIL"] = None
            env_overrides["ZENDESK_API_TOKEN"] = None
        else:
            _text_input("ZENDESK_EMAIL", "Email", prefix="target")
            _secret_input("ZENDESK_API_TOKEN", "API token", prefix="target")
            env_overrides = _env_values(["ZENDESK_EMAIL", "ZENDESK_API_TOKEN"], prefix="target")
            env_overrides["ZENDESK_BEARER_TOKEN"] = None
        env_overrides["ZENDESK_BASE_URL"] = base_url.strip() or None
        target = (
            f"zendesk://workspace?{urlencode({'base_url': base_url, 'query': query, 'limit': str(int(limit)), 'include_comments': str(include_comments).lower()})}"
            if base_url.strip()
            else ""
        )
        return target, env_overrides, "Scans Zendesk search results and optionally ticket comments for pasted sensitive data."
    if target_mode == "Snowflake":
        account_url = st.text_input("Account URL", value="", placeholder="https://account.region.snowflakecomputing.com", key="target-snowflake-url")
        warehouse = st.text_input("Warehouse", value="", key="target-snowflake-warehouse")
        database = st.text_input("Database", value="", key="target-snowflake-db")
        schema = st.text_input("Schema", value="", key="target-snowflake-schema")
        table = st.text_input("Table (optional)", value="", key="target-snowflake-table")
        limit = st.number_input("Limit", min_value=1, value=250, step=50, key="target-snowflake-limit")
        statement = st.text_area(
            "Statement",
            value="",
            placeholder="Leave blank to auto-build SELECT * FROM <table> LIMIT <n>",
            key="target-snowflake-statement",
        )
        _secret_input("SNOWFLAKE_TOKEN", "Programmatic access token", prefix="target")
        _text_input("SNOWFLAKE_ROLE", "Role", prefix="target", default="")
        query_params = {
            "account_url": account_url,
            "limit": str(int(limit)),
        }
        if statement.strip():
            query_params["statement"] = statement.strip()
        elif table.strip():
            query_params["table"] = table.strip()
        target = f"snowflake://workspace?{urlencode(query_params)}" if account_url.strip() else ""
        env_overrides = _env_values(["SNOWFLAKE_TOKEN", "SNOWFLAKE_ROLE"], prefix="target")
        env_overrides["SNOWFLAKE_ACCOUNT_URL"] = account_url.strip() or None
        env_overrides["SNOWFLAKE_WAREHOUSE"] = warehouse.strip() or None
        env_overrides["SNOWFLAKE_DATABASE"] = database.strip() or None
        env_overrides["SNOWFLAKE_SCHEMA"] = schema.strip() or None
        return target, env_overrides, "Snowflake uses the SQL API with a read-only statement or auto-built table scan."
    return "", {}, ""


def _execute_scan(
    *,
    label: str,
    baseline_upload,
    env_overrides: dict[str, str | None],
    runner,
) -> None:
    progress = st.progress(0)
    status = st.empty()
    detail = st.empty()
    try:
        status.markdown(f"**{label}**: validating configuration")
        detail.caption("Preparing scan context.")
        progress.progress(10)
        with _temporary_environment(env_overrides):
            status.markdown(f"**{label}**: connecting and loading records")
            progress.progress(35)
            result = runner(_make_progress_callback(progress, status, detail, label))
        recipe_id = st.session_state.get("selected_recipe") or None
        if recipe_id:
            result = prepare_hunt_result(
                result,
                recipe_id=recipe_id,
                target=label,
                lookback=str(result.metadata.get("from", result.metadata.get("lookback", "n/a"))),
            )
        status.markdown(f"**{label}**: loaded `{result.records_scanned}` record(s), analyzing findings")
        detail.caption("Running detection, correlation, and scoring.")
        progress.progress(60)
        status.markdown(f"**{label}**: analyzing records")
        progress.progress(75)
        result = _apply_uploaded_baseline(result, baseline_upload)
        progress.progress(92)
        st.session_state["scan_result"] = result
        _remember_scan(result)
        progress.progress(100)
        status.markdown(f"**{label}**: complete")
        detail.caption(
            f"Finished in {_format_seconds(result.metadata.get('provider_details', {}).get('elapsed_seconds', 0.0)) if isinstance(result.metadata.get('provider_details'), dict) else '0s'}."
        )
        if result.records_scanned == 0:
            st.warning(f"Scan completed but {result.source} returned 0 parsed record(s). Check Scan Details below for the exact query and provider response summary.")
        else:
            st.success(f"Scanned {result.records_scanned} record(s) from {result.source}.")
    except ConfigurationError as exc:
        st.error(str(exc))
    except Exception as exc:
        st.error(f"Scan failed: {exc}")


def _run_remote_provider_scan(
    provider_name: str,
    query: str,
    start: str,
    end: str,
    *,
    progress_callback=None,
    resume: bool = False,
) -> ScanResult:
    recipe_id = st.session_state.get("selected_recipe") or None
    provider = build_provider(provider_name)
    previous_records = []
    if normalize_provider_name(provider_name) == "coralogix" and resume:
        bundle = st.session_state.get("coralogix_resume")
        if isinstance(bundle, dict):
            previous_records = list(bundle.get("records", []))
            if hasattr(provider, "resume_state"):
                provider.resume_state = bundle.get("resume_state")
    if hasattr(provider, "set_progress_callback"):
        provider.set_progress_callback(progress_callback)
    records = provider.fetch(query=query, start=start, end=end)
    if previous_records:
        records = _dedupe_log_records(previous_records + records)
    provider_details = getattr(provider, "last_fetch_details", {})
    if normalize_provider_name(provider_name) == "coralogix":
        if isinstance(provider_details, dict) and provider_details.get("resume_available"):
            st.session_state["coralogix_resume"] = {
                "query": query,
                "from": start,
                "to": end,
                "resume_state": provider_details.get("resume_state"),
                "records": records,
            }
        else:
            st.session_state["coralogix_resume"] = None
    return Pipeline().run(
        records,
        source=normalize_provider_name(provider_name),
        metadata={
            "mode": "remote",
            "provider": normalize_provider_name(provider_name),
            "query": query,
            "from": start,
            "to": end,
            "provider_details": provider_details,
        },
        recipe_id=recipe_id,
    )


def _run_target_scan(target: str) -> ScanResult:
    recipe_id = st.session_state.get("selected_recipe") or None
    loaded = build_source(target).load()
    return Pipeline().run(loaded.records, source=loaded.source, metadata=loaded.metadata, recipe_id=recipe_id)


def _scan_uploaded_file(uploaded) -> ScanResult:
    recipe_id = st.session_state.get("selected_recipe") or None
    suffix = Path(uploaded.name).suffix or ".ndjson"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
        handle.write(uploaded.getvalue())
        temp_path = handle.name
    try:
        records = load_file(temp_path)
    finally:
        Path(temp_path).unlink(missing_ok=True)
    return Pipeline().run(records, source=uploaded.name, metadata={"mode": "file"}, recipe_id=recipe_id)


def _apply_uploaded_baseline(result: ScanResult, uploaded) -> ScanResult:
    if uploaded is None:
        return result
    payload = _load_baseline_payload(uploaded)
    if isinstance(payload, dict) and payload.get("cluster_signatures") is not None:
        return apply_hunt_baseline(result, payload, baseline_source=uploaded.name)
    return apply_baseline_payload(result, payload, baseline_source=uploaded.name)


def _load_baseline_payload(uploaded) -> dict[str, object]:
    suffix = Path(uploaded.name).suffix.lower()
    data = uploaded.getvalue()
    if suffix == ".zip":
        with zipfile.ZipFile(BytesIO(data)) as archive:
            candidates = [name for name in archive.namelist() if name.endswith("evidence.json")]
            if not candidates:
                raise ValueError("Evidence zip must include evidence.json.")
            return json.loads(archive.read(candidates[0]).decode("utf-8"))
    return json.loads(data.decode("utf-8"))


def _remember_scan(result: ScanResult) -> None:
    history = list(st.session_state.get("scan_history", []))
    history.insert(
        0,
        {
            "time": datetime.now().strftime("%H:%M:%S"),
            "source": result.source,
            "records": result.records_scanned,
            "findings": len(result.findings),
        },
    )
    st.session_state["scan_history"] = history[:12]


def _make_progress_callback(progress, status, detail, label: str):
    def callback(event: dict[str, object]) -> None:
        provider = str(event.get("provider", "provider"))
        note = str(event.get("note", "Working"))
        processed = int(event.get("processed_windows", 0))
        queued = int(event.get("queued_windows", 0))
        discovered = int(event.get("discovered_windows", processed + queued))
        ratio = float(event.get("progress", 0.0))
        progress_value = min(90, max(15, int(ratio * 100)))
        elapsed = _format_seconds(float(event.get("elapsed_seconds", 0.0)))
        eta_raw = event.get("eta_seconds")
        eta = _format_seconds(float(eta_raw)) if isinstance(eta_raw, (int, float)) else "estimating"
        window = f"{event.get('window_start', '')} -> {event.get('window_end', '')}"
        tier = str(event.get("tier", ""))
        stage = str(event.get("stage", "running"))
        raw_rows = event.get("raw_rows")
        parsed_rows = event.get("parsed_rows")
        counts = []
        if raw_rows is not None:
            counts.append(f"raw={raw_rows}")
        if parsed_rows is not None:
            counts.append(f"parsed={parsed_rows}")
        counts_text = f" | {' '.join(counts)}" if counts else ""
        status.markdown(f"**{label}**: {provider} {stage}")
        detail.caption(
            f"{note} | tier={tier} | window={window} | processed={processed} queued={queued} discovered={discovered} | elapsed={elapsed} | eta~={eta}{counts_text}"
        )
        progress.progress(progress_value)

    return callback


def _format_seconds(value: float) -> str:
    total = max(0, int(round(value)))
    minutes, seconds = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    if minutes:
        return f"{minutes}m {seconds:02d}s"
    return f"{seconds}s"


@contextmanager
def _temporary_environment(overrides: dict[str, str | None]):
    original: dict[str, str | None] = {}
    for key, value in overrides.items():
        original[key] = os.environ.get(key)
        if value is None or value == "":
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _env_values(names: list[str], *, prefix: str) -> dict[str, str | None]:
    return {
        name: st.session_state.get(_state_key(prefix, name), "").strip() or None
        for name in names
    }


def _text_input(name: str, label: str, *, prefix: str, default: str = "") -> str:
    key = _state_key(prefix, name)
    initial = st.session_state.get(key, os.getenv(name, default))
    return st.text_input(label, value=initial, key=key)


def _secret_input(name: str, label: str, *, prefix: str) -> str:
    key = _state_key(prefix, name)
    initial = st.session_state.get(key, os.getenv(name, ""))
    return st.text_input(label, value=initial, key=key, type="password")


def _state_key(prefix: str, name: str) -> str:
    return f"{prefix}-{name}"


def _render_result(
    result: ScanResult,
    show_raw_values: bool = True,
    export_raw_values: bool = False,
    selected_recipe: str | None = None,
) -> None:
    st.subheader("2. Review Results")
    st.caption("Stay in `Campaigns` for the simple view. Drop into `Details` only when you need provider response data or the full graph.")
    summary_tab, campaigns_tab, reports_tab, details_tab = st.tabs(["Summary", "Campaigns", "Reports", "Details"])
    diff = build_diff_summary(result)
    with summary_tab:
        _render_summary_tab(result, diff, selected_recipe)
    with campaigns_tab:
        report_result = _render_campaigns_tab(result, diff, show_raw_values=show_raw_values)
    with reports_tab:
        _render_reports(report_result, unsafe_show_values=export_raw_values, include_values_in_graph=show_raw_values)
    with details_tab:
        _render_details_tab(result, show_raw_values=show_raw_values)


def _render_summary_tab(result: ScanResult, diff, selected_recipe: str | None) -> None:
    meta_col, action_col = st.columns([1.25, 1])
    with meta_col:
        st.caption(f"Source: `{result.source}` | Records scanned: `{result.records_scanned}` | Findings: `{len(result.findings)}`")
        if selected_recipe:
            recipe = get_recipe(selected_recipe)
            if recipe is not None:
                st.caption(f"Hunt recipe: `{recipe.title}`")
    with action_col:
        st.download_button(
            "Download Baseline Artifact",
            data=_build_baseline_data(result),
            file_name="baseline.json",
            mime="application/json",
        )
        st.download_button(
            "Download Hunt Artifact",
            data=_build_hunt_data(result),
            file_name="hunt-artifact.json",
            mime="application/json",
        )
    _render_severity_cards(result)
    if diff.active:
        _render_diff_cards(diff)

    overview_left, overview_right = st.columns(2)
    with overview_left:
        st.markdown("#### Triage Queue")
        triage_rows = top_triage_rows(result.findings)
        st.dataframe(
            triage_rows or [{"priority": "P4", "score": 0, "bucket": "backlog", "severity": "low", "type": "none", "source": result.source, "record_id": "-", "summary": "No findings"}],
            use_container_width=True,
        )
        st.markdown("#### Exploitability")
        ladder_rows = [{"priority": priority, "count": count} for priority, count in exploitability_counts(result.findings)]
        st.dataframe(ladder_rows or [{"priority": "P4", "count": 0}], use_container_width=True)
        hunt_summary = result.metadata.get("hunt_summary", {})
        if isinstance(hunt_summary, dict) and hunt_summary:
            st.markdown("#### Hunt Delta")
            st.write(
                f"New exposures: `{hunt_summary.get('new_clusters', 0)}` | Existing: `{hunt_summary.get('existing_clusters', 0)}` | Resolved: `{hunt_summary.get('resolved_clusters', 0)}`"
            )
    with overview_right:
        st.markdown("#### Top Campaigns")
        growing_rows = top_growing_clusters(result)
        st.dataframe(
            growing_rows or [{"cluster": "None", "priority": "P4", "severity": "low", "seen_count": 0, "source_count": 0, "asset_count": 0, "first_seen": "", "last_seen": ""}],
            use_container_width=True,
        )
        st.markdown("#### Top Entity Families")
        entity_rows = [{"entity": entity, "count": count} for entity, count in top_entity_families(result.findings)]
        st.dataframe(entity_rows or [{"entity": "None", "count": 0}], use_container_width=True)
        st.markdown("#### Asset Snapshot")
        st.dataframe(_asset_rows(result) or [{"asset": "unknown", "priority": "P4", "source": result.source}], use_container_width=True)


def _render_campaigns_tab(result: ScanResult, diff, *, show_raw_values: bool) -> ScanResult:
    st.caption("Grouped campaigns are the default view. Switch to raw findings only when you need record-level confirmation.")
    default_statuses = ["current"]
    if diff.active:
        default_statuses = ["new", "existing", "current"]
    controls = st.columns(5)
    with controls[0]:
        selected_severities = st.multiselect(
            "Severity",
            options=["critical", "high", "medium", "low"],
            default=["critical", "high", "medium", "low"],
        )
    with controls[1]:
        selected_priorities = st.multiselect(
            "Exploitability",
            options=["P0", "P1", "P2", "P3", "P4"],
            default=["P0", "P1", "P2", "P3", "P4"],
        )
    with controls[2]:
        selected_statuses = st.multiselect(
            "Status",
            options=["new", "existing", "current"],
            default=default_statuses,
        )
    with controls[3]:
        view_mode = st.selectbox("View", options=["Campaigns", "Raw Findings"])
    with controls[4]:
        text_filter = st.text_input("Search", value="")
    grouped_view = view_mode == "Campaigns"

    filtered_findings = [
        finding
        for finding in result.findings
        if finding_matches_filters(
            finding,
            severities=set(selected_severities),
            priorities=set(selected_priorities),
            baseline_statuses=set(selected_statuses),
        )
        and _matches_text_filter(finding, text_filter)
    ]
    if not filtered_findings:
        st.warning("No findings match the current filters.")
        return _filtered_result(result, filtered_findings)

    if grouped_view:
        groups = group_findings(filtered_findings)
        st.caption(f"Showing `{len(groups)}` grouped campaign(s) from `{len(filtered_findings)}` finding(s).")
        rows = build_findings_rows(groups, include_values=show_raw_values)
        findings_left, findings_right = st.columns([1.25, 1])
        with findings_left:
            st.dataframe(rows, use_container_width=True)
        with findings_right:
            selected_group = st.selectbox(
                "Drill-down group",
                options=[group.key for group in groups],
                format_func=lambda key: next(group.title for group in groups if group.key == key),
            )
            _render_group_detail(next(group for group in groups if group.key == selected_group), show_raw_values)
        report_result = _filtered_result(result, filtered_findings)
    else:
        st.caption(f"Showing `{len(filtered_findings)}` raw finding(s).")
        rows = _finding_rows(filtered_findings, include_values=show_raw_values)
        findings_left, findings_right = st.columns([1.25, 1])
        with findings_left:
            st.dataframe(rows, use_container_width=True)
        with findings_right:
            selected_finding = st.selectbox(
                "Drill-down finding",
                options=[finding.id for finding in filtered_findings],
                format_func=lambda finding_id: next(
                    f"{finding.severity.upper()} | {finding.type} | {finding.record_id}"
                    for finding in filtered_findings
                    if finding.id == finding_id
                ),
            )
            _render_finding_detail(
                next(finding for finding in filtered_findings if finding.id == selected_finding),
                show_raw_values,
            )
        report_result = _filtered_result(result, filtered_findings)
    return report_result


def _render_details_tab(result: ScanResult, *, show_raw_values: bool) -> None:
    _render_scan_details(result)
    with st.expander("Exposure Graph", expanded=False):
        _render_exposure_graph(result, show_raw_values=show_raw_values)
    with st.expander("Full Metadata", expanded=False):
        st.json(result.metadata)


def _render_exposure_graph(result: ScanResult, *, show_raw_values: bool) -> None:
    graph = build_exposure_graph(result.findings, include_values=show_raw_values)
    graph_meta = graph.metadata
    graph_cols = st.columns(4)
    graph_cols[0].metric("Nodes", graph_meta.get("nodes", 0))
    graph_cols[1].metric("Edges", graph_meta.get("edges", 0))
    graph_cols[2].metric("Repeated Entities", graph_meta.get("repeated_entities", 0))
    graph_cols[3].metric("Findings Visualized", graph_meta.get("findings_visualized", 0))
    if hasattr(st, "graphviz_chart"):
        st.graphviz_chart(graph.to_graphviz(), use_container_width=True)
    else:
        st.markdown("```dot\n%s\n```" % graph.to_graphviz())
    with st.expander("Graph JSON", expanded=False):
        st.json(graph.to_dict())


def _render_reports(result: ScanResult, unsafe_show_values: bool, include_values_in_graph: bool = False) -> None:
    st.subheader("Reports")
    st.caption("Downloads reflect the current findings filters and keep values obfuscated unless unsafe mode is enabled.")
    export_left, export_right, export_bottom = st.columns(3)
    with export_left:
        st.download_button(
            "Download HTML Audit Report",
            data=_build_export_data("html", result, unsafe_show_values),
            file_name="audit-report.html",
            mime="text/html",
        )
        st.download_button(
            "Download Markdown",
            data=_build_export_data("md", result, unsafe_show_values),
            file_name="findings.md",
        )
        st.download_button(
            "Download Baseline JSON",
            data=_build_baseline_data(result),
            file_name="baseline.json",
            mime="application/json",
        )
        st.download_button(
            "Download Hunt Artifact",
            data=_build_hunt_data(result),
            file_name="hunt-artifact.json",
            mime="application/json",
        )
    with export_right:
        st.download_button(
            "Download JSON",
            data=_build_export_data("json", result, unsafe_show_values),
            file_name="findings.json",
            mime="application/json",
        )
        st.download_button(
            "Download CSV",
            data=_build_export_data("csv", result, unsafe_show_values),
            file_name="findings.csv",
        )
    with export_bottom:
        st.download_button(
            "Download SARIF",
            data=_build_export_data("sarif", result, unsafe_show_values),
            file_name="findings.sarif",
            mime="application/json",
        )
        st.download_button(
            "Download Evidence Pack",
            data=_build_export_data("evidence", result, unsafe_show_values),
            file_name="evidence.zip",
            mime="application/zip",
        )
        st.download_button(
            "Download Exposure Graph JSON",
            data=_build_export_data("graph", result, include_values_in_graph and unsafe_show_values),
            file_name="exposure-graph.json",
            mime="application/json",
        )


def _render_group_detail(group, show_raw_values: bool) -> None:
    st.markdown(f"#### {group.title}")
    st.write(f"Occurrences: `{group.count}` | Priority: `{group.priority}` | Severity: `{group.severity}`")
    st.write(f"Entities: `{', '.join(group.entity_types)}`")
    st.write(f"Sources: `{', '.join(group.sources)}`")
    if group.first_seen or group.last_seen:
        st.write(f"Timeline: `{group.first_seen or 'unknown'}` -> `{group.last_seen or 'unknown'}`")
    sample_finding = group.findings[0] if group.findings else None
    if sample_finding:
        cluster = sample_finding.context.get("cluster", {})
        if isinstance(cluster, dict):
            validation = cluster.get("validation", [])
            if validation:
                st.markdown("#### Cluster Validation")
                st.json(validation)
    preview = group.raw_preview if show_raw_values and group.raw_preview else group.preview
    st.write(preview or "Preview unavailable.")
    for finding in group.findings:
        with st.expander(f"{finding.severity.upper()} - {finding.type} - {finding.record_id}"):
            _render_finding_detail(finding, show_raw_values)


def _render_finding_detail(finding: Finding, show_raw_values: bool) -> None:
    st.write(finding.safe_summary)
    asset_summary = finding.context.get("asset_summary")
    if asset_summary:
        st.write(f"Asset: `{asset_summary}`")
    if finding.context.get("record_timestamp"):
        st.write(f"Seen at: `{finding.context.get('record_timestamp')}`")
    if finding.context.get("timeline"):
        timeline = finding.context.get("timeline")
        st.markdown("#### Spread")
        st.json(timeline)
    if finding.context.get("validation"):
        st.markdown("#### Validation")
        st.json(finding.context.get("validation"))
    if show_raw_values:
        raw_values = [
            {
                "entity_type": entity.entity_type,
                "field_name": entity.field_name,
                "raw_value": entity.raw_value,
            }
            for entity in finding.entities
            if entity.raw_value
        ]
        if raw_values:
            st.markdown("#### Raw Matches")
            st.json(raw_values)
    st.json(finding.to_safe_dict(include_values=show_raw_values))


def _render_severity_cards(result: ScanResult) -> None:
    counts = result.severity_counts()
    markup = [
        '<div class="plh-card-grid">',
        _metric_card("Critical", counts.get("critical", 0), "critical"),
        _metric_card("High", counts.get("high", 0), "high"),
        _metric_card("Medium", counts.get("medium", 0), "medium"),
        _metric_card("Low", counts.get("low", 0), "low"),
        "</div>",
    ]
    st.markdown("".join(markup), unsafe_allow_html=True)


def _render_scan_details(result: ScanResult) -> None:
    st.subheader("Scan Details")
    metadata = result.metadata or {}
    provider_details = metadata.get("provider_details", {})
    if isinstance(provider_details, dict) and provider_details.get("partial"):
        st.warning("This is a partial Coralogix scan batch. Findings shown so far are real, and you can resume the remaining windows from the Remote Provider tab.")
    summary_left, summary_right = st.columns(2)
    with summary_left:
        st.write(f"Source: `{result.source}`")
        st.write(f"Records parsed: `{result.records_scanned}`")
        st.write(f"Findings: `{len(result.findings)}`")
    with summary_right:
        if metadata.get("provider"):
            st.write(f"Provider: `{metadata.get('provider')}`")
        if metadata.get("from") or metadata.get("to"):
            st.write(f"Window: `{metadata.get('from', '')}` -> `{metadata.get('to', '')}`")
        if metadata.get("query"):
            st.write(f"Requested filter: `{metadata.get('query')}`")
    if provider_details:
        st.markdown("#### Provider Response")
        st.json(provider_details)


def _render_diff_cards(diff) -> None:
    markup = [
        '<div class="plh-card-grid">',
        _metric_card("New", diff.new, "critical"),
        _metric_card("Unchanged", diff.unchanged, "neutral"),
        _metric_card("Resolved", diff.resolved, "low"),
        "</div>",
    ]
    st.markdown("".join(markup), unsafe_allow_html=True)


def _metric_card(label: str, value: int, tone: str) -> str:
    return (
        '<div class="plh-card plh-card-%s"><span class="plh-label">%s</span><strong class="plh-value">%s</strong></div>'
        % (tone, label, value)
    )


def _render_preset(preset_name: str) -> None:
    preset = get_preset(preset_name)
    if preset is None:
        st.warning("No preset found for that integration.")
        return
    st.markdown(
        (
            f"**{preset.title}**  \n"
            f"Minimum access: {preset.minimum_access}  \n"
            f"Required scopes: {', '.join(preset.required_scopes)}"
        )
    )
    for note in preset.notes:
        st.write(f"- {note}")


def _filtered_result(result: ScanResult, findings: list[Finding]) -> ScanResult:
    return ScanResult(
        findings=list(findings),
        records_scanned=result.records_scanned,
        source=result.source,
        metadata=dict(result.metadata),
    )


def _dedupe_log_records(records):
    seen: set[tuple[str, str]] = set()
    deduped = []
    for record in records:
        key = (record.timestamp, record.message)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)
    return deduped


def _asset_rows(result: ScanResult, limit: int = 8) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    seen_assets: set[tuple[str, str, str]] = set()
    for finding in result.findings:
        asset = str(finding.context.get("asset_summary", "unknown"))
        priority = str(finding.context.get("exploitability_priority", "P4"))
        key = (asset, priority, finding.source)
        if key in seen_assets:
            continue
        seen_assets.add(key)
        rows.append({"asset": asset, "priority": priority, "source": finding.source})
        if len(rows) >= limit:
            break
    return rows


def _finding_rows(findings: list[Finding], *, include_values: bool = False) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for finding in findings:
        entity = finding.entities[0] if finding.entities else None
        rows.append(
            {
                "severity": finding.severity,
                "priority": finding.context.get("exploitability_priority", ""),
                "type": finding.type,
                "record_id": finding.record_id,
                "entity": entity.entity_type if entity else "",
                "baseline": finding.context.get("hunt_status", finding.context.get("baseline_status", "current")),
                "preview": (
                    entity.raw_value
                    if include_values and entity and entity.raw_value
                    else entity.masked_preview if entity else ""
                ),
            }
        )
    return rows


def _matches_text_filter(finding: Finding, query: str) -> bool:
    needle = query.strip().lower()
    if not needle:
        return True
    haystack = " ".join(
        [
            finding.type,
            finding.record_id,
            finding.safe_summary,
            str(finding.context.get("asset_summary", "")),
            str(finding.context.get("cluster_id", "")),
            " ".join(entity.entity_type for entity in finding.entities),
            " ".join(entity.masked_preview for entity in finding.entities),
        ]
    ).lower()
    return needle in haystack


def _build_export_data(kind: str, result: ScanResult, include_values: bool) -> str | bytes:
    if kind == "graph":
        graph = build_exposure_graph(result.findings, include_values=include_values)
        return json.dumps(graph.to_dict(), indent=2)
    suffix = ".zip" if kind == "evidence" else f".{kind}"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
        temp_path = Path(handle.name)
    try:
        if kind == "html":
            write_html_report(result, str(temp_path), include_values=include_values)
            return temp_path.read_text(encoding="utf-8")
        if kind == "md":
            write_markdown(result, str(temp_path), include_values=include_values)
            return temp_path.read_text(encoding="utf-8")
        if kind == "json":
            write_json(result, str(temp_path), include_values=include_values)
            return temp_path.read_text(encoding="utf-8")
        if kind == "csv":
            write_csv(result, str(temp_path), include_values=include_values)
            return temp_path.read_text(encoding="utf-8")
        if kind == "sarif":
            write_sarif(result, str(temp_path), include_values=include_values)
            return temp_path.read_text(encoding="utf-8")
        if kind == "evidence":
            write_evidence_pack(result, str(temp_path), include_values=include_values)
            return temp_path.read_bytes()
        raise ValueError(f"Unsupported export kind: {kind}")
    finally:
        temp_path.unlink(missing_ok=True)


def _build_baseline_data(result: ScanResult) -> str:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
        temp_path = Path(handle.name)
    try:
        write_baseline(result, str(temp_path))
        return temp_path.read_text(encoding="utf-8")
    finally:
        temp_path.unlink(missing_ok=True)


def _build_hunt_data(result: ScanResult) -> str:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
        temp_path = Path(handle.name)
    try:
        write_hunt_artifact(result, str(temp_path))
        return temp_path.read_text(encoding="utf-8")
    finally:
        temp_path.unlink(missing_ok=True)


def _render_hero() -> None:
    st.markdown(
        f"""
        <div class="plh-hero">
          <p class="plh-kicker">PII Leak Hunter</p>
          <h1>Scan internal systems for secrets, PII, and risky exposure patterns.</h1>
          <p class="plh-copy">Pick a provider or platform, add session-only credentials, run a read-only scan, review grouped campaigns, and export an audit report. Keep it simple unless you need the deeper details.</p>
          <div class="plh-meta">
            <span>v{__version__}</span>
            <span>{DIFF_SIGNATURE_FAMILY_COUNT} diff signature families</span>
            <a href="{REPO_URL}" target="_blank" rel="noreferrer">Repository</a>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _inject_styles() -> None:
    st.markdown(
        """
        <style>
          .stApp {
            background: radial-gradient(circle at top left, rgba(190, 91, 54, 0.08), transparent 28%), #f5f1ea;
            color: #181512;
          }
          .block-container {
            padding-top: 1.6rem;
            padding-bottom: 4rem;
            max-width: 1280px;
          }
          .plh-hero {
            padding: 1.75rem 1.9rem;
            border: 1px solid rgba(190, 91, 54, 0.18);
            background: linear-gradient(180deg, rgba(255,255,255,0.94), rgba(255,248,239,0.94));
            border-radius: 24px;
            box-shadow: 0 20px 40px rgba(23, 20, 17, 0.08);
            margin-bottom: 1.2rem;
          }
          .plh-kicker {
            margin: 0 0 0.35rem;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            font-size: 0.82rem;
            color: #8d5038;
            font-weight: 700;
          }
          .plh-hero h1 {
            margin: 0;
            font-size: 2.35rem;
            line-height: 1.08;
            text-wrap: balance;
          }
          .plh-copy {
            margin-top: 0.8rem;
            max-width: 58rem;
            color: #5f554e;
            font-size: 1rem;
          }
          .plh-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 0.65rem;
            margin-top: 0.95rem;
          }
          .plh-meta span,
          .plh-meta a {
            display: inline-flex;
            align-items: center;
            padding: 0.42rem 0.72rem;
            border-radius: 999px;
            background: rgba(190, 91, 54, 0.1);
            border: 1px solid rgba(190, 91, 54, 0.16);
            color: #6f402d;
            text-decoration: none;
            font-size: 0.92rem;
            font-weight: 600;
          }
          .plh-card-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 0.9rem;
            margin-bottom: 1rem;
          }
          .plh-card {
            border-radius: 20px;
            padding: 1rem 1.1rem;
            background: rgba(255,255,255,0.92);
            border: 1px solid #dfd4c7;
            box-shadow: 0 12px 28px rgba(23, 20, 17, 0.05);
          }
          .plh-card-critical { border-color: rgba(157, 43, 21, 0.28); }
          .plh-card-high { border-color: rgba(193, 85, 28, 0.28); }
          .plh-card-medium { border-color: rgba(196, 138, 24, 0.28); }
          .plh-card-low { border-color: rgba(42, 126, 84, 0.28); }
          .plh-card-neutral { border-color: rgba(95, 85, 78, 0.18); }
          .plh-label {
            display: block;
            font-size: 0.78rem;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: #6d645c;
            margin-bottom: 0.35rem;
          }
          .plh-value {
            font-size: 2rem;
            line-height: 1;
            font-variant-numeric: tabular-nums;
          }
          .stButton > button, .stDownloadButton > button {
            border-radius: 999px;
            border: 1px solid rgba(190, 91, 54, 0.18);
          }
          .stButton > button[kind="primary"] {
            background: #be5b36;
            color: #fff9f2;
          }
        </style>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    run_app()
