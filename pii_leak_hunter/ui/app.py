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

from pii_leak_hunter.core.baseline import apply_baseline_payload, write_baseline
from pii_leak_hunter.core.models import Finding, ScanResult
from pii_leak_hunter.core.pipeline import Pipeline
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
    top_entity_families,
)
from pii_leak_hunter.utils.config import ConfigurationError

try:
    import streamlit as st
except Exception as exc:  # pragma: no cover - import depends on runtime env
    raise RuntimeError("Streamlit is required to run the UI.") from exc


def run_app() -> None:
    st.set_page_config(page_title="PII Leak Hunter", layout="wide")
    _inject_styles()
    _initialize_state()
    _render_hero()

    show_raw_values, export_raw_values = _render_sidebar()

    top_left, top_right = st.columns([1.6, 1])
    with top_left:
        st.subheader("Scan Console")
        st.caption(
            "Choose a source, configure access in-session, run a read-only scan, and export safe reports without dropping into the CLI."
        )
    with top_right:
        baseline_upload = st.file_uploader(
            "Optional baseline artifact",
            type=["json", "zip"],
            key="baseline-uploader",
            help="Upload a prior safe scan JSON, baseline JSON, or evidence pack zip to compare new vs unchanged findings.",
        )

    remote_tab, target_tab, upload_tab, guide_tab = st.tabs(
        ["Remote Provider", "Target / URI", "Upload File", "Least Privilege"]
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
        _render_result(result, show_raw_values=show_raw_values, export_raw_values=export_raw_values)
    else:
        st.info("Run a scan to unlock the overview, grouped findings, audit report, and evidence exports.")


def _initialize_state() -> None:
    st.session_state.setdefault("scan_result", None)
    st.session_state.setdefault("scan_history", [])


def _render_sidebar() -> tuple[bool, bool]:
    sidebar = st.sidebar
    sidebar.subheader("Session")
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
    result = st.session_state.get("scan_result")
    if isinstance(result, ScanResult):
        sidebar.markdown("#### Active Scan")
        sidebar.write(f"Source: `{result.source}`")
        sidebar.write(f"Records: `{result.records_scanned}`")
        sidebar.write(f"Findings: `{len(result.findings)}`")
    history = st.session_state.get("scan_history", [])
    if history:
        sidebar.markdown("#### Recent Runs")
        sidebar.dataframe(history[:8], use_container_width=True, hide_index=True)
    sidebar.caption("Credentials entered here stay in the current Streamlit session only.")
    return show_raw_values, export_raw_values


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
                runner=lambda: _run_remote_provider_scan(provider_name, resolved_query, resolved_start, end),
            )
    with right:
        st.markdown("#### Connection Details")
        st.caption("These values are used for the current session scan and do not need to be exported as shell env vars first.")
        _render_provider_credentials(provider_name)


def _render_target_tab(baseline_upload) -> None:
    left, right = st.columns([1.15, 1])
    with left:
        target_mode = st.selectbox(
            "Target Type",
            options=["Local path", "Raw target", "Postgres", "S3", "ServiceNow", "Notion"],
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
                    runner=lambda: _run_target_scan(target),
                )
    with right:
        st.markdown("#### Builder Notes")
        st.write("- `Local path` scans files or directories that already exist on the host running Streamlit.")
        st.write("- `Raw target` accepts a full path or URI such as `postgres://...`, `s3://...`, `servicenow://...`, or `notion://...`.")
        st.write("- `ServiceNow` and `Notion` builders include in-session auth so you do not need to preconfigure shell env vars.")
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
            runner=lambda: _scan_uploaded_file(uploaded),
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
            placeholder="postgres://... | s3://... | servicenow://... | notion://...",
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
    try:
        status.markdown(f"**{label}**: validating configuration")
        progress.progress(10)
        with _temporary_environment(env_overrides):
            status.markdown(f"**{label}**: connecting and loading records")
            progress.progress(35)
            result = runner()
        status.markdown(f"**{label}**: loaded `{result.records_scanned}` record(s), analyzing findings")
        progress.progress(60)
        status.markdown(f"**{label}**: analyzing records")
        progress.progress(75)
        result = _apply_uploaded_baseline(result, baseline_upload)
        progress.progress(92)
        st.session_state["scan_result"] = result
        _remember_scan(result)
        progress.progress(100)
        status.markdown(f"**{label}**: complete")
        if result.records_scanned == 0:
            st.warning(f"Scan completed but {result.source} returned 0 parsed record(s). Check Scan Details below for the exact query and provider response summary.")
        else:
            st.success(f"Scanned {result.records_scanned} record(s) from {result.source}.")
    except ConfigurationError as exc:
        st.error(str(exc))
    except Exception as exc:
        st.error(f"Scan failed: {exc}")


def _run_remote_provider_scan(provider_name: str, query: str, start: str, end: str) -> ScanResult:
    provider = build_provider(provider_name)
    records = provider.fetch(query=query, start=start, end=end)
    provider_details = getattr(provider, "last_fetch_details", {})
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
    )


def _run_target_scan(target: str) -> ScanResult:
    loaded = build_source(target).load()
    return Pipeline().run(loaded.records, source=loaded.source, metadata=loaded.metadata)


def _scan_uploaded_file(uploaded) -> ScanResult:
    suffix = Path(uploaded.name).suffix or ".ndjson"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
        handle.write(uploaded.getvalue())
        temp_path = handle.name
    records = load_file(temp_path)
    return Pipeline().run(records, source=uploaded.name, metadata={"mode": "file"})


def _apply_uploaded_baseline(result: ScanResult, uploaded) -> ScanResult:
    if uploaded is None:
        return result
    payload = _load_baseline_payload(uploaded)
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


def _render_result(result: ScanResult, show_raw_values: bool = True, export_raw_values: bool = False) -> None:
    _render_scan_details(result)
    st.subheader("Overview")
    meta_col, action_col = st.columns([1.25, 1])
    with meta_col:
        st.caption(f"Source: `{result.source}` | Records scanned: `{result.records_scanned}` | Findings: `{len(result.findings)}`")
    with action_col:
        baseline_path = _write_temp_baseline(result)
        st.download_button(
            "Download Baseline Artifact",
            data=baseline_path.read_text(encoding="utf-8"),
            file_name="baseline.json",
            mime="application/json",
        )
    _render_severity_cards(result)
    diff = build_diff_summary(result)
    if diff.active:
        _render_diff_cards(diff)

    overview_left, overview_right = st.columns(2)
    with overview_left:
        st.markdown("#### Exploitability Ladder")
        ladder_rows = [
            {"priority": priority, "count": count}
            for priority, count in exploitability_counts(result.findings)
        ]
        st.dataframe(ladder_rows or [{"priority": "P4", "count": 0}], use_container_width=True)
        st.markdown("#### Source Metadata")
        st.json(result.metadata)
    with overview_right:
        st.markdown("#### Top Entity Families")
        entity_rows = [
            {"entity": entity, "count": count}
            for entity, count in top_entity_families(result.findings)
        ]
        st.dataframe(entity_rows or [{"entity": "None", "count": 0}], use_container_width=True)
        if diff.active:
            st.markdown("#### Baseline Status")
            st.write(f"New: `{diff.new}` | Unchanged: `{diff.unchanged}` | Resolved: `{diff.resolved}`")

    st.subheader("Findings")
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
            "Baseline status",
            options=["new", "existing", "current"],
            default=default_statuses,
        )
    with controls[3]:
        grouped_view = st.checkbox("Grouped View", value=True)
    with controls[4]:
        text_filter = st.text_input("Search", value="")

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
        report_result = _filtered_result(result, filtered_findings)
        _render_reports(report_result, unsafe_show_values=export_raw_values)
        return

    if grouped_view:
        groups = group_findings(filtered_findings)
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

    _render_reports(report_result, unsafe_show_values=export_raw_values)


def _render_reports(result: ScanResult, unsafe_show_values: bool) -> None:
    st.subheader("Reports")
    st.caption("Downloads reflect the current findings filters and keep values obfuscated unless unsafe mode is enabled.")
    export_left, export_right, export_bottom = st.columns(3)
    html_path = _write_temp_export("html", result, unsafe_show_values)
    json_path = _write_temp_export("json", result, unsafe_show_values)
    md_path = _write_temp_export("md", result, unsafe_show_values)
    csv_path = _write_temp_export("csv", result, unsafe_show_values)
    sarif_path = _write_temp_export("sarif", result, unsafe_show_values)
    evidence_path = _write_temp_export("evidence", result, unsafe_show_values)
    baseline_path = _write_temp_baseline(result)
    with export_left:
        st.download_button(
            "Download HTML Audit Report",
            data=html_path.read_text(encoding="utf-8"),
            file_name="audit-report.html",
            mime="text/html",
        )
        st.download_button(
            "Download Markdown",
            data=md_path.read_text(encoding="utf-8"),
            file_name="findings.md",
        )
        st.download_button(
            "Download Baseline JSON",
            data=baseline_path.read_text(encoding="utf-8"),
            file_name="baseline.json",
            mime="application/json",
        )
    with export_right:
        st.download_button(
            "Download JSON",
            data=json_path.read_text(encoding="utf-8"),
            file_name="findings.json",
            mime="application/json",
        )
        st.download_button(
            "Download CSV",
            data=csv_path.read_text(encoding="utf-8"),
            file_name="findings.csv",
        )
    with export_bottom:
        st.download_button(
            "Download SARIF",
            data=sarif_path.read_text(encoding="utf-8"),
            file_name="findings.sarif",
            mime="application/json",
        )
        st.download_button(
            "Download Evidence Pack",
            data=evidence_path.read_bytes(),
            file_name="evidence.zip",
            mime="application/zip",
        )


def _render_group_detail(group, show_raw_values: bool) -> None:
    st.markdown(f"#### {group.title}")
    st.write(f"Occurrences: `{group.count}` | Priority: `{group.priority}` | Severity: `{group.severity}`")
    st.write(f"Entities: `{', '.join(group.entity_types)}`")
    preview = group.raw_preview if show_raw_values and group.raw_preview else group.preview
    st.write(preview or "Preview unavailable.")
    for finding in group.findings:
        with st.expander(f"{finding.severity.upper()} - {finding.type} - {finding.record_id}"):
            _render_finding_detail(finding, show_raw_values)


def _render_finding_detail(finding: Finding, show_raw_values: bool) -> None:
    st.write(finding.safe_summary)
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
                "baseline": finding.context.get("baseline_status", "current"),
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
            " ".join(entity.entity_type for entity in finding.entities),
            " ".join(entity.masked_preview for entity in finding.entities),
        ]
    ).lower()
    return needle in haystack


def _write_temp_export(kind: str, result: ScanResult, include_values: bool) -> Path:
    suffix = ".zip" if kind == "evidence" else f".{kind}"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
        temp_path = Path(handle.name)
    if kind == "html":
        write_html_report(result, str(temp_path), include_values=include_values)
    elif kind == "md":
        write_markdown(result, str(temp_path), include_values=include_values)
    elif kind == "json":
        write_json(result, str(temp_path), include_values=include_values)
    elif kind == "csv":
        write_csv(result, str(temp_path), include_values=include_values)
    elif kind == "sarif":
        write_sarif(result, str(temp_path), include_values=include_values)
    elif kind == "evidence":
        write_evidence_pack(result, str(temp_path), include_values=include_values)
    else:
        raise ValueError(f"Unsupported export kind: {kind}")
    return temp_path


def _write_temp_baseline(result: ScanResult) -> Path:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
        temp_path = Path(handle.name)
    write_baseline(result, str(temp_path))
    return temp_path


def _render_hero() -> None:
    st.markdown(
        """
        <div class="plh-hero">
          <p class="plh-kicker">PII Leak Hunter</p>
          <h1>Operator-grade leak hunting with actual scan controls, not just a thin demo shell.</h1>
          <p class="plh-copy">Configure providers in-session, scan remote platforms or URI targets, watch scan progress, compare against baselines, and export a polished audit report without exposing raw secrets by default.</p>
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
