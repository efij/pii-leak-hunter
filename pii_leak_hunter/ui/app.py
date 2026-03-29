from __future__ import annotations

import json
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path

from pii_leak_hunter.core.baseline import apply_baseline_payload
from pii_leak_hunter.core.models import Finding, ScanResult
from pii_leak_hunter.core.pipeline import Pipeline
from pii_leak_hunter.loader.file_loader import load_file
from pii_leak_hunter.output.csv_writer import write_csv
from pii_leak_hunter.output.evidence_pack import write_evidence_pack
from pii_leak_hunter.output.html_writer import write_html_report
from pii_leak_hunter.output.json_writer import write_json
from pii_leak_hunter.output.markdown_writer import write_markdown
from pii_leak_hunter.output.sarif_writer import write_sarif
from pii_leak_hunter.providers.factory import SUPPORTED_PROVIDERS, build_provider, normalize_provider_name
from pii_leak_hunter.security.least_privilege import PRESETS, get_preset
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
    _render_hero()

    st.subheader("Scan")
    st.caption("Run a read-only scan, optionally compare against a safe baseline, then export a shareable audit report.")
    unsafe_show_values = st.checkbox(
        "Unsafe: show raw values",
        value=False,
        help="Disabled by default so the UI and reports stay safe to share.",
    )
    baseline_upload = st.file_uploader(
        "Optional baseline artifact (.json or evidence .zip)",
        type=["json", "zip"],
        key="baseline-uploader",
        help="Upload a prior safe scan JSON, baseline JSON, or evidence pack zip to compare new vs unchanged findings.",
    )
    source_mode = st.radio("Source", ["Local file", "Remote provider"], horizontal=True)

    if source_mode == "Local file":
        _render_local_scan_controls(
            baseline_upload=baseline_upload,
            unsafe_show_values=unsafe_show_values,
        )
    else:
        _render_remote_scan_controls(
            baseline_upload=baseline_upload,
            unsafe_show_values=unsafe_show_values,
        )

    st.subheader("Least-Privilege Guide")
    preset_name = st.selectbox(
        "Integration preset",
        options=[""] + sorted(PRESETS),
        format_func=lambda value: "Select an integration" if not value else value,
    )
    if preset_name:
        _render_preset(preset_name)

    result = st.session_state.get("scan_result")
    if isinstance(result, ScanResult):
        _render_result(result, unsafe_show_values=unsafe_show_values)
    else:
        st.info("Run a scan to unlock the overview, grouped findings, and HTML audit report.")


def _render_local_scan_controls(*, baseline_upload, unsafe_show_values: bool) -> None:
    uploaded = st.file_uploader(
        "Upload .log, .json, .ndjson, .gz, .bz2, or .zip",
        type=["log", "json", "ndjson", "gz", "bz2", "zip"],
        key="scan-source-uploader",
    )
    if uploaded and st.button("Run Scan", type="primary", key="scan-local"):
        try:
            result = _scan_uploaded_file(uploaded)
            result = _apply_uploaded_baseline(result, baseline_upload)
            st.session_state["scan_result"] = result
            st.success(f"Scanned {result.records_scanned} record(s) from {result.source}.")
        except Exception as exc:
            st.error(f"Scan failed: {exc}")


def _render_remote_scan_controls(*, baseline_upload, unsafe_show_values: bool) -> None:
    provider_name = st.selectbox("Provider", options=list(SUPPORTED_PROVIDERS), index=0)
    query = st.text_input("Query", value=_default_query(provider_name))
    start = st.text_input("From", value="-24h")
    end = st.text_input("To", value="now")
    if st.button("Run Remote Scan", type="primary", key="scan-remote"):
        try:
            provider = build_provider(provider_name)
            records = provider.fetch(query=query, start=start, end=end)
            result = Pipeline().run(
                records,
                source=normalize_provider_name(provider_name),
                metadata={
                    "mode": "remote",
                    "provider": normalize_provider_name(provider_name),
                    "query": query,
                    "from": start,
                    "to": end,
                },
            )
            result = _apply_uploaded_baseline(result, baseline_upload)
            st.session_state["scan_result"] = result
            st.success(f"Scanned {result.records_scanned} record(s) from {result.source}.")
        except ConfigurationError as exc:
            st.error(str(exc))
        except Exception as exc:
            st.error(f"Scan failed: {exc}")


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


def _render_result(result: ScanResult, unsafe_show_values: bool = False) -> None:
    st.subheader("Overview")
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
        st.dataframe(ladder_rows, use_container_width=True)
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
            st.write(
                f"New: `{diff.new}` | Unchanged: `{diff.unchanged}` | Resolved: `{diff.resolved}`"
            )

    st.subheader("Findings")
    default_statuses = ["current"]
    if diff.active:
        default_statuses = ["new", "existing", "current"]
    controls = st.columns(4)
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

    filtered_findings = [
        finding
        for finding in result.findings
        if finding_matches_filters(
            finding,
            severities=set(selected_severities),
            priorities=set(selected_priorities),
            baseline_statuses=set(selected_statuses),
        )
    ]
    if not filtered_findings:
        st.warning("No findings match the current filters.")
        report_result = _filtered_result(result, filtered_findings)
        _render_reports(report_result, unsafe_show_values=unsafe_show_values)
        return

    if grouped_view:
        groups = group_findings(filtered_findings)
        rows = build_findings_rows(groups)
        findings_left, findings_right = st.columns([1.25, 1])
        with findings_left:
            st.dataframe(rows, use_container_width=True)
        with findings_right:
            selected_group = st.selectbox(
                "Drill-down group",
                options=[group.key for group in groups],
                format_func=lambda key: next(group.title for group in groups if group.key == key),
            )
            _render_group_detail(next(group for group in groups if group.key == selected_group), unsafe_show_values)
        report_result = _filtered_result(result, filtered_findings)
    else:
        rows = _finding_rows(filtered_findings)
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
                unsafe_show_values,
            )
        report_result = _filtered_result(result, filtered_findings)

    _render_reports(report_result, unsafe_show_values=unsafe_show_values)


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


def _render_group_detail(group, unsafe_show_values: bool) -> None:
    st.markdown(f"#### {group.title}")
    st.write(f"Occurrences: `{group.count}` | Priority: `{group.priority}` | Severity: `{group.severity}`")
    st.write(f"Entities: `{', '.join(group.entity_types)}`")
    st.write(group.preview or "Masked preview unavailable.")
    for finding in group.findings:
        with st.expander(f"{finding.severity.upper()} - {finding.type} - {finding.record_id}"):
            _render_finding_detail(finding, unsafe_show_values)


def _render_finding_detail(finding: Finding, unsafe_show_values: bool) -> None:
    st.write(finding.safe_summary)
    st.json(finding.to_safe_dict(include_values=unsafe_show_values))


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


def _finding_rows(findings: list[Finding]) -> list[dict[str, object]]:
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
                "preview": entity.masked_preview if entity else "",
            }
        )
    return rows


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


def _default_query(provider_name: str) -> str:
    defaults = {
        "coralogix": 'source:"mailer-service"',
        "datadog": "service:mailer-service",
        "dynatrace": 'contains(content, "mailer-service")',
        "splunk": 'index=main service="mailer-service"',
        "newrelic": "`service.name` = 'mailer-service'",
    }
    return defaults.get(normalize_provider_name(provider_name), "*")


def _render_hero() -> None:
    st.markdown(
        """
        <div class="plh-hero">
          <p class="plh-kicker">PII Leak Hunter</p>
          <h1>Read-only leak hunting with safer triage and cleaner reporting.</h1>
          <p class="plh-copy">Scan logs and operational data, compare against a baseline, then export a polished HTML audit report with masked evidence and exploitability context.</p>
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
            padding-top: 2rem;
            padding-bottom: 4rem;
            max-width: 1200px;
          }
          .plh-hero {
            padding: 1.75rem 1.9rem;
            border: 1px solid rgba(190, 91, 54, 0.18);
            background: linear-gradient(180deg, rgba(255,255,255,0.92), rgba(255,248,239,0.92));
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
            max-width: 52rem;
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
