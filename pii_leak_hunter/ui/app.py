from __future__ import annotations

import json
import tempfile
from pathlib import Path

from pii_leak_hunter.core.models import ScanResult
from pii_leak_hunter.core.pipeline import Pipeline
from pii_leak_hunter.loader.file_loader import load_file
from pii_leak_hunter.output.csv_writer import write_csv
from pii_leak_hunter.output.json_writer import write_json
from pii_leak_hunter.output.markdown_writer import write_markdown
from pii_leak_hunter.providers.coralogix import CoralogixProvider
from pii_leak_hunter.utils.config import ConfigurationError, CoralogixConfig

try:
    import streamlit as st
except Exception as exc:  # pragma: no cover - import depends on runtime env
    raise RuntimeError("Streamlit is required to run the UI.") from exc


def run_app() -> None:
    st.set_page_config(page_title="PII Leak Hunter", layout="wide")
    st.title("PII Leak Hunter")
    st.caption("Read-only log scanning for PII leaks, masking failures, and secret overlap.")

    source_mode = st.radio("Source", ["Local file", "Coralogix"], horizontal=True)
    unsafe_show_values = st.checkbox("Unsafe: show raw values", value=False)

    if source_mode == "Local file":
        uploaded = st.file_uploader("Upload .log, .json, or .ndjson", type=["log", "json", "ndjson"])
        if uploaded and st.button("Scan file", type="primary"):
            result = _scan_uploaded_file(uploaded)
            _render_result(result, unsafe_show_values=unsafe_show_values)
    else:
        query = st.text_input("Query", value='source:"mailer-service"')
        start = st.text_input("From", value="-24h")
        end = st.text_input("To", value="now")
        if st.button("Scan Coralogix", type="primary"):
            try:
                provider = CoralogixProvider(CoralogixConfig.from_env())
                records = provider.fetch(query=query, start=start, end=end)
                result = Pipeline().run(
                    records,
                    source="coralogix",
                    metadata={"mode": "coralogix", "query": query, "from": start, "to": end},
                )
                _render_result(result, unsafe_show_values=unsafe_show_values)
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


def _render_result(result: ScanResult, unsafe_show_values: bool = False) -> None:
    counts = result.severity_counts()
    columns = st.columns(4)
    for index, severity in enumerate(["critical", "high", "medium", "low"]):
        columns[index].metric(severity.title(), counts.get(severity, 0))

    if not result.findings:
        st.success("No findings detected.")
        return

    selected_severities = st.multiselect(
        "Severity filter",
        options=["critical", "high", "medium", "low"],
        default=["critical", "high", "medium", "low"],
    )
    filtered = [finding for finding in result.findings if finding.severity in selected_severities]
    rows = []
    for finding in filtered:
        entity = finding.entities[0] if finding.entities else None
        rows.append(
            {
                "severity": finding.severity,
                "type": finding.type,
                "record_id": finding.record_id,
                "entity_type": entity.entity_type if entity else "",
                "preview": entity.masked_preview if entity else "",
                "hash": entity.value_hash[:12] if entity else "",
            }
        )
    st.dataframe(rows, use_container_width=True)

    st.subheader("Drill-down")
    for finding in filtered:
        with st.expander(f"{finding.severity.upper()} - {finding.type} - {finding.record_id}"):
            st.write(finding.safe_summary)
            st.json(finding.to_safe_dict(include_values=unsafe_show_values))

    st.subheader("Export")
    st.download_button(
        "Download JSON",
        data=json.dumps(result.to_safe_dict(include_values=unsafe_show_values), indent=2),
        file_name="findings.json",
        mime="application/json",
    )
    markdown_path = _write_temp_export("md", result, unsafe_show_values)
    csv_path = _write_temp_export("csv", result, unsafe_show_values)
    st.download_button("Download Markdown", data=markdown_path.read_text(encoding="utf-8"), file_name="findings.md")
    st.download_button("Download CSV", data=csv_path.read_text(encoding="utf-8"), file_name="findings.csv")


def _write_temp_export(kind: str, result: ScanResult, include_values: bool) -> Path:
    with tempfile.NamedTemporaryFile(suffix=f".{kind}", delete=False) as handle:
        temp_path = Path(handle.name)
    if kind == "md":
        write_markdown(result, str(temp_path), include_values=include_values)
    elif kind == "json":
        write_json(result, str(temp_path), include_values=include_values)
    elif kind == "csv":
        write_csv(result, str(temp_path), include_values=include_values)
    else:
        raise ValueError(f"Unsupported export kind: {kind}")
    return temp_path


if __name__ == "__main__":
    run_app()
