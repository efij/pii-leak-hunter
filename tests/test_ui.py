import importlib

from pii_leak_hunter.core.models import DetectionResult, Finding, ScanResult


def test_ui_render_smoke(monkeypatch) -> None:
    importorskip = importlib.import_module("pytest").importorskip
    importorskip("streamlit")
    app_module = importlib.import_module("pii_leak_hunter.ui.app")

    calls: list[str] = []

    class FakeColumn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def metric(self, label, value):
            calls.append(f"metric:{label}:{value}")

    class FakeExpander:
        def __enter__(self):
            calls.append("expander")
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    class FakeSessionState(dict):
        pass

    class FakeStreamlit:
        session_state = FakeSessionState()

        def columns(self, count):
            if isinstance(count, int):
                size = count
            else:
                size = len(count)
            return [FakeColumn() for _ in range(size)]

        def multiselect(self, *args, **kwargs):
            if "Severity" in args:
                return ["critical", "high", "medium", "low"]
            if "Exploitability" in args:
                return ["P0", "P1", "P2", "P3", "P4"]
            return ["current"]

        def checkbox(self, *args, **kwargs):
            return kwargs.get("value", False)

        def selectbox(self, label, options, format_func=None, **kwargs):
            return options[0]

        def markdown(self, *args, **kwargs):
            calls.append("markdown")

        def caption(self, value):
            calls.append(f"caption:{value}")

        def dataframe(self, *args, **kwargs):
            calls.append("dataframe")

        def subheader(self, value):
            calls.append(f"subheader:{value}")

        def expander(self, value):
            calls.append(f"expander-title:{value}")
            return FakeExpander()

        def write(self, value):
            calls.append("write")

        def json(self, value):
            calls.append("json")

        def download_button(self, *args, **kwargs):
            calls.append("download")

        def success(self, value):
            calls.append("success")

        def warning(self, value):
            calls.append("warning")

        def info(self, value):
            calls.append("info")

    monkeypatch.setattr(app_module, "st", FakeStreamlit())
    result = ScanResult(
        findings=[
            Finding(
                id="f1",
                record_id="r1",
                type="entity_detection",
                severity="medium",
                entities=[
                    DetectionResult(
                        entity_type="EMAIL_ADDRESS",
                        start=0,
                        end=5,
                        score=0.8,
                        value_hash="abc123",
                        masked_preview="user=***",
                    )
                ],
                context={"exploitability_priority": "P2"},
                source="fixture",
                safe_summary="Email detected.",
            )
        ],
        records_scanned=1,
        source="fixture",
    )

    app_module._render_result(result)
    assert "dataframe" in calls
    assert "download" in calls
    assert "json" in calls
