import importlib

from pii_leak_hunter.core.models import DetectionResult, Finding, ScanResult


def test_ui_render_smoke(monkeypatch) -> None:
    importorskip = importlib.import_module("pytest").importorskip
    importorskip("streamlit")
    app_module = importlib.import_module("pii_leak_hunter.ui.app")

    calls: list[str] = []

    class FakeColumn:
        def metric(self, label, value):
            calls.append(f"metric:{label}:{value}")

    class FakeExpander:
        def __enter__(self):
            calls.append("expander")
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    class FakeStreamlit:
        def columns(self, count):
            return [FakeColumn() for _ in range(count)]

        def multiselect(self, *args, **kwargs):
            return ["critical", "high", "medium", "low"]

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
                context={},
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
