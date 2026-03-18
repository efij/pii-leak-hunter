from __future__ import annotations

from pii_leak_hunter.core.models import DetectionResult
from pii_leak_hunter.detection.custom_recognizers import iter_pattern_definitions
from pii_leak_hunter.detection.patterns import PATTERNS, looks_like_name
from pii_leak_hunter.detection.presidio_adapter import PresidioAdapter
from pii_leak_hunter.utils.hashing import HashingService
from pii_leak_hunter.utils.masking import masked_preview


class DetectionEngine:
    def __init__(self, hashing_service: HashingService | None = None) -> None:
        self.hashing_service = hashing_service or HashingService()
        self.presidio = PresidioAdapter()

    def detect(
        self,
        text: str,
        field_metadata: dict[str, str] | None = None,
    ) -> list[DetectionResult]:
        detections: list[DetectionResult] = []
        seen: set[tuple[str, int, int]] = set()

        for match in self.presidio.analyze(text):
            raw_value = text[match.start:match.end]
            key = (match.entity_type, match.start, match.end)
            if key in seen:
                continue
            detections.append(
                self._build_result(
                    entity_type=match.entity_type,
                    text=text,
                    start=match.start,
                    end=match.end,
                    score=match.score,
                    raw_value=raw_value,
                    detection_source="presidio",
                )
            )
            seen.add(key)

        for definition in iter_pattern_definitions():
            pattern = PATTERNS[definition.entity_type]
            for match in pattern.finditer(text):
                key = (definition.entity_type, match.start(), match.end())
                if key in seen:
                    continue
                raw_value = match.group(0)
                detections.append(
                    self._build_result(
                        entity_type=definition.entity_type,
                        text=text,
                        start=match.start(),
                        end=match.end(),
                        score=definition.score,
                        raw_value=raw_value,
                        detection_source="regex",
                    )
                )
                seen.add(key)

        detections.extend(self._detect_field_entities(field_metadata or {}, text, seen))
        return sorted(detections, key=lambda item: (item.start, item.end, item.entity_type))

    def _detect_field_entities(
        self,
        field_metadata: dict[str, str],
        text: str,
        seen: set[tuple[str, int, int]],
    ) -> list[DetectionResult]:
        detections: list[DetectionResult] = []
        for field_name, value in field_metadata.items():
            normalized_field = field_name.lower()
            if "name" in normalized_field and looks_like_name(value):
                start = text.find(value)
                if start == -1:
                    continue
                end = start + len(value)
                key = ("PERSON", start, end)
                if key in seen:
                    continue
                detections.append(
                    self._build_result(
                        entity_type="PERSON",
                        text=text,
                        start=start,
                        end=end,
                        score=0.7,
                        raw_value=value,
                        detection_source="field-heuristic",
                        field_name=field_name,
                    )
                )
                seen.add(key)
        return detections

    def _build_result(
        self,
        *,
        entity_type: str,
        text: str,
        start: int,
        end: int,
        score: float,
        raw_value: str,
        detection_source: str,
        field_name: str | None = None,
    ) -> DetectionResult:
        return DetectionResult(
            entity_type=entity_type,
            start=start,
            end=end,
            score=score,
            value_hash=self.hashing_service.hash_value(raw_value),
            masked_preview=masked_preview(text, start, end),
            raw_value=raw_value,
            field_name=field_name,
            detection_source=detection_source,
        )
