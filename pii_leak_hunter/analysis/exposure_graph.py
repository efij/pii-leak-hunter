from __future__ import annotations

from dataclasses import dataclass

from pii_leak_hunter.core.models import Finding
from pii_leak_hunter.scoring.risk import SEVERITY_ORDER
from pii_leak_hunter.ui.presentation import PRIORITY_ORDER


@dataclass(slots=True, frozen=True)
class ExposureNode:
    node_id: str
    kind: str
    label: str
    tone: str = "neutral"


@dataclass(slots=True, frozen=True)
class ExposureEdge:
    source: str
    target: str
    label: str = ""


@dataclass(slots=True)
class ExposureGraph:
    nodes: list[ExposureNode]
    edges: list[ExposureEdge]
    metadata: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "metadata": self.metadata,
            "nodes": [
                {"node_id": node.node_id, "kind": node.kind, "label": node.label, "tone": node.tone}
                for node in self.nodes
            ],
            "edges": [
                {"source": edge.source, "target": edge.target, "label": edge.label}
                for edge in self.edges
            ],
        }

    def to_graphviz(self) -> str:
        lines = [
            "digraph ExposureGraph {",
            '  rankdir="LR";',
            '  graph [bgcolor="transparent", pad="0.2"];',
            '  node [shape="box", style="rounded,filled", fontname="Helvetica"];',
            '  edge [fontname="Helvetica", color="#8d8173"];',
        ]
        for node in self.nodes:
            fill = {
                "critical": "#f5c4b9",
                "high": "#f8d8b6",
                "medium": "#f3e4b5",
                "low": "#d7ebdd",
                "neutral": "#ede5da",
            }.get(node.tone, "#ede5da")
            label = node.label.replace('"', '\\"')
            lines.append(f'  "{node.node_id}" [label="{label}", fillcolor="{fill}"];')
        for edge in self.edges:
            if edge.label:
                label = edge.label.replace('"', '\\"')
                lines.append(f'  "{edge.source}" -> "{edge.target}" [label="{label}"];')
            else:
                lines.append(f'  "{edge.source}" -> "{edge.target}";')
        lines.append("}")
        return "\n".join(lines)


def build_exposure_graph(
    findings: list[Finding],
    *,
    include_values: bool = False,
    max_findings: int = 40,
) -> ExposureGraph:
    chosen_findings = sorted(findings, key=_finding_rank)[:max_findings]
    nodes: dict[str, ExposureNode] = {}
    edges: dict[tuple[str, str, str], ExposureEdge] = {}
    source_links = 0
    repeated_entities: set[str] = set()
    seen_entity_nodes: set[str] = set()

    for finding in chosen_findings:
        source_id = f"source:{finding.source}"
        record_id = f"record:{finding.record_id}"
        finding_id = f"finding:{finding.id}"
        nodes.setdefault(source_id, ExposureNode(source_id, "source", finding.source, "neutral"))
        nodes.setdefault(record_id, ExposureNode(record_id, "record", finding.record_id, "neutral"))
        nodes.setdefault(
            finding_id,
            ExposureNode(
                finding_id,
                "finding",
                f"{finding.type} ({finding.context.get('exploitability_priority', 'P4')})",
                finding.severity,
            ),
        )
        edges[(source_id, record_id, "contains")] = ExposureEdge(source_id, record_id, "contains")
        edges[(record_id, finding_id, "evidence")] = ExposureEdge(record_id, finding_id, "evidence")
        source_links += 1
        asset = finding.context.get("asset", {})
        if isinstance(asset, dict):
            for key in ("service", "project", "environment", "account", "cluster", "channel", "table"):
                value = asset.get(key)
                if not value:
                    continue
                asset_id = f"asset:{key}:{value}"
                nodes.setdefault(asset_id, ExposureNode(asset_id, "asset", f"{key}: {value}", "neutral"))
                edges[(record_id, asset_id, key)] = ExposureEdge(record_id, asset_id, key)
        for entity in finding.entities:
            entity_id = f"entity:{entity.entity_type}:{entity.value_hash}"
            if entity_id in seen_entity_nodes:
                repeated_entities.add(entity_id)
            seen_entity_nodes.add(entity_id)
            label_value = entity.raw_value if include_values and entity.raw_value else entity.masked_preview or entity.value_hash[:10]
            nodes.setdefault(
                entity_id,
                ExposureNode(entity_id, "entity", f"{entity.entity_type}: {label_value}", _entity_tone(finding.severity)),
            )
            edges[(finding_id, entity_id, "matches")] = ExposureEdge(finding_id, entity_id, "matches")

    return ExposureGraph(
        nodes=list(nodes.values()),
        edges=list(edges.values()),
        metadata={
            "findings_visualized": len(chosen_findings),
            "nodes": len(nodes),
            "edges": len(edges),
            "repeated_entities": len(repeated_entities),
            "source_links": source_links,
        },
    )


def _entity_tone(severity: str) -> str:
    return severity if severity in {"critical", "high", "medium", "low"} else "neutral"


def _finding_rank(finding: Finding) -> tuple[int, int, int]:
    severity_rank = SEVERITY_ORDER.get(finding.severity, -1)
    priority_rank = 10 - PRIORITY_ORDER.get(str(finding.context.get("exploitability_priority", "P4")), 9)
    entity_rank = len(finding.entities)
    return (-severity_rank, -priority_rank, -entity_rank)
