from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import re
from typing import Any
from uuid import uuid4


def finding_id(category: str, rule_id: str, identity: str) -> str:
    digest = sha256(f"{category}:{rule_id}:{identity}".encode("utf-8")).hexdigest()
    return f"{category}-{digest[:12]}"


@dataclass(slots=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    manifest: str
    direct: bool | None
    locator: str

    @property
    def key(self) -> str:
        normalized_name = re.sub(r"[-_.]+", "-", self.name).lower()
        return f"{self.ecosystem.lower()}:{normalized_name}@{self.version}"


@dataclass(slots=True)
class GraphNode:
    id: str
    kind: str
    label: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class GraphEdge:
    source: str
    target: str
    kind: str
    path: str | None = None
    line: int | None = None


@dataclass(slots=True)
class Finding:
    id: str
    rule_id: str
    category: str
    title: str
    description: str
    severity: str
    status: str
    confidence: float
    locations: list[dict[str, Any]]
    evidence: list[str]
    remediation: str
    references: list[str] = field(default_factory=list)
    dependency: dict[str, Any] | None = None


@dataclass(slots=True)
class AnalyzerStatus:
    name: str
    status: str
    message: str
    analyzed: int = 0


@dataclass(slots=True)
class AuditReport:
    target: str
    revision: str | None
    created_at: str
    status: str
    findings: list[Finding]
    analyzers: list[AnalyzerStatus]
    warnings: list[str]
    summary: dict[str, int]
    graph_nodes: list[GraphNode]
    graph_edges: list[GraphEdge]
    run_id: str = field(default_factory=lambda: str(uuid4()))
    schema_version: str = "1.0"
    tool_version: str = "0.1.0"

    @classmethod
    def create(
        cls,
        target: str,
        revision: str | None,
        findings: list[Finding],
        analyzers: list[AnalyzerStatus],
        warnings: list[str],
        summary: dict[str, int],
        graph_nodes: list[GraphNode],
        graph_edges: list[GraphEdge],
    ) -> AuditReport:
        status = "partial" if any(item.status == "incomplete" for item in analyzers) else "complete"
        return cls(
            target=target,
            revision=revision,
            created_at=datetime.now(timezone.utc).isoformat(),
            status=status,
            findings=findings,
            analyzers=analyzers,
            warnings=warnings,
            summary=summary,
            graph_nodes=graph_nodes,
            graph_edges=graph_edges,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "unknown": 4,
}
