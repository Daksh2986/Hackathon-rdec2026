from __future__ import annotations

import json
from dataclasses import asdict
from html import escape
from pathlib import Path
from typing import Any

from .models import AuditReport


def _markdown(value: Any) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    for character in ("\\", "`", "*", "_", "{", "}", "[", "]", "<", ">", "|"):
        text = text.replace(character, f"\\{character}")
    return text


def render_markdown(report: AuditReport) -> str:
    lines = [
        "# Repository Security Audit",
        "",
        f"- **Run ID:** `{report.run_id}`",
        f"- **Target:** `{_markdown(report.target)}`",
        f"- **Revision:** `{report.revision or 'unknown'}`",
        f"- **Created:** `{report.created_at}`",
        f"- **Run status:** **{report.status.upper()}**",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "|---|---:|",
    ]
    for key, value in report.summary.items():
        lines.append(f"| {_markdown(key.replace('_', ' ').title())} | {value} |")

    lines.extend(["", "## Analyzer status", ""])
    for analyzer in report.analyzers:
        lines.append(
            f"- **{_markdown(analyzer.name)} — {analyzer.status.upper()}:** "
            f"{_markdown(analyzer.message)}"
        )

    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.append("No findings were reported by the enabled checks. This is not proof that the target is secure.")
    for finding in report.findings:
        lines.extend(
            [
                f"### [{finding.severity.upper()}] {_markdown(finding.title)}",
                "",
                f"- **ID:** `{finding.id}`",
                f"- **Rule:** `{finding.rule_id}`",
                f"- **Category:** {_markdown(finding.category)}",
                f"- **Evidence status:** **{finding.status.upper()}**",
                f"- **Heuristic confidence:** {finding.confidence:.2f}",
                f"- **Description:** {_markdown(finding.description)}",
                "",
                "**Locations**",
            ]
        )
        for location in finding.locations:
            line = f":{location['line']}" if location.get("line") is not None else ""
            lines.append(
                f"- `{_markdown(location.get('path', 'unknown'))}{line}` "
                f"({_markdown(location.get('role', 'evidence'))})"
            )
        lines.extend(["", "**Evidence**"])
        lines.extend(f"- {_markdown(item)}" for item in finding.evidence)
        lines.extend(["", f"**Remediation:** {_markdown(finding.remediation)}"])
        if finding.dependency:
            package = finding.dependency
            lines.extend(
                [
                    "",
                    "**Dependency**",
                    f"- `{_markdown(package['ecosystem'])}:{_markdown(package['name'])}@{_markdown(package['version'])}`",
                    f"- Direct dependency: `{package['direct']}`",
                    f"- Manifest: `{_markdown(package['manifest'])}`",
                    f"- Fixed versions: `{_markdown(', '.join(package['fixed_versions']) or 'not supplied')}`",
                ]
            )
        if finding.references:
            lines.extend(["", "**References**"])
            lines.extend(f"- <{escape(url, quote=True)}>" for url in finding.references)
        lines.append("")

    lines.extend(["## Warnings and coverage limitations", ""])
    if report.warnings:
        lines.extend(f"- {_markdown(warning)}" for warning in report.warnings)
    else:
        lines.append("No inventory, parsing, or advisory lookup warnings were reported.")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "Dependency findings marked confirmed reflect an exact-version OSV response. Source findings are "
            "suspected syntax-based paths, not proof of exploitability. A clean or partial report does not "
            "establish that the repository is secure; review the listed coverage and limitations.",
            "",
        ]
    )
    return "\n".join(lines)


def render_sarif(report: AuditReport) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}
    level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    for finding in report.findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
            },
        )
        locations = []
        for location in finding.locations:
            physical_location: dict[str, Any] = {
                "artifactLocation": {"uri": str(location["path"]).replace("\\", "/")}
            }
            if location.get("line") is not None:
                physical_location["region"] = {"startLine": location["line"]}
            locations.append({"physicalLocation": physical_location})
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": level_map.get(finding.severity, "note"),
                "message": {"text": finding.description},
                "locations": locations,
                "partialFingerprints": {"primaryLocationLineHash": finding.id},
                "properties": {
                    "findingId": finding.id,
                    "category": finding.category,
                    "evidenceStatus": finding.status,
                    "confidence": finding.confidence,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                },
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PS05 Repository Auditor",
                        "version": report.tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "runId": report.run_id,
                    "target": report.target,
                    "revision": report.revision,
                    "status": report.status,
                },
            }
        ],
    }


def write_reports(report: AuditReport, output: Path, formats: set[str]) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if "json" in formats:
        destination = output / "report.json"
        destination.write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        written.append(destination)
    if "markdown" in formats:
        destination = output / "report.md"
        destination.write_text(render_markdown(report), encoding="utf-8")
        written.append(destination)
    if "sarif" in formats:
        destination = output / "report.sarif.json"
        destination.write_text(
            json.dumps(render_sarif(report), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        written.append(destination)

    graph_path = output / "graph.json"
    graph_path.write_text(
        json.dumps(
            {
                "nodes": [asdict(item) for item in report.graph_nodes],
                "edges": [asdict(item) for item in report.graph_edges],
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    written.append(graph_path)
    return written
