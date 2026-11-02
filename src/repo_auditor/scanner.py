from __future__ import annotations

from pathlib import Path

from .advisory_cache import DEFAULT_TTL_SECONDS, lookup_osv
from .dependencies import DependencyInventory, analyze_dependencies
from .inventory import build_inventory
from .models import (
    AnalyzerStatus,
    AuditReport,
    Finding,
    GraphEdge,
    GraphNode,
)
from .osv import AdvisoryError, findings_from_vulnerabilities
from .python_analysis import MAX_GRAPH_EDGES, analyze_python_file


def audit_repository(
    root: Path,
    target: str,
    revision: str | None,
    offline: bool = False,
    advisory_timeout: float = 10.0,
    max_files: int = 20_000,
    cache_path: Path | None = None,
    cache_ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> AuditReport:
    inventory = build_inventory(root, max_files=max_files)
    warnings = list(inventory.warnings)
    analyzers: list[AnalyzerStatus] = []
    findings: list[Finding] = []
    graph_nodes: list[GraphNode] = []
    graph_edges: list[GraphEdge] = []
    analyzers.append(
        AnalyzerStatus(
            name="repository_inventory",
            status="incomplete" if inventory.warnings else "complete",
            message=(
                f"Inventoried {len(inventory.files)} file(s), excluding "
                f"{inventory.excluded_count} by configured rules or limits."
            ),
            analyzed=len(inventory.files),
        )
    )
    dependencies: DependencyInventory = analyze_dependencies(root, inventory.manifest_files)
    warnings.extend(dependencies.warnings)
    graph_nodes.extend(dependencies.nodes)
    graph_edges.extend(dependencies.edges)
    dependency_status = "incomplete" if dependencies.warnings else "complete"
    analyzers.append(
        AnalyzerStatus(
            name="dependency_inventory",
            status=dependency_status,
            message=(
                f"Parsed {dependencies.manifests_analyzed} supported manifest(s) and "
                f"identified {len(dependencies.dependencies)} resolved package version(s)."
            ),
            analyzed=dependencies.manifests_analyzed,
        )
    )

    parse_errors = 0
    analysis_limit_warnings = 0
    python_analyzed = 0
    for path in inventory.source_files:
        file_findings, error, analysis_warning = analyze_python_file(root, path, graph_nodes, graph_edges)
        if error:
            warnings.append(error)
            parse_errors += 1
            continue
        if analysis_warning:
            warnings.append(analysis_warning)
            analysis_limit_warnings += 1
        python_analyzed += 1
        findings.extend(file_findings)
    graph_truncated = len(graph_nodes) >= MAX_GRAPH_EDGES or len(graph_edges) >= MAX_GRAPH_EDGES
    if graph_truncated:
        warnings.append(f"Code/dependency graph reached its {MAX_GRAPH_EDGES}-item resource limit.")
    analyzers.append(
        AnalyzerStatus(
            name="python_ast_and_taint",
            status="incomplete" if parse_errors or analysis_limit_warnings or graph_truncated else "complete",
            message=(
                f"Parsed {python_analyzed} Python file(s); {parse_errors} file(s) could not be parsed. "
                f"{analysis_limit_warnings} file(s) reached analysis limits. "
                "Analysis includes bounded same-file direct-call summaries and is limited to documented source/sink patterns."
                + (" Graph output was truncated by its resource limit." if graph_truncated else "")
            ),
            analyzed=python_analyzed,
        )
    )

    cache_hits = 0
    network_queries = 0
    missing_cached = 0
    stale_cached = 0
    if dependencies.dependencies:
        try:
            lookup = lookup_osv(
                dependencies.dependencies,
                cache_path=cache_path,
                offline=offline,
                timeout=advisory_timeout,
                ttl_seconds=cache_ttl_seconds,
            )
            vulnerability_map = lookup.vulnerabilities
            cache_hits = lookup.cache_hits
            network_queries = lookup.network_queries
            missing_cached = len(lookup.missing)
            stale_cached = lookup.stale_entries
            for dependency in dependencies.dependencies:
                findings.extend(
                    findings_from_vulnerabilities(
                        dependency,
                        vulnerability_map.get(dependency.key, []),
                    )
                )
            advisory_status = "incomplete" if missing_cached or stale_cached else "complete"
            advisory_message = (
                f"Checked {len(vulnerability_map)} package version(s): {cache_hits} cache hit(s), "
                f"{network_queries} OSV request item(s), {missing_cached} cache miss(es), "
                f"{stale_cached} stale cached result(s)."
            )
            if missing_cached:
                warnings.append(
                    f"OSV advisory results are unavailable for {missing_cached} package version(s); "
                    "no safety conclusion is available for those packages."
                )
            if stale_cached:
                warnings.append(
                    f"{stale_cached} stale OSV cache result(s) were used offline; advisory coverage may be outdated."
                )
        except AdvisoryError as error:
            warnings.append(str(error))
            advisory_status = "incomplete"
            advisory_message = "OSV lookup failed; dependency advisory coverage is incomplete."
    else:
        advisory_status = "complete"
        advisory_message = "No resolved package versions were available for advisory checks."
    analyzers.append(
        AnalyzerStatus(
            name="osv_advisories",
            status=advisory_status,
            message=advisory_message,
            analyzed=len(dependencies.dependencies) - missing_cached,
        )
    )

    findings = list({finding.id: finding for finding in findings}.values())
    findings.sort(
        key=lambda item: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}.get(
                item.severity, 5
            ),
            item.locations[0].get("path", "") if item.locations else "",
            item.locations[0].get("line") or 0 if item.locations else 0,
            item.id,
        )
    )
    graph_nodes = list({node.id: node for node in graph_nodes}.values())
    graph_edges = list(
        {
            (edge.source, edge.target, edge.kind, edge.path, edge.line): edge
            for edge in graph_edges
        }.values()
    )
    summary = {
        "files_discovered": len(inventory.files),
        "files_excluded": inventory.excluded_count,
        "python_files_discovered": len(inventory.source_files),
        "python_files_analyzed": python_analyzed,
        "manifests_discovered": len(inventory.manifest_files),
        "manifests_analyzed": dependencies.manifests_analyzed,
        "dependencies_resolved": len(dependencies.dependencies),
        "osv_cache_hits": cache_hits,
        "osv_network_queries": network_queries,
        "osv_cache_missing": missing_cached,
        "osv_cache_stale": stale_cached,
        "findings": len(findings),
        "confirmed_findings": sum(item.status == "confirmed" for item in findings),
        "suspected_findings": sum(item.status == "suspected" for item in findings),
        "graph_nodes": len(graph_nodes),
        "graph_edges": len(graph_edges),
    }
    return AuditReport.create(
        target=target,
        revision=revision,
        findings=findings,
        analyzers=analyzers,
        warnings=warnings,
        summary=summary,
        graph_nodes=graph_nodes,
        graph_edges=graph_edges,
    )
