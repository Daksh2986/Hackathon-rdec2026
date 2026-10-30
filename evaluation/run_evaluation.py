from __future__ import annotations

import json
import sys
from pathlib import Path
from time import perf_counter
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from repo_auditor.models import GraphEdge, GraphNode
from repo_auditor.python_analysis import analyze_python_file


def evaluate(fixtures: Path | None = None) -> dict[str, Any]:
    fixture_root = fixtures or Path(__file__).parent / "fixtures"
    labels = json.loads((fixture_root / "labels.json").read_text(encoding="utf-8"))
    counts = {"true_positive": 0, "false_positive": 0, "true_negative": 0, "false_negative": 0}
    expected_paths = 0
    matched_paths = 0
    parse_errors: list[str] = []
    started = perf_counter()

    for case in labels["cases"]:
        path = fixture_root / case["file"]
        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []
        findings, error, warning = analyze_python_file(fixture_root, path, nodes, edges)
        if error:
            parse_errors.append(error)
            findings = []
        if warning:
            parse_errors.append(warning)
        expected = case["expected"]
        found_vulnerability = bool(findings)
        expected_vulnerability = case["label"] == "vulnerable"

        if expected_vulnerability and found_vulnerability:
            counts["true_positive"] += 1
        elif expected_vulnerability:
            counts["false_negative"] += 1
        elif found_vulnerability:
            counts["false_positive"] += 1
        else:
            counts["true_negative"] += 1

        for expected_finding in expected:
            expected_paths += 1
            if any(
                finding.rule_id == expected_finding["rule_id"]
                and any(
                    location.get("role") == "potentially unsafe sink"
                    and location.get("line") == expected_finding["sink_line"]
                    for location in finding.locations
                )
                for finding in findings
            ):
                matched_paths += 1

    elapsed_ms = (perf_counter() - started) * 1000
    tp, fp, tn, fn = (
        counts["true_positive"],
        counts["false_positive"],
        counts["true_negative"],
        counts["false_negative"],
    )
    return {
        "schema_version": "1.0",
        "fixtures": len(labels["cases"]),
        "confusion_matrix": counts,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "source_to_sink_path_accuracy": matched_paths / expected_paths if expected_paths else 0.0,
        "matched_source_to_sink_paths": matched_paths,
        "expected_source_to_sink_paths": expected_paths,
        "runtime_ms": round(elapsed_ms, 3),
        "parse_errors": parse_errors,
        "limitations": [
            "Small labeled smoke-test set; results are not representative of arbitrary repositories.",
            "Fixtures are parsed as text and are never executed.",
            "Metrics cover only the implemented Python source-to-sink rules.",
        ],
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
