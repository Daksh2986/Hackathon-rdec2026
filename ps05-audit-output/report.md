# Repository Security Audit

- **Run ID:** `f50a3b65-fe27-4f92-b497-50224335be20`
- **Target:** `C:\\project2\\Hackathon-rdec2026\\achithon-2026-syntaxis`
- **Revision:** `d3bbe9b18f8648e40beb55c96d7ae55cb222e636`
- **Created:** `2026-10-30T17:42:43.770372+00:00`
- **Run status:** **COMPLETE**

## Summary

| Metric | Count |
|---|---:|
| Files Discovered | 47 |
| Files Excluded | 7 |
| Python Files Discovered | 24 |
| Python Files Analyzed | 24 |
| Manifests Discovered | 1 |
| Manifests Analyzed | 1 |
| Dependencies Resolved | 0 |
| Osv Cache Hits | 0 |
| Osv Network Queries | 0 |
| Osv Cache Missing | 0 |
| Osv Cache Stale | 0 |
| Findings | 2 |
| Confirmed Findings | 0 |
| Suspected Findings | 2 |
| Graph Nodes | 590 |
| Graph Edges | 1663 |

## Analyzer status

- **repository\_inventory — COMPLETE:** Inventoried 47 file(s), excluding 7 by configured rules or limits.
- **dependency\_inventory — COMPLETE:** Parsed 1 supported manifest(s) and identified 0 resolved package version(s).
- **python\_ast\_and\_taint — COMPLETE:** Parsed 24 Python file(s); 0 file(s) could not be parsed. 0 file(s) reached analysis limits. Analysis includes bounded same-file direct-call summaries and is limited to documented source/sink patterns.
- **osv\_advisories — COMPLETE:** No resolved package versions were available for advisory checks.

## Findings

### [HIGH] Untrusted input may reach dynamic code execution

- **ID:** `code-086c14365ba4`
- **Rule:** `PY-EVAL-001`
- **Category:** data\_flow
- **Evidence status:** **SUSPECTED**
- **Heuristic confidence:** 0.65
- **Description:** Untrusted input reaches eval().

**Locations**
- `evaluation/fixtures/vulnerable\_eval.py:2` (untrusted input source)
- `evaluation/fixtures/vulnerable\_eval.py:2` (potentially unsafe sink)

**Evidence**
- Within function parse, a supported source-to-sink path was found.
- Source line(s): 2; sink line: 2.
- This is bounded same-file syntax-based analysis; verify the path and sanitization manually.

**Remediation:** Remove dynamic evaluation of untrusted data; use a constrained parser or explicit operation mapping.

### [HIGH] Untrusted input may reach a shell command

- **ID:** `code-18b0b1b16a96`
- **Rule:** `PY-SHELL-001`
- **Category:** data\_flow
- **Evidence status:** **SUSPECTED**
- **Heuristic confidence:** 0.75
- **Description:** Untrusted input reaches a subprocess call with shell=True.

**Locations**
- `evaluation/fixtures/vulnerable\_shell.py:5` (untrusted input source)
- `evaluation/fixtures/vulnerable\_shell.py:6` (potentially unsafe sink)

**Evidence**
- Within function run, a supported source-to-sink path was found.
- Source line(s): 5; sink line: 6.
- This is bounded same-file syntax-based analysis; verify the path and sanitization manually.

**Remediation:** Avoid shell=True and pass a fixed executable with an argument list. Validate any user-controlled arguments.

## Warnings and coverage limitations

No inventory, parsing, or advisory lookup warnings were reported.

## Interpretation

Dependency findings marked confirmed reflect an exact-version OSV response. Source findings are suspected syntax-based paths, not proof of exploitability. A clean or partial report does not establish that the repository is secure; review the listed coverage and limitations.
