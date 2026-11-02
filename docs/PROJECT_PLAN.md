# PS05 Project Description and Component Plan

## Project at a glance

**Working name:** Multi-Agent Codebase Vulnerability and Dependency Graph Auditor
**Challenge:** PS05 — Automated Multi-Agent Codebase Vulnerability and Dependency Graph Auditor
**Domain:** DevSecOps, generative AI, and agentic systems
**Primary deliverable:** A command-line tool, with a localhost-only browser interface, that audits a local codebase or Git repository and emits a prioritized, evidence-linked security report.

## Current implementation status

The repository now contains a working MVP under `src/repo_auditor/`. It implements a CLI and localhost-only browser UI; local/public-GitHub intake from the CLI; conservative Python/npm dependency parsing; batched OSV checks with a persistent SQLite cache and offline-cache status; Python AST graph extraction; selected source-to-sink rules with bounded direct same-file function-argument summaries (three rounds, at most 200 functions and 500 parameters per function); evidence-backed findings; JSON/Markdown/graph/SARIF outputs; analyzer status reporting; standard-library tests; a versioned report schema; and a small labeled evaluation runner. The browser UI accepts local folder paths, starts background audit jobs, displays and filters findings and coverage, and serves the generated Markdown/JSON report links. It defaults to the server's working folder, renders at most 200 findings in the page for responsiveness, and retains the complete report on disk. Reaching a summary limit is surfaced as incomplete analysis coverage.

The implementation deliberately uses Python's built-in `ast` module and a deterministic custom orchestration pipeline instead of adding Tree-sitter, NetworkX, CrewAI, LangGraph, or an LLM dependency. The code is not yet a general multi-language analyzer: JavaScript/TypeScript source, cross-file and broader interprocedural analysis, patch generation/validation, and pull-request integration remain future work. See the project [README](../README.md) for setup, commands, supported formats, exit codes, smoke-evaluation use, and safety boundaries.

The tool combines conventional, reproducible analysis with graph-based context and optional AI assistance. It inventories dependency manifests, checks dependency versions against vulnerability advisories, analyzes selected source-to-sink paths, and consolidates results into one explainable report. Where an issue is sufficiently supported, it can suggest a remediation and optionally prepare a focused patch. Proposed patches are review artifacts: the tool must not automatically merge or apply them without user approval.

The system must distinguish confirmed findings from suspected findings. An LLM explanation, agreement between agents, or a passing test is not by itself proof that a vulnerability exists or that a patch is secure. Every finding should retain its evidence and validation status so a reviewer can independently inspect the conclusion.

## Goals and boundaries

### Goals

- Accept a local repository path and, if time permits, a Git repository URL.
- Identify supported source files and dependency manifests.
- Parse supported code into structural information and build code/dependency graphs.
- Check direct and transitive dependencies against OSV and other explicitly configured advisory sources.
- Perform targeted, explainable data-flow or taint analysis for a small, documented set of source-to-sink patterns.
- Coordinate specialized analysis steps and consolidate duplicate or related results.
- Produce human-readable Markdown and machine-readable JSON reports; add SARIF if time allows.
- Give each finding a severity/priority, confidence or evidence status, affected location, supporting evidence, and remediation guidance.
- Optionally generate a patch proposal and validate it with relevant tests and checks in an isolated working copy.

### Non-goals for the first version

- Claiming to prove a repository is secure or to discover every vulnerability.
- Supporting every programming language, package manager, vulnerability class, or build system.
- Automatically changing the user's working tree, opening a pull request, or merging code.
- Treating model-generated findings as confirmed without independently inspectable evidence.
- Running arbitrary repository scripts with elevated privileges or unrestricted access to the host.

## User workflow

1. The user starts the CLI or localhost browser UI. The UI accepts a local repository folder; the CLI also accepts a public repository URL.
2. The input manager validates the target and creates a read-only inventory. A remote repository supplied through the CLI is cloned into a controlled temporary workspace.
3. The manifest analyzer discovers supported dependency files, resolves package identifiers and versions where possible, and records unresolved cases.
4. The code analyzer discovers supported source files, parses them, and extracts functions, calls, imports, and configured source/sink patterns.
5. Graph builders create code relationship and dependency graphs. The analyzers use these graphs to identify relevant paths and dependency reachability.
6. The dependency checker queries configured advisory sources, primarily OSV, with caching, timeouts, and clear reporting of unavailable or incomplete results.
7. Specialized analysis workers produce evidence-bearing candidate findings. An orchestrator coordinates these steps, handles failures explicitly, and deduplicates results.
8. A finding validator assigns an evidence state (confirmed, suspected, or needs review) based on deterministic evidence and analysis coverage. AI may help explain or prioritize evidence, but cannot independently confirm a finding.
9. The report writer outputs Markdown and JSON, including limitations and analysis status. SARIF is an optional additional output.
10. If requested, a remediation worker proposes a minimal patch in an isolated copy. The validation runner executes only configured, bounded checks and reports their results. The patch is presented for human review and is never automatically merged.

## System architecture and components

### 1. Command-line interface

**Responsibilities**

- Provide a predictable entry point for local paths and supported repository URLs.
- Expose output location, supported-language scope, advisory/network options, and optional patch validation.
- Print concise progress and actionable errors; use a non-zero exit code for failed or incomplete runs as defined by the CLI contract.
- Support a machine-readable run summary for automation.

**Initial commands/options to consider**

- `audit <path-or-url>` — run the audit.
- `--output <directory>` — choose where reports and artifacts are written.
- `--format markdown,json` — select report formats.
- `--offline` — use cached advisory results only; clearly report missing or stale coverage.
- `--patch-proposals` — request optional patch proposals without applying them to the input.
- `--validate-patches` — run configured checks against proposed patches in isolation.

Finalize names and exact option semantics during implementation. Do not silently interpret unsupported options as successful analysis.

### 2. Target intake and workspace manager

**Responsibilities**

- Validate the input path or URL and identify the repository root.
- For remote input, clone a selected revision into a temporary workspace; record the commit/revision analyzed.
- Exclude generated, vendored, and oversized paths according to explicit defaults and user-visible configuration.
- Keep original inputs unchanged and clean up only tool-owned temporary data.
- Apply resource limits and reject unsafe or ambiguous targets rather than traversing outside the requested repository.

### 3. Repository inventory and file discovery

**Responsibilities**

- Enumerate files deterministically and record file types, sizes, and exclusions.
- Identify supported source languages and dependency manifest/lockfile formats.
- Report unsupported or malformed files as coverage limitations instead of implying they were analyzed.
- Preserve repository-relative paths in reports and evidence.

### 4. Dependency inventory and graph

**Responsibilities**

- Parse supported manifests and lockfiles into normalized package records.
- Preserve ecosystem, package name, resolved version, direct/transitive status, manifest path, and dependency edges when available.
- Build a dependency graph with direct and transitive relationships.
- Avoid guessing package identity or version when parsing is incomplete; represent unresolved dependencies explicitly.

**Suggested first slice**

Select one or two package ecosystems based on the expected demonstration repository and available parsing libraries. Add more only after end-to-end dependency matching and reporting work for the first supported formats.

### 5. Advisory intelligence connector

**Responsibilities**

- Query OSV (and only other sources explicitly selected for the project) using normalized package identifiers and versions.
- Normalize advisory identifiers, affected version ranges, references, and fixed-version information.
- Cache responses to reduce repeat calls and support reproducible offline or rate-limited runs.
- Handle timeouts, rate limits, invalid responses, and network failures explicitly.
- Include source and retrieval status in reports; do not convert a failed lookup into a clean bill of health.

### 6. Source parser and structural analyzer

**Responsibilities**

- Use Tree-sitter for the initial supported language set.
- Parse files into ASTs and extract definitions, calls, imports, and relevant source locations.
- Record parse errors and unsupported syntax so coverage is visible.
- Use repository-relative file paths and stable line/column locations in evidence.

### 7. Code relationship graph

**Responsibilities**

- Represent files, modules, functions, call relationships, imports, and relevant data-flow edges as graph nodes and edges.
- Use NetworkX or a comparable graph library for traversals and path queries.
- Keep edge types and provenance explicit: parsed call, import, inferred relationship, or other evidence source.
- Bound traversal depth and graph size, and report when configured limits reduce analysis.

### 8. Targeted data-flow and taint analyzer

**Responsibilities**

- Define a small, documented set of sources, transformations, and sinks for the initially supported language(s).
- Trace candidate values across supported assignments and function/call relationships.
- Produce a path with source and sink locations and intermediate evidence, not just a pattern-match label.
- Distinguish proven paths from heuristic/incomplete paths; unsupported control flow must lower the evidence status or be reported as a limitation.
- Keep rules testable with safe and vulnerable fixtures.

This component should begin with a narrow, reliable set of patterns rather than claiming general-purpose interprocedural taint analysis.

### 9. Analysis workers / agents

Use a workflow engine (LangGraph, CrewAI, or a small custom orchestrator) only where it improves coordination and observability. The project does not require multiple unconstrained LLM agents.

Potential roles:

- **Dependency worker:** validates normalized packages against advisory records.
- **Code-pattern worker:** runs deterministic rules and identifies relevant code locations.
- **Data-flow worker:** evaluates supported source-to-sink paths in the code graph.
- **Context worker (optional LLM):** summarizes existing evidence, suggests likely impact, and drafts remediation guidance.
- **Triage/consolidation worker:** groups duplicates and prepares a consistent finding record without discarding evidence or upgrading confidence solely from agent agreement.
- **Patch worker (optional):** proposes a minimal patch after a finding has sufficient supporting evidence.

Each worker should have a defined input/output schema, explicit time/resource bounds, and a recorded status. The orchestrator should surface worker errors and incomplete results rather than silently returning a success-shaped report.

### 10. Finding model, evidence, and prioritization

Use one normalized finding format across all analyzers. A finding should include, where applicable:

- Stable finding ID and category (dependency, source pattern, data flow, or other).
- Title and concise description.
- Severity/priority and the basis used to assign it.
- Evidence status: confirmed, suspected, or needs review.
- Confidence as a separate estimate, not a substitute for evidence status.
- Repository-relative file and line/column locations.
- Dependency name, ecosystem, version, and dependency path when relevant.
- Source-to-sink path or code relationship evidence when relevant.
- Advisory ID, affected range, fixed version, and advisory URL when relevant.
- Remediation recommendation and optional patch reference.
- Validation results, analysis coverage, and known limitations.

Deduplicate findings without erasing distinct locations, advisories, or dependency paths. Keep raw analyzer evidence available for report rendering and review.

### 11. Remediation and isolated patch validation

**Responsibilities**

- Recommend a focused correction and explain its connection to the evidence.
- Generate a patch file or isolated working-copy change only when requested and supported.
- Preserve the original repository and show the exact proposed diff.
- Run only configured checks, such as relevant unit tests, targeted security tests, static analysis, and regression tests.
- Apply timeouts and resource limits to test commands. Do not execute arbitrary project commands without an explicit configured policy and user authorization.
- Report each check as passed, failed, skipped, or not run, including exit status and useful output.
- Never treat tests passing as proof that the vulnerability is fixed or that no other issues exist.

### 12. Report writers and integrations

**Markdown report:** readable executive summary, prioritized findings, evidence, remediation, validation, and coverage limitations.

**JSON report:** stable, versioned schema suitable for automation and test assertions.

**SARIF (optional):** map supported finding fields to SARIF while preserving rule IDs, locations, severity, and evidence references.

**Patch artifacts (optional):** store proposed diffs separately from reports and identify whether validation was performed.

The final report should state repository revision, tool version, run time, enabled analyzers, excluded files, advisory lookup status, supported coverage, and incomplete/failed steps.

### 13. Configuration, logging, and operational safety

- Keep configuration explicit and validate it at startup.
- Store API credentials only in environment variables or approved local secret storage; never write them to reports or logs.
- Make network use and any LLM use visible to the user.
- Avoid sending source code to hosted models unless the user has configured and authorized that behavior.
- Log analyzer status and errors without logging secrets or unnecessary source contents.
- Use safe temporary directories, bounded downloads, request timeouts, and cleanup restricted to tool-owned paths.
- Do not modify the target repository by default.

## Recommended implementation sequence

### Phase 1 — End-to-end CLI and report contract

- Define a versioned finding/run JSON schema.
- Implement target intake, file inventory, CLI options, and Markdown/JSON report generation.
- Add fixtures and tests for success, invalid input, and incomplete analysis.

### Phase 2 — Dependency audit

- Support a small selected set of manifests/lockfiles.
- Normalize package records and build direct/transitive dependency relationships where possible.
- Add OSV lookup, response normalization, caching, and explicit network-failure status.
- Test affected, unaffected, unknown, and unresolvable package versions.

### Phase 3 — Code structure and graph

- Parse one or more selected languages with Tree-sitter.
- Extract functions/imports/calls and build a typed NetworkX graph.
- Surface parse errors and coverage information in reports.

### Phase 4 — Targeted data-flow analysis

- Implement a few clearly scoped source/sink rules.
- Track evidence paths across supported constructs.
- Test both vulnerable and safe examples, including unsupported/ambiguous cases.

### Phase 5 — Orchestration and contextual AI (optional)

- Coordinate deterministic analyzers through a clear workflow.
- Add an LLM context worker only if it improves explanations or triage; require structured output and retain the evidence it was given.
- Test malformed model output, timeouts, disabled credentials, and disagreement with deterministic evidence.

### Phase 6 — Remediation and validation (optional)

- Generate a focused patch proposal in an isolated copy.
- Run bounded, configured tests and static checks.
- Produce a reviewable diff plus validation results; never auto-merge.

### Phase 7 — Evaluation and demonstration

- Run the benchmark fixtures and measure required metrics.
- Demonstrate a complete audit from input to report.
- Document supported inputs, limitations, setup, run commands, and output examples.

For a hackathon MVP, complete Phases 1–4 with a narrow but reliable scope before investing in optional LLM orchestration, SARIF, or automated patching.

## Evaluation plan

Build a labeled fixture set containing both vulnerable and safe examples and dependency cases with known advisory status. Keep evaluation labels separate from the analyzer's runtime inputs.

Measure and report:

- Dependency advisory matching accuracy, including affected-version boundary cases.
- Source-to-sink path accuracy on supported patterns.
- Precision/false-positive rate and recall where the fixture labels support those measurements.
- Correctness of evidence locations and dependency paths.
- Patch validation success rate for generated proposals, with skipped/failed tests counted transparently.
- Regression test results.
- Runtime and resource use on representative repository sizes.
- Coverage: supported file types, successfully parsed files, manifests analyzed, and failed or skipped checks.

Report the fixture size, ground-truth method, metric definitions, and limitations. Do not use a single aggregate score to hide false positives, missed cases, or incomplete analysis.

## Suggested repository structure

Adapt this structure to the implementation language and repository conventions:

```text
src/
  cli/                 # Argument parsing and user-facing commands
  intake/              # Local/remote target handling and safe workspace setup
  inventory/           # File and manifest discovery
  dependencies/        # Manifest parsing, graph, advisory clients
  parsing/             # Tree-sitter parsing and structural extraction
  code_graph/          # Code graph model and graph construction
  analysis/            # Rules and targeted data-flow analysis
  orchestration/       # Worker coordination and run state
  findings/            # Finding schema, evidence, prioritization, deduplication
  remediation/          # Optional patch proposal and isolated validation
  reporting/            # Markdown, JSON, and optional SARIF renderers
tests/
  fixtures/
    vulnerable/
    safe/
  unit/
  integration/
```

## Definition of done for the hackathon MVP

- A user can run the CLI on a documented local fixture or repository and get Markdown and JSON reports.
- The report identifies the analyzed revision, enabled checks, coverage, failures, and limitations.
- At least one supported dependency format is checked against OSV, with tests for known affected and unaffected cases.
- At least one supported language is parsed, and the graph contains documented code relationships.
- At least one targeted source-to-sink pattern has evidence-linked positive and negative tests.
- Findings use the same schema and distinguish confirmed from suspected/needs-review results.
- Network, parser, analyzer, and optional model failures are visible and do not produce misleading clean results.
- The target repository is not changed by a normal audit.
- Any patch proposal is optional, isolated, reviewable, and accompanied by bounded validation results.
- Setup, usage, supported coverage, evaluation results, and known limitations are documented.

## Decisions to settle before implementation

The PS05 statement does not prescribe these implementation details. Choose and document them based on the team, time, and demonstration target:

1. Initial programming language(s) and dependency manifest formats.
2. Whether remote repository URLs are required for the MVP or local paths are sufficient.
3. Which source-to-sink rules are realistic to implement and test.
4. Whether to use LangGraph, CrewAI, or a custom workflow; whether any hosted/local LLM is available and permitted.
5. Whether advisory lookups require internet access, and what offline behavior is supported.
6. Which checks can safely run for patch validation and how they are isolated.
7. Whether SARIF or patch generation is more valuable than strengthening core audit accuracy.

Until decided, treat these as configurable project choices, not requirements guaranteed by PS05.
