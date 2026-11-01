<div align="center">

# Hackathon Problem-Solving Workspace

**One repository. One selected problem statement. One focused solution.**

This checkout is focused on PS05: the Automated Multi-Agent Codebase Vulnerability and Dependency Graph Auditor.

</div>

---

## Selected problem statement

PS05 is the selected challenge. Its authoritative specification is [`PS05.md`](./PS05.md).
See [`docs/PROJECT_PLAN.md`](./docs/PROJECT_PLAN.md) for the project description, proposed architecture, component breakdown, implementation sequence, and evaluation plan.
The runnable MVP is implemented in `src/repo_auditor/`; its actual supported checks and limitations are listed below.

## Problem statement

| ID | Problem title | Specification |
|---|---|---|
| `PS05` | Automated Multi-Agent Codebase Vulnerability and Dependency Graph Auditor | See `PS05.md` |

## Getting started

1. Read [`PS05.md`](./PS05.md) for the challenge requirements.
2. Use [`docs/PROJECT_PLAN.md`](./docs/PROJECT_PLAN.md) as an implementation blueprint, adapting its recommendations to the team and hackathon constraints.
3. Follow PS05's setup, implementation, testing, and submission requirements.
4. Keep changes and evaluation focused on PS05.

The other problem-statement files have been removed from this checkout. Restore them from the repository history or a fresh checkout if you need to switch challenges.

## Repository guide

```text
.
├── AGENTS.md
├── agent_trace_instructions.md
├── CLAUDE.md
├── README.md
├── PS05.md
├── docs/
│   └── PROJECT_PLAN.md
├── evaluation/
│   ├── fixtures/
│   └── run_evaluation.py
├── log.txt
├── pyproject.toml
├── pyrightconfig.json
├── schemas/
│   └── report.schema.json
├── src/
│   └── repo_auditor/
│       └── web/       # Local browser UI
├── tests/             # Unit and integration tests
└── .vscode/           # VS Code tasks and launch profiles
```

### Project files

- **`AGENTS.md`** — coding-agent guidance for the challenge workflow and evaluation safeguards.
- **`agent_trace_instructions.md`** — guidance for collecting, reviewing, redacting, and packaging agent traces. Follow PS05's submission instructions if they specify a different trace artifact or archive layout.
- **`CLAUDE.md`** — compatibility pointer to the shared `AGENTS.md` instructions.
- **`docs/PROJECT_PLAN.md`** — architecture, implementation status, component breakdown, and evaluation plan.

## Implemented MVP

The CLI performs a read-only audit of a local repository or a public GitHub repository URL. It includes:

- Repository inventory with explicit exclusions for generated/vendor directories, symlinks, oversized files, and a configurable file-count limit.
- Exact-version dependency inventory from pinned `requirements*.txt` entries, Poetry `pyproject.toml` / `poetry.lock`, and npm `package-lock.json` (v1 and package-based lockfiles).
- Direct/transitive dependency relationships where manifests and lockfiles provide enough information; unknown directness is `null`, and ambiguous relationships are warned about rather than guessed.
- Batched exact-version vulnerability queries to OSV with a local SQLite cache. `--offline` uses cached data only and reports cache misses and stale results; only package names, ecosystems, and versions are sent to OSV, never source code.
- Python AST structure and bounded taint analysis for selected shell execution (`shell=True`), `eval`/`exec`, and SQL `execute` patterns. Direct same-file function-argument-to-sink flows are summarized for up to three rounds and bounded to 200 functions and 500 parameters per function; hitting these limits is reported as incomplete coverage.
- A graph of packages, imports, function definitions, and candidate calls.
- Evidence-linked findings with severity, confidence estimate, and `confirmed` / `suspected` status.
- JSON and Markdown reports, an always-written `graph.json`, and optional SARIF 2.1.0 output.
- Explicit coverage warnings and non-zero exit codes for failed or incomplete runs.

The initial implementation uses Python's built-in AST and a deterministic analyzer pipeline; it does not depend on Tree-sitter, NetworkX, CrewAI, LangGraph, or an LLM. This keeps runs reproducible and avoids sending source code to hosted models. LLM summaries, broader language support, cross-file/interprocedural analysis, automated patch generation, test execution, and pull requests are not implemented. Remediation guidance is included, but the tool never edits the audited repository.

### Requirements and installation

- Python 3.11 or newer
- Git for public GitHub URL input
- Network access to `https://api.osv.dev` for dependency advisory lookups (optional; `--offline` is available)

From this directory:

```powershell
python -m pip install -e .
```

### Run from VS Code with a virtual environment

1. Open this `achithon-2026-syntaxis` folder in VS Code.
2. Select **Terminal → Run Task… → PS05: Install project in virtual environment**. This creates `.venv` and installs the auditor.
3. Select **Run and Debug** from the VS Code sidebar, choose **PS05: Audit a repository**, and press **F5**.
4. Enter the target repository path when prompted. Keep the report output folder outside that repository. The default scans this project and saves reports to `..\ps05-audit-output`.
5. Open `report.md` in the output folder to read the results.

The workspace is configured to use `.venv\Scripts\python.exe` on Windows. If you recreate the environment, run the install task again. The same run configuration can also be started from the command line after installation:

```powershell
python -m repo_auditor audit C:\path\to\repository --output C:\path\to\audit-output
```

### Run an audit

```powershell
ps05-audit audit C:\path\to\repository --output C:\path\to\audit-output
```

Or run as a Python module:

```powershell
python -m repo_auditor audit C:\path\to\repository --output C:\path\to\audit-output
```

The module form requires the package to be installed (or `src` to be on `PYTHONPATH`).

### Browser interface

Start the local web interface from VS Code with **Run and Debug → PS05: Web interface → F5**, or from PowerShell:

```powershell
ps05-audit web
```

Or, from the project directory:

```powershell
.\.venv\Scripts\python.exe -m repo_auditor web
```

The server listens only on `127.0.0.1:8765` and opens the interface in your browser. The form defaults to the current terminal folder and a sibling `ps05-audit-output` folder; change either path if needed, making sure the report folder is outside the audited repository. Choose **Start security audit** to run in the background. The browser displays status, summary, analyzer coverage, warnings, and evidence-linked findings, with a filter for narrowing results and links to the generated Markdown and JSON reports. For large results, the page renders at most 200 findings to stay responsive; the JSON report retains the complete finding list. Use `--port 8766` to select a different local port or `--no-browser` to start without opening a tab; press `Ctrl+C` in the terminal to stop it.

The browser UI runs locally and accepts only same-origin requests. It scans local folders only; public GitHub URL cloning remains available through the command-line `audit` command. The UI does not execute repository code or modify the scanned repository.

Audit a public GitHub repository:

```powershell
ps05-audit audit https://github.com/owner/repository --output .\audit-output
```

Run offline using cached advisories only, bypass the cache, or request SARIF:

```powershell
ps05-audit audit C:\path\to\repository --offline --output .\audit-output
ps05-audit audit C:\path\to\repository --offline --no-cache --output C:\audit-output
ps05-audit audit C:\path\to\repository --format json markdown sarif --output .\audit-output
```

Outputs are `report.json`, `report.md`, and `graph.json`; SARIF adds `report.sarif.json`. The JSON report contract is versioned by `schema_version` and described in [`schemas/report.schema.json`](./schemas/report.schema.json).

The default SQLite cache is stored outside the target repository in the platform's per-user local cache directory. Use `--cache-file` to choose another path, `--cache-ttl-hours` to change online refresh age, or `--no-cache` to disable persistence. Offline mode uses cached answers (including stale answers with an explicit warning) and never contacts OSV. A cache miss is reported as incomplete coverage.

Exit codes: `0` means all enabled analysis completed, `1` means the target or report operation failed, and `2` means one or more analyzers were incomplete (including an offline run with missing/stale advisory results). Reports must be written outside a local target repository. A complete run with no findings is not a security guarantee.

### Supported analysis scope and limitations

- Dependency manifest support is intentionally conservative: only exact versions are queried. Ranges, URL/VCS dependencies, and unresolved versions are reported as skipped or unsupported.
- Python data-flow analysis covers selected sources (`input`, request argument/form/header/cookie/JSON access, `sys.argv`, and environment variables) and sinks (`subprocess` with `shell=True`, `eval`, `exec`, and `execute`-like methods). It follows direct function argument-to-sink flows within a single file to a bounded depth (three rounds, 200 functions, and 500 parameters per function); aliases, cross-file calls, returned tainted values, complex control/data flow, sanitizers, dynamic dispatch, and framework-specific behavior may cause false positives or missed findings.
- Other languages are inventoried only as ordinary files; they are not parsed or security-analyzed.
- OSV results confirm that the advisory service returned a match for the exact package version, not that the dependency is reachable or exploitable in this application. Missing severity remains `unknown`.
- A failed/skipped advisory lookup is never reported as a clean dependency result. The report status and analyzer messages describe incomplete coverage.
- GitHub input is restricted to public HTTPS repository URLs on `github.com`, shallow-cloned without submodules into a temporary directory, with a 120-second clone timeout. Local input is scanned without changing its source files.
- The analyzer does not execute repository code or project test commands. Report output is rejected when it resolves inside a local audited repository.

### Tests

Run the standard-library unit and integration test suite:

```powershell
python -m unittest discover -s tests -v
```

The tests cover dependency parsing, graph edges, cached and uncached advisory handling, positive and negative direct-call taint cases, output generation, offline status, invalid input, safe GitHub URL validation, and protection against writing reports into the local target.

Run the labeled static-analysis smoke evaluation:

```powershell
python evaluation\run_evaluation.py
```

It reports confusion-matrix counts, precision, recall, false-positive rate, source-to-sink path accuracy, and runtime. The included three fixtures are a smoke test only, not a representative benchmark; the script parses them without executing their contents.

## Build, test, and submit

Continue to treat [`PS05.md`](./PS05.md) as authoritative for hackathon-specific requirements. This MVP is a starting implementation, not a claim that every optional feature in the problem statement is complete.

Before submitting, verify that:

- The solution uses only allowed inputs and resources.
- The required output files exist and match the exact specified schema and coverage.
- The prescribed run and evaluation steps complete successfully.
- The package contains every required artifact and excludes credentials, secrets, and prohibited files.
- Any required agent trace or usage report is included in the requested format.

Use the submission URL stated by the selected challenge. Do not guess a URL or substitute a general contest page for an official submission link.

## Safety and working practices

- **Read the selected specification first.** It is authoritative for problem-specific requirements.
- **Keep secrets out of source control.** Use environment variables or ignored local configuration when the challenge requires credentials.
- **Protect private data.** Review traces and outputs for API keys, tokens, passwords, cookies, private keys, and sensitive personal information before sharing.
- **Keep changes scoped.** Work on the selected PS and shared files only; do not bring assumptions or evaluation labels over from another problem.
- **Retain trace integrity.** Preserve original structured session logs where practical. Redact only sensitive content, and do not include credentials or unrelated application data.

## Problem details

Keep challenge-specific facts grounded in the authoritative PS05 specification. Add only verified setup and submission information.

---

<div align="center">

**PS05 selected. Build to its specification.**

</div>
