from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .models import Finding, GraphEdge, GraphNode, finding_id

MAX_GRAPH_EDGES = 100_000
MAX_INTERPROCEDURAL_ROUNDS = 3
MAX_INTERPROCEDURAL_FUNCTIONS = 200
MAX_INTERPROCEDURAL_PARAMETERS = 500


def _callee_name(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return type(node).__name__


def _source_call(node: ast.Call) -> bool:
    name = _callee_name(node.func)
    if name in {"input", "os.getenv", "os.environ.get"}:
        return True
    if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
        receiver = _callee_name(node.func.value).rsplit(".", 1)[-1]
        return receiver in {"args", "form", "values", "headers", "cookies", "json"}
    return False


def _environment_source(node: ast.AST) -> bool:
    if isinstance(node, ast.Subscript):
        base = _callee_name(node.value)
        return base in {
            "sys.argv",
            "os.environ",
        } or base.rsplit(".", 1)[-1] in {"args", "form", "values", "headers", "cookies", "json"}
    return _callee_name(node) in {"sys.argv", "os.environ"}


def _names(target: ast.AST) -> Iterable[str]:
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for item in target.elts:
            yield from _names(item)


class _TaintAnalysis:
    def __init__(
        self,
        path: str,
        function_name: str,
        function_summaries: dict[str, dict[int, list[FunctionSinkSummary]]] | None = None,
        function_parameters: dict[str, list[str]] | None = None,
        initial_taint: dict[str, set[int]] | None = None,
    ):
        self.path = path
        self.function_name = function_name
        self.function_summaries = function_summaries or {}
        self.function_parameters = function_parameters or {}
        self.environment = {
            name: set(lines) for name, lines in (initial_taint or {}).items()
        }
        self.findings: list[Finding] = []

    def _tainted_sources(self, node: ast.AST) -> set[int]:
        if isinstance(node, ast.Name):
            return set(self.environment.get(node.id, set()))
        if isinstance(node, ast.Call):
            if _source_call(node):
                return {getattr(node, "lineno", 1)}
            sources: set[int] = set()
            for child in [node.func, *node.args, *(keyword.value for keyword in node.keywords)]:
                sources.update(self._tainted_sources(child))
            return sources
        if _environment_source(node):
            return {getattr(node, "lineno", 1)}
        if isinstance(node, ast.Constant):
            return set()
        sources = set()
        for child in ast.iter_child_nodes(node):
            sources.update(self._tainted_sources(child))
        return sources

    def _add_finding(
        self,
        call: ast.Call,
        rule_id: str,
        title: str,
        severity: str,
        source_lines: set[int],
        remediation: str,
        reason: str,
    ) -> None:
        line = getattr(call, "lineno", 1)
        locations = [
            {"path": self.path, "line": source_line, "role": "untrusted input source"}
            for source_line in sorted(source_lines)
        ]
        locations.append({"path": self.path, "line": line, "role": "potentially unsafe sink"})
        self.findings.append(
            Finding(
                id=finding_id("code", rule_id, f"{self.path}:{line}"),
                rule_id=rule_id,
                category="data_flow",
                title=title,
                description=reason,
                severity=severity,
                status="suspected",
                confidence=0.75 if rule_id == "PY-SHELL-001" else 0.65,
                locations=locations,
                evidence=[
                    f"Within function {self.function_name}, a supported source-to-sink path was found.",
                    f"Source line(s): {', '.join(map(str, sorted(source_lines)))}; sink line: {line}.",
                    "This is bounded same-file syntax-based analysis; verify the path and sanitization manually.",
                ],
                remediation=remediation,
            )
        )

    def _inspect_calls(self, node: ast.AST) -> None:
        for item in ast.walk(node):
            if not isinstance(item, ast.Call):
                continue
            callee = _callee_name(item.func)
            if callee in {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output"}:
                shell_enabled = any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in item.keywords)
                if shell_enabled:
                    sources: set[int] = set()
                    for argument in item.args:
                        sources.update(self._tainted_sources(argument))
                    for keyword in item.keywords:
                        if keyword.arg != "shell":
                            sources.update(self._tainted_sources(keyword.value))
                    if sources:
                        self._add_finding(
                            item,
                            "PY-SHELL-001",
                            "Untrusted input may reach a shell command",
                            "high",
                            sources,
                            "Avoid shell=True and pass a fixed executable with an argument list. Validate any user-controlled arguments.",
                            "Untrusted input reaches a subprocess call with shell=True.",
                        )
            elif callee in {"eval", "exec"}:
                sources = self._tainted_sources(item.args[0]) if item.args else set()
                if sources:
                    self._add_finding(
                        item,
                        "PY-EVAL-001",
                        "Untrusted input may reach dynamic code execution",
                        "high",
                        sources,
                        "Remove dynamic evaluation of untrusted data; use a constrained parser or explicit operation mapping.",
                        f"Untrusted input reaches {callee}().",
                    )
            elif callee.endswith(".execute") or callee.endswith(".executemany"):
                sources = self._tainted_sources(item.args[0]) if item.args else set()
                if sources:
                    self._add_finding(
                        item,
                        "PY-SQL-001",
                        "Untrusted input may reach a SQL execution call",
                        "medium",
                        sources,
                        "Use parameterized queries and pass user-controlled values as query parameters.",
                        "Untrusted input reaches the first argument of an execute-like call; the receiver is not type-resolved.",
                    )
            elif isinstance(item.func, ast.Name) and item.func.id in self.function_summaries:
                self._inspect_user_function_call(item, item.func.id)

    def _inspect_user_function_call(self, call: ast.Call, function_name: str) -> None:
        for parameter_index, sinks in self.function_summaries[function_name].items():
            if parameter_index < len(call.args):
                sources = self._tainted_sources(call.args[parameter_index])
            else:
                parameter_names = self.function_parameters.get(function_name, [])
                if parameter_index >= len(parameter_names):
                    continue
                keyword = next(
                    (item for item in call.keywords if item.arg == parameter_names[parameter_index]),
                    None,
                )
                if keyword is None:
                    continue
                sources = self._tainted_sources(keyword.value)
            if not sources:
                continue
            for sink in sinks:
                call_line = getattr(call, "lineno", 1)
                locations = [
                    {"path": self.path, "line": line, "role": "untrusted input source"}
                    for line in sorted(sources)
                ]
                locations.extend(
                    [
                        {"path": self.path, "line": call_line, "role": "function call site"},
                        {"path": sink.path, "line": sink.line, "role": "potentially unsafe sink"},
                    ]
                )
                self.findings.append(
                    Finding(
                        id=finding_id(
                            "code",
                            sink.rule_id,
                            f"{self.path}:{call_line}:{sink.path}:{sink.line}",
                        ),
                        rule_id=sink.rule_id,
                        category="data_flow",
                        title=f"Untrusted input may reach a sensitive sink through {function_name}()",
                        description=sink.description,
                        severity=sink.severity,
                        status="suspected",
                        confidence=0.7,
                        locations=locations,
                        evidence=[
                            f"Untrusted input in {self.function_name}() is passed to {function_name}().",
                            f"The parameter reaches a sensitive sink at {sink.path}:{sink.line}.",
                            "Direct same-file function summaries are conservative; verify aliases and sanitization manually.",
                        ],
                        remediation=sink.remediation,
                    )
                )

    def _process_statements(self, statements: list[ast.stmt]) -> None:
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(statement, ast.If):
                self._inspect_calls(statement.test)
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                self._inspect_calls(statement.iter if isinstance(statement, (ast.For, ast.AsyncFor)) else statement.test)
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    self._inspect_calls(item.context_expr)
            elif isinstance(statement, ast.Try):
                pass
            else:
                self._inspect_calls(statement)
            if isinstance(statement, ast.Assign):
                sources = self._tainted_sources(statement.value)
                for target in statement.targets:
                    for name in _names(target):
                        if sources:
                            self.environment[name] = sources
                        else:
                            self.environment.pop(name, None)
            elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
                sources = self._tainted_sources(statement.value)
                for name in _names(statement.target):
                    if sources:
                        self.environment[name] = sources
                    else:
                        self.environment.pop(name, None)
            elif isinstance(statement, ast.AugAssign):
                sources = self._tainted_sources(statement.value)
                for name in _names(statement.target):
                    combined = self.environment.get(name, set()) | sources
                    if combined:
                        self.environment[name] = combined
            elif isinstance(statement, ast.If):
                before = {name: set(lines) for name, lines in self.environment.items()}
                self._process_statements(statement.body)
                true_branch = {name: set(lines) for name, lines in self.environment.items()}
                self.environment = {name: set(lines) for name, lines in before.items()}
                self._process_statements(statement.orelse)
                false_branch = {name: set(lines) for name, lines in self.environment.items()}
                merged = {name: set(lines) for name, lines in before.items()}
                for name in set(true_branch) | set(false_branch):
                    merged[name] = (
                        merged.get(name, set())
                        | true_branch.get(name, set())
                        | false_branch.get(name, set())
                    )
                self.environment = merged
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                before = {name: set(lines) for name, lines in self.environment.items()}
                self._process_statements(statement.body)
                body = {name: set(lines) for name, lines in self.environment.items()}
                self.environment = before
                self._process_statements(statement.orelse)
                for name, lines in body.items():
                    self.environment[name] = self.environment.get(name, set()) | lines
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                self._process_statements(statement.body)
            elif isinstance(statement, (ast.Try,)):
                before = {name: set(lines) for name, lines in self.environment.items()}
                branches = [statement.body, *[handler.body for handler in statement.handlers], statement.orelse]
                merged = {name: set(lines) for name, lines in before.items()}
                for branch in branches:
                    self.environment = {name: set(lines) for name, lines in before.items()}
                    self._process_statements(branch)
                    for name, lines in self.environment.items():
                        merged[name] = merged.get(name, set()) | lines
                self.environment = merged
                self._process_statements(statement.finalbody)


def _function_definitions(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    functions: list[ast.FunctionDef | ast.AsyncFunctionDef] = []

    class Collector(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            functions.append(node)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            functions.append(node)
            self.generic_visit(node)

    Collector().visit(tree)
    return functions


@dataclass(frozen=True, slots=True)
class FunctionSinkSummary:
    rule_id: str
    title: str
    severity: str
    description: str
    remediation: str
    path: str
    line: int


def _function_parameters(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    arguments = function.args
    return [
        argument.arg
        for argument in [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    ]


def _unique_function_definitions(
    functions: list[ast.FunctionDef | ast.AsyncFunctionDef],
) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    by_name: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for function in functions:
        by_name.setdefault(function.name, []).append(function)
    return {name: items[0] for name, items in by_name.items() if len(items) == 1}


def _build_function_summaries(
    functions: list[ast.FunctionDef | ast.AsyncFunctionDef],
    relative: str,
) -> tuple[dict[str, dict[int, list[FunctionSinkSummary]]], bool]:
    all_functions = _unique_function_definitions(functions)
    unique_functions = dict(list(all_functions.items())[:MAX_INTERPROCEDURAL_FUNCTIONS])
    truncated = len(unique_functions) < len(all_functions)
    summaries: dict[str, dict[int, list[FunctionSinkSummary]]] = {
        name: {} for name in unique_functions
    }
    parameter_names = {
        name: _function_parameters(function) for name, function in unique_functions.items()
    }

    for _ in range(MAX_INTERPROCEDURAL_ROUNDS):
        updated: dict[str, dict[int, list[FunctionSinkSummary]]] = {}
        for name, function in unique_functions.items():
            parameter_summaries: dict[int, list[FunctionSinkSummary]] = {}
            for index, parameter in enumerate(_function_parameters(function)):
                if index >= MAX_INTERPROCEDURAL_PARAMETERS:
                    truncated = True
                    break
                parameter_marker = -(function.lineno * 1000 + index + 1)
                analyzer = _TaintAnalysis(
                    relative,
                    name,
                    summaries,
                    parameter_names,
                    {parameter: {parameter_marker}},
                )
                analyzer._process_statements(function.body)
                sinks: dict[tuple[str, str, int], FunctionSinkSummary] = {}
                for finding in analyzer.findings:
                    if not any(
                        location.get("role") == "untrusted input source"
                        and location.get("line") == parameter_marker
                        for location in finding.locations
                    ):
                        continue
                    sink_location = next(
                        (
                            location
                            for location in finding.locations
                            if location.get("role") == "potentially unsafe sink"
                        ),
                        None,
                    )
                    if sink_location is None or sink_location.get("line") is None:
                        continue
                    sink_path = str(sink_location.get("path", relative))
                    summary = FunctionSinkSummary(
                        rule_id=finding.rule_id,
                        title=finding.title,
                        severity=finding.severity,
                        description=finding.description,
                        remediation=finding.remediation,
                        path=sink_path,
                        line=int(sink_location["line"]),
                    )
                    sinks[(summary.rule_id, summary.path, summary.line)] = summary
                if sinks:
                    parameter_summaries[index] = list(sinks.values())
            updated[name] = parameter_summaries
        if updated == summaries:
            break
        summaries = updated
    return summaries, truncated


def analyze_python_file(
    root: Path,
    path: Path,
    nodes: list[GraphNode],
    edges: list[GraphEdge],
) -> tuple[list[Finding], str | None, str | None]:
    relative = path.relative_to(root).as_posix()
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=relative)
    except (OSError, UnicodeError, SyntaxError) as error:
        return [], f"Could not parse {relative}: {error}", None

    module_id = f"file:{relative}"

    def add_node(node: GraphNode) -> None:
        if len(nodes) < MAX_GRAPH_EDGES:
            nodes.append(node)

    def add_edge(edge: GraphEdge) -> None:
        if len(edges) < MAX_GRAPH_EDGES:
            edges.append(edge)

    add_node(GraphNode(module_id, "file", relative))
    findings: list[Finding] = []
    functions = _function_definitions(tree)
    functions_by_name: dict[str, list[str]] = {}
    for function in functions:
        functions_by_name.setdefault(function.name, []).append(
            f"function:{relative}::{function.name}@{function.lineno}"
        )

    class StructureCollector(ast.NodeVisitor):
        scope: list[str]

        def __init__(self) -> None:
            self.scope = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._function(node)

        def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            parent_id = self.scope[-1] if self.scope else module_id
            function_id = f"function:{relative}::{node.name}@{node.lineno}"
            add_node(
                GraphNode(
                    function_id,
                    "function",
                    node.name,
                    {"path": relative, "line": node.lineno, "async": isinstance(node, ast.AsyncFunctionDef)},
                )
            )
            add_edge(GraphEdge(parent_id, function_id, "defines", relative, node.lineno))
            self.scope.append(function_id)
            self.generic_visit(node)
            self.scope.pop()

        def visit_Call(self, node: ast.Call) -> None:
            caller = self.scope[-1] if self.scope else module_id
            callee = _callee_name(node.func)
            targets = functions_by_name.get(node.func.id, []) if isinstance(node.func, ast.Name) else []
            if len(targets) == 1:
                add_edge(GraphEdge(caller, targets[0], "calls", relative, node.lineno))
            else:
                target = f"symbol:{callee}"
                add_node(GraphNode(target, "symbol", callee))
                add_edge(GraphEdge(caller, target, "calls_candidate", relative, node.lineno))
            self.generic_visit(node)

        def visit_Import(self, node: ast.Import) -> None:
            caller = self.scope[-1] if self.scope else module_id
            for alias in node.names:
                target = f"module:{alias.name}"
                add_node(GraphNode(target, "module", alias.name))
                add_edge(GraphEdge(caller, target, "imports", relative, node.lineno))

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            caller = self.scope[-1] if self.scope else module_id
            module = "." * node.level + (node.module or "")
            target = f"module:{module}"
            add_node(GraphNode(target, "module", module))
            add_edge(GraphEdge(caller, target, "imports", relative, node.lineno))

    StructureCollector().visit(tree)

    summaries, summaries_truncated = _build_function_summaries(functions, relative)
    parameter_names = {
        name: _function_parameters(function)
        for name, function in _unique_function_definitions(functions).items()
    }
    for function in functions:
        analyzer = _TaintAnalysis(relative, function.name, summaries, parameter_names)
        analyzer._process_statements(function.body)
        findings.extend(analyzer.findings)

    module_analyzer = _TaintAnalysis(relative, "<module>", summaries, parameter_names)
    module_analyzer._process_statements(tree.body)
    findings.extend(module_analyzer.findings)

    summary_warning = None
    if summaries_truncated:
        summary_warning = (
            f"Interprocedural analysis in {relative} was bounded to "
            f"{MAX_INTERPROCEDURAL_FUNCTIONS} functions, {MAX_INTERPROCEDURAL_PARAMETERS} parameters per function, "
            f"and {MAX_INTERPROCEDURAL_ROUNDS} rounds."
        )
    return findings, None, summary_warning
