from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from repo_auditor.models import GraphEdge, GraphNode
from repo_auditor.python_analysis import analyze_python_file


class PythonAnalysisTests(unittest.TestCase):
    def _analyze(self, source: str):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        path = root / "app.py"
        path.write_text(source, encoding="utf-8")
        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []
        findings, error, warning = analyze_python_file(root, path, nodes, edges)
        self.assertIsNone(error)
        self.assertIsNone(warning)
        return findings, nodes, edges

    def test_tracks_request_input_through_assignment_to_shell_sink(self) -> None:
        findings, _, _ = self._analyze(
            "def run(request):\n"
            "    command = request.args.get('cmd')\n"
            "    subprocess.run(command, shell=True)\n"
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-SHELL-001")
        self.assertEqual(findings[0].status, "suspected")
        self.assertEqual(
            {(location["line"], location["role"]) for location in findings[0].locations},
            {(2, "untrusted input source"), (3, "potentially unsafe sink")},
        )

    def test_safe_constant_shell_call_is_not_reported(self) -> None:
        findings, _, _ = self._analyze("subprocess.run('echo safe', shell=True)\n")
        self.assertEqual(findings, [])

    def test_bracket_request_source_and_environment_helper_are_tracked(self) -> None:
        findings, _, _ = self._analyze(
            "def run(request):\n"
            "    subprocess.run(request.args['cmd'], shell=True)\n"
            "    eval(os.environ.get('EXPR'))\n"
        )
        self.assertEqual(
            {finding.rule_id for finding in findings},
            {"PY-SHELL-001", "PY-EVAL-001"},
        )

    def test_reports_eval_and_sql_execution_paths(self) -> None:
        findings, _, _ = self._analyze(
            "def run(request, cursor):\n"
            "    value = request.form.get('value')\n"
            "    eval(value)\n"
            "    cursor.execute('SELECT ' + value)\n"
        )

        self.assertEqual({finding.rule_id for finding in findings}, {"PY-EVAL-001", "PY-SQL-001"})
        self.assertTrue(all(finding.status == "suspected" for finding in findings))

    def test_branch_analysis_merges_taint_without_duplicate_sink(self) -> None:
        findings, _, _ = self._analyze(
            "def run(request, flag):\n"
            "    if flag:\n"
            "        command = request.args.get('cmd')\n"
            "    else:\n"
            "        command = 'echo safe'\n"
            "    subprocess.run(command, shell=True)\n"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].locations[-1]["line"], 6)

    def test_tracks_tainted_arguments_through_direct_function_call(self) -> None:
        findings, nodes, edges = self._analyze(
            "def run_shell(command):\n"
            "    subprocess.run(command, shell=True)\n"
            "def handle(request):\n"
            "    command = request.args.get('cmd')\n"
            "    run_shell(command)\n"
        )

        matching = [finding for finding in findings if finding.rule_id == "PY-SHELL-001"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(
            {(location["line"], location["role"]) for location in matching[0].locations},
            {
                (4, "untrusted input source"),
                (5, "function call site"),
                (2, "potentially unsafe sink"),
            },
        )
        self.assertIn("run_shell", {node.label for node in nodes if node.kind == "function"})
        self.assertTrue(any(edge.kind == "calls" for edge in edges))

    def test_summarizes_two_direct_function_call_hops(self) -> None:
        findings, _, _ = self._analyze(
            "def execute(command):\n"
            "    subprocess.run(command, shell=True)\n"
            "def forward(command):\n"
            "    execute(command)\n"
            "def handle(request):\n"
            "    command = request.args.get('cmd')\n"
            "    forward(command)\n"
        )
        matching = [finding for finding in findings if finding.rule_id == "PY-SHELL-001"]
        self.assertTrue(any(
            any(location.get("role") == "function call site" and location.get("line") == 7 for location in finding.locations)
            and any(location.get("role") == "potentially unsafe sink" and location.get("line") == 2 for location in finding.locations)
            for finding in matching
        ))

    def test_parse_errors_are_reported_as_coverage_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "bad.py"
            path.write_text("def broken(:\n", encoding="utf-8")
            findings, error, warning = analyze_python_file(root, path, [], [])
        self.assertEqual(findings, [])
        self.assertIn("Could not parse bad.py", error or "")
        self.assertIsNone(warning)

    def test_function_summary_limit_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "many_functions.py"
            path.write_text(
                "\n".join(
                    f"def function_{index}():\n    return {index}"
                    for index in range(201)
                ),
                encoding="utf-8",
            )
            findings, error, warning = analyze_python_file(root, path, [], [])
        self.assertEqual(findings, [])
        self.assertIsNone(error)
        self.assertIn("bounded to 200 functions", warning or "")


if __name__ == "__main__":
    unittest.main()
