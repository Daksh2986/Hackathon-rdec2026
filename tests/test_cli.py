from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from repo_auditor.cli import main
from repo_auditor.intake import _validate_github_url, repository_target


class CliTests(unittest.TestCase):
    def test_offline_audit_writes_reports_and_marks_advisories_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            output = Path(temporary) / "reports"
            root.mkdir()
            (root / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
            (root / "app.py").write_text(
                "def run(request):\n"
                "    value = request.args.get('cmd')\n"
                "    subprocess.run(value, shell=True)\n",
                encoding="utf-8",
            )

            result = main(
                [
                    "audit",
                    str(root),
                    "--offline",
                    "--no-cache",
                    "--output",
                    str(output),
                    "--format",
                    "json",
                    "markdown",
                    "sarif",
                ]
            )

            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            markdown = (output / "report.md").read_text(encoding="utf-8")
            graph = json.loads((output / "graph.json").read_text(encoding="utf-8"))
            sarif = json.loads((output / "report.sarif.json").read_text(encoding="utf-8"))
            schema = json.loads(
                (Path(__file__).parents[1] / "schemas" / "report.schema.json").read_text(encoding="utf-8")
            )

        self.assertEqual(result, 2)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["summary"]["findings"], 1)
        self.assertIn("no safety conclusion", " ".join(report["warnings"]))
        self.assertIn("PY-SHELL-001", markdown)
        self.assertTrue(graph["nodes"])
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(set(schema["required"]).issubset(report))

    def test_analysis_limit_marks_audit_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            output = Path(temporary) / "reports"
            root.mkdir()
            source = "\n".join(
                f"def function_{index}():\n    return {index}"
                for index in range(201)
            )
            (root / "app.py").write_text(source, encoding="utf-8")

            result = main(
                [
                    "audit",
                    str(root),
                    "--offline",
                    "--no-cache",
                    "--output",
                    str(output),
                    "--format",
                    "json",
                ]
            )
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))

        python_analyzer = next(
            analyzer for analyzer in report["analyzers"]
            if analyzer["name"] == "python_ast_and_taint"
        )
        self.assertEqual(result, 2)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(python_analyzer["status"], "incomplete")
        self.assertTrue(any("bounded to 200 functions" in warning for warning in report["warnings"]))

    def test_invalid_remote_target_is_rejected_without_network_access(self) -> None:
        with self.assertRaisesRegex(ValueError, "public https://github.com"):
            with repository_target("https://example.com/owner/repository"):
                self.fail("Invalid hosts must not be cloned.")

    def test_public_github_url_shape_is_accepted(self) -> None:
        self.assertEqual(
            _validate_github_url("https://github.com/example/project.git"),
            "https://github.com/example/project.git",
        )

    def test_invalid_input_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = main(
                [
                    "audit",
                    str(Path(temporary) / "missing"),
                    "--output",
                    str(Path(temporary) / "reports"),
                ]
            )
        self.assertEqual(result, 1)

    def test_non_finite_timeout_is_rejected(self) -> None:
        with self.assertRaises(SystemExit) as result:
            main(["audit", ".", "--timeout", "nan"])
        self.assertEqual(result.exception.code, 2)

    def test_local_output_inside_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            root.mkdir()
            result = main(
                [
                    "audit",
                    str(root),
                    "--offline",
                    "--output",
                    str(root / "reports"),
                ]
            )
        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
