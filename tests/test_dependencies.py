from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from repo_auditor.dependencies import analyze_dependencies


class DependencyParsingTests(unittest.TestCase):
    def test_requirements_only_queries_exact_pins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "requirements.txt").write_text(
                "requests==2.31.0\nflask>=3.0\n# ignored\n", encoding="utf-8"
            )
            result = analyze_dependencies(root, [root / "requirements.txt"])

        self.assertEqual([(item.name, item.version) for item in result.dependencies], [("requests", "2.31.0")])
        self.assertTrue(result.dependencies[0].direct)
        self.assertTrue(any("Unpinned" in warning for warning in result.warnings))

    def test_poetry_lock_creates_unambiguous_transitive_edge(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "pyproject.toml").write_text(
                '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "^2.31"\n',
                encoding="utf-8",
            )
            (root / "poetry.lock").write_text(
                '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
                '[package.dependencies]\nurllib3 = ">=1.21"\n\n'
                '[[package]]\nname = "urllib3"\nversion = "2.0.7"\n',
                encoding="utf-8",
            )
            result = analyze_dependencies(root, [root / "pyproject.toml", root / "poetry.lock"])

        self.assertEqual(len(result.dependencies), 2)
        requests = next(item for item in result.dependencies if item.name == "requests")
        urllib3 = next(item for item in result.dependencies if item.name == "urllib3")
        self.assertTrue(requests.direct)
        self.assertFalse(urllib3.direct)
        edge_pairs = {(edge.source, edge.target) for edge in result.edges}
        self.assertEqual(
            edge_pairs,
            {("project:root", requests.key), (requests.key, urllib3.key)},
        )

    def test_npm_lock_v3_records_direct_dependency_and_edge(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "package-lock.json"
            manifest.write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"dependencies": {"express": "^4.0.0"}},
                            "node_modules/express": {
                                "version": "4.18.2",
                                "dependencies": {"cookie": "^0.5.0"},
                            },
                            "node_modules/cookie": {"version": "0.5.0"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = analyze_dependencies(root, [manifest])

        express = next(item for item in result.dependencies if item.name == "express")
        cookie = next(item for item in result.dependencies if item.name == "cookie")
        self.assertTrue(express.direct)
        self.assertFalse(cookie.direct)
        self.assertIn((express.key, cookie.key), {(edge.source, edge.target) for edge in result.edges})

    def test_malformed_npm_json_is_reported_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "package-lock.json"
            manifest.write_text("[]", encoding="utf-8")
            result = analyze_dependencies(root, [manifest])
        self.assertEqual(result.dependencies, [])
        self.assertTrue(any("Invalid JSON structure" in warning for warning in result.warnings))

    def test_project_optional_and_poetry_group_dependencies_are_direct(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "pyproject.toml"
            path.write_text(
                '[project.optional-dependencies]\ntest = ["pytest==8.0.0"]\n'
                '[tool.poetry.group.dev.dependencies]\nruff = "0.3.0"\n',
                encoding="utf-8",
            )
            result = analyze_dependencies(root, [path])
        self.assertEqual(
            {(item.name, item.version, item.direct) for item in result.dependencies},
            {("pytest", "8.0.0", True), ("ruff", "0.3.0", True)},
        )

    def test_poetry_lock_without_project_metadata_keeps_directness_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "poetry.lock"
            path.write_text('[[package]]\nname = "requests"\nversion = "2.31.0"\n', encoding="utf-8")
            result = analyze_dependencies(root, [path])
        self.assertIsNone(result.dependencies[0].direct)


if __name__ == "__main__":
    unittest.main()
