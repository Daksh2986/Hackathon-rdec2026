from __future__ import annotations

import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

from repo_auditor.models import Dependency
from repo_auditor.advisory_cache import lookup_osv
from repo_auditor.osv import AdvisoryError, findings_from_vulnerabilities, query_osv_batch


class OsvTests(unittest.TestCase):
    def test_maps_osv_response_to_confirmed_evidence_finding(self) -> None:
        dependency = Dependency("PyPI", "requests", "2.0", "requirements.txt", True, "requirements.txt:1")
        findings = findings_from_vulnerabilities(
            dependency,
            [
                {
                    "id": "GHSA-example",
                    "summary": "Example advisory",
                    "database_specific": {"severity": "HIGH"},
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "requests"},
                            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.1"}]}],
                        }
                    ],
                    "references": [{"url": "https://example.test/advisory"}],
                }
            ],
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "confirmed")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].dependency["fixed_versions"], ["2.1"])
        self.assertEqual(findings[0].references, ["https://example.test/advisory"])

    def test_batch_client_maps_results_to_packages(self) -> None:
        dependency = Dependency("npm", "express", "4.18.2", "package-lock.json", True, "node_modules/express")
        response = io.BytesIO(json.dumps({"results": [{"vulns": [{"id": "GHSA-test"}]}]}).encode())
        with patch("repo_auditor.osv.urlopen", return_value=response):
            results = query_osv_batch([dependency])
        self.assertEqual(results[dependency.key], [{"id": "GHSA-test"}])

    def test_batch_client_surfaces_invalid_response(self) -> None:
        dependency = Dependency("npm", "express", "4.18.2", "package-lock.json", True, "node_modules/express")
        response = io.BytesIO(b"{}")
        with patch("repo_auditor.osv.urlopen", return_value=response):
            with self.assertRaises(AdvisoryError):
                query_osv_batch([dependency])

    def test_batch_client_surfaces_network_errors(self) -> None:
        dependency = Dependency("npm", "express", "4.18.2", "package-lock.json", True, "node_modules/express")
        with patch("repo_auditor.osv.urlopen", side_effect=URLError("network unavailable")):
            with self.assertRaisesRegex(AdvisoryError, "OSV lookup failed"):
                query_osv_batch([dependency])

    def test_online_result_is_cached_for_offline_reuse(self) -> None:
        dependency = Dependency("npm", "express", "4.18.2", "package-lock.json", True, "node_modules/express")
        response = io.BytesIO(json.dumps({"results": [{"vulns": []}]}).encode())
        with tempfile.TemporaryDirectory() as temporary:
            cache_path = Path(temporary) / "cache" / "osv.sqlite3"
            with patch("repo_auditor.osv.urlopen", return_value=response):
                online = lookup_osv([dependency], cache_path, offline=False)
            with patch("repo_auditor.osv.urlopen", side_effect=AssertionError("offline must not use the network")):
                offline = lookup_osv([dependency], cache_path, offline=True)

        self.assertEqual(online.network_queries, 1)
        self.assertEqual(online.cache_hits, 0)
        self.assertEqual(offline.network_queries, 0)
        self.assertEqual(offline.cache_hits, 1)
        self.assertEqual(offline.missing, [])
        self.assertEqual(offline.vulnerabilities[dependency.key], [])

    def test_offline_cache_miss_and_stale_entry_are_explicit(self) -> None:
        dependency = Dependency("PyPI", "requests", "2.31.0", "requirements.txt", True, "requirements.txt:1")
        with tempfile.TemporaryDirectory() as temporary:
            cache_path = Path(temporary) / "cache.sqlite3"
            empty = lookup_osv([dependency], cache_path, offline=True)
            with patch(
                "repo_auditor.osv.urlopen",
                return_value=io.BytesIO(json.dumps({"results": [{"vulns": []}]}).encode()),
            ):
                lookup_osv([dependency], cache_path, offline=False)
            connection = sqlite3.connect(cache_path)
            try:
                connection.execute("UPDATE osv_cache SET fetched_at = 0")
                connection.commit()
            finally:
                connection.close()
            stale = lookup_osv([dependency], cache_path, offline=True)

        self.assertEqual(empty.missing, [dependency.key])
        self.assertEqual(stale.stale_entries, 1)
        self.assertEqual(stale.missing, [])


if __name__ == "__main__":
    unittest.main()
