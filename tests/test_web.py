from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

from repo_auditor.web import AuditJob, LocalAuditServer, _validate_target_and_output


class WebInterfaceTests(unittest.TestCase):
    def test_completed_job_limits_browser_payload_to_keep_ui_responsive(self) -> None:
        job = AuditJob(
            id="audit-id",
            status="completed",
            target="repository",
            offline=False,
            output=Path("reports"),
            report={"findings": [{} for _ in range(201)], "summary": {"findings": 201}},
        )

        payload = job.to_dict()

        self.assertEqual(len(payload["report"]["findings"]), 200)
        self.assertEqual(payload["report"]["findings_total"], 201)
        self.assertTrue(payload["report"]["findings_truncated"])

    def test_target_validation_requires_local_existing_directory_and_safe_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            root.mkdir()
            output = Path(temporary) / "reports"
            self.assertEqual(
                _validate_target_and_output(str(root), str(output), True),
                (root.resolve(), output.resolve(), True),
            )
            with self.assertRaisesRegex(ValueError, "outside the repository"):
                _validate_target_and_output(str(root), str(root / "reports"), False)
            with self.assertRaisesRegex(ValueError, "existing local directory"):
                _validate_target_and_output(str(root / "missing"), str(output), False)
            with self.assertRaisesRegex(ValueError, "Offline mode"):
                _validate_target_and_output(str(root), str(output), "yes")

    def test_local_ui_serves_and_completes_an_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            output = Path(temporary) / "reports"
            root.mkdir()
            (root / "app.py").write_text(
                "def run(request):\n"
                "    value = request.args.get('cmd')\n"
                "    subprocess.run(value, shell=True)\n",
                encoding="utf-8",
            )
            server = LocalAuditServer(0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(thread.join, 2)
            self.addCleanup(server.shutdown)
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)

            connection.request("GET", "/")
            page = connection.getresponse()
            self.assertEqual(page.status, 200)
            self.assertIn("Create a security audit", page.read().decode("utf-8"))

            connection.request("GET", "/api/config")
            config_response = connection.getresponse()
            config = json.loads(config_response.read())
            self.assertEqual(config_response.status, 200)
            self.assertEqual(config["default_target"], str(Path.cwd().resolve()))
            self.assertEqual(config["default_output"], str(Path.cwd().resolve().parent / "ps05-audit-output"))

            payload = json.dumps(
                {"target": str(root), "output": str(output), "offline": True}
            )
            connection.request(
                "POST",
                "/api/audits",
                body=payload,
                headers={
                    "Content-Type": "application/json",
                    "Origin": f"http://127.0.0.1:{server.server_port}",
                },
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 202)
            job = json.loads(response.read())

            for _ in range(50):
                connection.request("GET", f"/api/audits/{job['id']}")
                status_response = connection.getresponse()
                result = json.loads(status_response.read())
                if result["status"] in {"completed", "failed"}:
                    break
                threading.Event().wait(0.05)

            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["report"]["summary"]["findings"], 1)
            self.assertTrue((output / "report.md").is_file())
            connection.request("GET", f"/api/audits/{job['id']}/files/report.md")
            report_response = connection.getresponse()
            self.assertEqual(report_response.status, 200)
            self.assertIn("PY-SHELL-001", report_response.read().decode("utf-8"))
            connection.close()

    def test_post_rejects_missing_or_foreign_origin(self) -> None:
        server = LocalAuditServer(0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        for origin in (None, "https://attacker.example"):
            headers = {"Content-Type": "application/json"}
            if origin is not None:
                headers["Origin"] = origin
            connection.request("POST", "/api/audits", body="{}", headers=headers)
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
        connection.close()


if __name__ == "__main__":
    unittest.main()
