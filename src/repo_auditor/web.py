from __future__ import annotations

import json
import logging
import threading
import webbrowser
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit
from uuid import uuid4

from .advisory_cache import DEFAULT_TTL_SECONDS, default_cache_path
from .intake import repository_revision
from .reporting import write_reports
from .scanner import audit_repository

MAX_REQUEST_BYTES = 16_384
MAX_RETAINED_JOBS = 20
MAX_ACTIVE_JOBS = 4
MAX_WEB_FINDINGS = 200
REPORT_FILES = {
    "report.json": ("report.json", "application/json; charset=utf-8"),
    "report.md": ("report.md", "text/markdown; charset=utf-8"),
    "graph.json": ("graph.json", "application/json; charset=utf-8"),
}
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}
_WEB_ROOT = files("repo_auditor").joinpath("web")
_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class AuditJob:
    id: str
    status: str
    target: str
    offline: bool
    output: Path
    report: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        report = self.report
        if report is not None:
            report = {
                **report,
                "findings": report["findings"][:MAX_WEB_FINDINGS],
                "findings_total": len(report["findings"]),
                "findings_truncated": len(report["findings"]) > MAX_WEB_FINDINGS,
            }
        return {
            "id": self.id,
            "status": self.status,
            "target": self.target,
            "offline": self.offline,
            "report": report,
            "error": self.error,
        }


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, AuditJob] = {}
        self._lock = threading.Lock()

    def submit(self, target: str, output: Path, offline: bool) -> AuditJob:
        with self._lock:
            active_count = sum(job.status in {"queued", "running"} for job in self._jobs.values())
            if active_count >= MAX_ACTIVE_JOBS:
                raise RuntimeError("The local auditor is busy. Wait for a running audit to finish.")
            if len(self._jobs) >= MAX_RETAINED_JOBS:
                removable = next(
                    (job_id for job_id, job in self._jobs.items() if job.status not in {"queued", "running"}),
                    None,
                )
                if removable is None:
                    raise RuntimeError("The local audit history is full. Wait for a running audit to finish.")
                del self._jobs[removable]
            job = AuditJob(str(uuid4()), "queued", target, offline, output)
            self._jobs[job.id] = job
            worker = threading.Thread(target=self._run, args=(job.id,), daemon=True)
            worker.start()
            return job

    def get(self, job_id: str) -> AuditJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def _run(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job.status = "running"
        try:
            root = Path(job.target)
            report = audit_repository(
                root=root,
                target=job.target,
                revision=repository_revision(root),
                offline=job.offline,
                cache_path=default_cache_path(),
                cache_ttl_seconds=DEFAULT_TTL_SECONDS,
            )
            write_reports(report, job.output, {"json", "markdown"})
            result = report.to_dict()
        except (OSError, RuntimeError, ValueError) as error:
            with self._lock:
                job.status = "failed"
                job.error = str(error)
            return
        except Exception:
            _LOGGER.exception("Audit job %s failed unexpectedly", job_id)
            with self._lock:
                job.status = "failed"
                job.error = "An unexpected audit error occurred. Check the server terminal for details."
            return
        with self._lock:
            job.report = result
            job.status = "completed"


class LocalAuditServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port: int) -> None:
        self.jobs = JobStore()
        super().__init__(("127.0.0.1", port), _make_handler(self))


def _validate_target_and_output(target_value: Any, output_value: Any, offline_value: Any) -> tuple[Path, Path, bool]:
    if not isinstance(target_value, str) or not target_value.strip() or len(target_value) > 4096:
        raise ValueError("Enter a valid local repository folder path.")
    if not isinstance(output_value, str) or not output_value.strip() or len(output_value) > 4096:
        raise ValueError("Enter a valid report output folder path.")
    if not isinstance(offline_value, bool):
        raise ValueError("Offline mode must be enabled or disabled.")

    requested_root = Path(target_value.strip()).expanduser()
    if not requested_root.is_dir():
        raise ValueError("The target must be an existing local directory.")
    try:
        root = requested_root.resolve(strict=True)
        output = Path(output_value.strip()).expanduser().resolve()
    except (OSError, RuntimeError, ValueError) as error:
        raise ValueError(f"Could not resolve a supplied folder path: {error}") from error
    if not root.is_dir():
        raise ValueError("The target must be an existing local directory.")
    if output.is_relative_to(root):
        raise ValueError("Choose a report output folder outside the repository being audited.")
    return root, output, offline_value


def _make_handler(server: LocalAuditServer) -> type[BaseHTTPRequestHandler]:
    class AuditRequestHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _allowed_authority(self) -> bool:
            port = server.server_port
            return self.headers.get("Host", "").lower() in {
                f"127.0.0.1:{port}",
                f"localhost:{port}",
            }

        def _allowed_origin(self, required: bool = False) -> bool:
            origin = self.headers.get("Origin")
            if origin is None:
                return not required
            return origin in {
                f"http://127.0.0.1:{server.server_port}",
                f"http://localhost:{server.server_port}",
            }

        def _send_json(self, status: HTTPStatus, body: dict[str, Any]) -> None:
            encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
            if status >= HTTPStatus.BAD_REQUEST:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            self.wfile.write(encoded)

        def _send_text(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def _send_error_json(self, status: HTTPStatus, message: str) -> None:
            self._send_json(status, {"error": message})

        def do_GET(self) -> None:
            if not self._allowed_authority() or not self._allowed_origin():
                self._send_error_json(HTTPStatus.FORBIDDEN, "This local interface only accepts same-origin requests.")
                return
            parsed = urlsplit(self.path)
            if parsed.path == "/api/config":
                target = Path.cwd().resolve()
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "default_target": str(target),
                        "default_output": str(target.parent / "ps05-audit-output"),
                    },
                )
                return
            if parsed.path in STATIC_FILES:
                filename, content_type = STATIC_FILES[parsed.path]
                try:
                    body = _WEB_ROOT.joinpath(filename).read_bytes()
                except OSError as error:
                    self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, f"Could not read the web interface: {error}")
                    return
                self._send_text(HTTPStatus.OK, body, content_type)
                return

            parts = [unquote(part) for part in parsed.path.split("/") if part]
            if len(parts) == 3 and parts[0] == "api" and parts[1] == "audits":
                job = server.jobs.get(parts[2])
                if job is None:
                    self._send_error_json(HTTPStatus.NOT_FOUND, "Audit not found.")
                    return
                self._send_json(HTTPStatus.OK, job.to_dict())
                return
            if (
                len(parts) == 5
                and parts[0] == "api"
                and parts[1] == "audits"
                and parts[3] == "files"
                and parts[4] in REPORT_FILES
            ):
                job = server.jobs.get(parts[2])
                if job is None or job.status != "completed":
                    self._send_error_json(HTTPStatus.NOT_FOUND, "Completed audit report not found.")
                    return
                filename, content_type = REPORT_FILES[parts[4]]
                try:
                    body = (job.output / filename).read_bytes()
                except OSError as error:
                    self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, f"Could not read report file: {error}")
                    return
                self._send_text(HTTPStatus.OK, body, content_type)
                return
            self._send_error_json(HTTPStatus.NOT_FOUND, "Not found.")

        def do_POST(self) -> None:
            if not self._allowed_authority() or not self._allowed_origin(required=True):
                self._send_error_json(HTTPStatus.FORBIDDEN, "This local interface only accepts same-origin requests.")
                return
            if urlsplit(self.path).path != "/api/audits":
                self._send_error_json(HTTPStatus.NOT_FOUND, "Not found.")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_error_json(HTTPStatus.BAD_REQUEST, "Invalid request length.")
                return
            if length <= 0 or length > MAX_REQUEST_BYTES:
                self._send_error_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request body is empty or too large.")
                return
            try:
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError("Request body must be a JSON object.")
                root, output, offline = _validate_target_and_output(
                    body.get("target"),
                    body.get("output"),
                    body.get("offline", False),
                )
                job = server.jobs.submit(str(root), output, offline)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
                self._send_error_json(HTTPStatus.BAD_REQUEST, str(error))
                return
            except RuntimeError as error:
                self._send_error_json(HTTPStatus.SERVICE_UNAVAILABLE, str(error))
                return
            self._send_json(HTTPStatus.ACCEPTED, job.to_dict())

    return AuditRequestHandler


def run_web_server(port: int = 8765, open_browser: bool = True) -> int:
    try:
        server = LocalAuditServer(port)
    except OSError as error:
        print(f"ps05-audit web: could not start local server: {error}")
        return 1
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"PS05 Repository Auditor is running at {url}")
    print("Press Ctrl+C to stop the server.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping the local auditor.")
    finally:
        server.server_close()
    return 0
