from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

from . import __version__
from .advisory_cache import DEFAULT_TTL_SECONDS, default_cache_path
from .intake import repository_revision, repository_target
from .reporting import write_reports
from .scanner import audit_repository


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ps05-audit",
        description="Read-only dependency and Python source audit for local repositories or public GitHub URLs.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    audit = subparsers.add_parser("audit", help="Audit a local repository or public GitHub URL.")
    audit.add_argument("target", help="Local repository directory or https://github.com/<owner>/<repo> URL.")
    audit.add_argument("--output", type=Path, default=Path("audit-output"), help="Directory for generated reports.")
    audit.add_argument(
        "--format",
        nargs="+",
        choices=("json", "markdown", "sarif"),
        default=["json", "markdown"],
        help="Report formats to write (graph.json is always included).",
    )
    audit.add_argument(
        "--offline",
        action="store_true",
        help="Use cached OSV results only; report missing or stale advisory coverage.",
    )
    audit.add_argument(
        "--cache-file",
        type=Path,
        default=default_cache_path(),
        help="SQLite OSV cache location.",
    )
    audit.add_argument("--no-cache", action="store_true", help="Disable the persistent OSV cache.")
    audit.add_argument(
        "--cache-ttl-hours",
        type=float,
        default=DEFAULT_TTL_SECONDS / 3600,
        help="Maximum age of an online cache entry before refreshing it (default: 24).",
    )
    audit.add_argument("--timeout", type=float, default=10.0, help="OSV request timeout in seconds (default: 10).")
    audit.add_argument("--max-files", type=int, default=20_000, help="Maximum files to inventory.")
    web = subparsers.add_parser("web", help="Start the local browser interface.")
    web.add_argument("--port", type=int, default=8765, help="Local web interface port (default: 8765).")
    web.add_argument("--no-browser", action="store_true", help="Do not open a browser automatically.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    if arguments.command == "web":
        if not 1 <= arguments.port <= 65535:
            parser.error("--port must be between 1 and 65535.")
        from .web import run_web_server

        return run_web_server(arguments.port, open_browser=not arguments.no_browser)
    if not math.isfinite(arguments.timeout) or arguments.timeout <= 0:
        parser.error("--timeout must be a finite number greater than zero.")
    if arguments.max_files <= 0:
        parser.error("--max-files must be greater than zero.")
    if not math.isfinite(arguments.cache_ttl_hours) or arguments.cache_ttl_hours <= 0:
        parser.error("--cache-ttl-hours must be a finite number greater than zero.")

    try:
        with repository_target(arguments.target) as (root, display_target):
            is_remote = arguments.target.startswith(("https://", "http://", "ssh://", "git@"))
            output_path = arguments.output.resolve()
            if not is_remote and output_path.is_relative_to(root.resolve()):
                raise ValueError("Report output must be outside the audited local repository.")
            report = audit_repository(
                root=root,
                target=display_target,
                revision=repository_revision(root),
                offline=arguments.offline,
                advisory_timeout=arguments.timeout,
                max_files=arguments.max_files,
                cache_path=None if arguments.no_cache else arguments.cache_file,
                cache_ttl_seconds=int(arguments.cache_ttl_hours * 3600),
            )
        written = write_reports(report, arguments.output, set(arguments.format))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ps05-audit: error: {error}", file=sys.stderr)
        return 1

    for path in written:
        print(f"Wrote {path}")
    print(
        f"Audit {report.status}: {report.summary['findings']} finding(s), "
        f"{report.summary['files_discovered']} file(s) inventoried."
    )
    return 2 if report.status == "partial" else 0


if __name__ == "__main__":
    raise SystemExit(main())
