from __future__ import annotations

import re
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator
from urllib.parse import urlsplit


GITHUB_PATH = re.compile(r"^/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")


def _validate_github_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or not GITHUB_PATH.fullmatch(parsed.path)
    ):
        raise ValueError("Remote targets must be public https://github.com/<owner>/<repository> URLs.")
    return value.rstrip("/")


@contextmanager
def repository_target(
    value: str,
    clone_timeout: float = 120.0,
) -> Generator[tuple[Path, str], None, None]:
    if value.startswith(("https://", "http://", "ssh://", "git@")):
        url = _validate_github_url(value)
        with tempfile.TemporaryDirectory(prefix="ps05-audit-") as temporary:
            checkout = Path(temporary) / "repository"
            command = [
                "git",
                "clone",
                "--depth",
                "1",
                "--no-recurse-submodules",
                "--",
                url,
                str(checkout),
            ]
            try:
                subprocess.run(
                    command,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=clone_timeout,
                )
            except FileNotFoundError as error:
                raise RuntimeError("Git is required to audit a GitHub URL.") from error
            except subprocess.TimeoutExpired as error:
                raise RuntimeError(f"GitHub clone exceeded {clone_timeout:g} seconds.") from error
            except subprocess.CalledProcessError as error:
                detail = (error.stderr or error.stdout or "git clone failed").strip()
                raise RuntimeError(f"Could not clone repository: {detail}") from error
            yield checkout, url
        return

    root = Path(value).expanduser().resolve()
    if not root.exists():
        raise ValueError(f"Target does not exist: {value}")
    if not root.is_dir():
        raise ValueError(f"Target must be a repository directory: {value}")
    yield root, str(root)


def repository_revision(root: Path, timeout: float = 5.0) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    revision = result.stdout.strip()
    return revision or None
