from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


EXCLUDED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".mypy_cache",
    ".pytest_cache",
}
MAX_FILE_BYTES = 1_000_000
SOURCE_SUFFIXES = {".py"}
MANIFEST_NAMES = {"pyproject.toml", "poetry.lock", "package-lock.json"}


@dataclass(slots=True)
class Inventory:
    files: list[Path]
    source_files: list[Path]
    manifest_files: list[Path]
    excluded_count: int
    warnings: list[str]


def build_inventory(root: Path, max_files: int = 20_000) -> Inventory:
    files: list[Path] = []
    sources: list[Path] = []
    manifests: list[Path] = []
    warnings: list[str] = []
    excluded_count = 0

    def on_error(error: OSError) -> None:
        warnings.append(f"Could not inspect a repository directory: {error}")

    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False, onerror=on_error):
        current_path = Path(current)
        retained: list[str] = []
        for directory in sorted(directories):
            candidate = current_path / directory
            if directory in EXCLUDED_DIRECTORIES or candidate.is_symlink():
                excluded_count += 1
            else:
                retained.append(directory)
        directories[:] = retained

        for filename in sorted(filenames):
            path = current_path / filename
            if path.is_symlink():
                excluded_count += 1
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    excluded_count += 1
                    continue
            except OSError as error:
                warnings.append(f"Could not inspect {path.relative_to(root)}: {error}")
                continue

            if len(files) >= max_files:
                warnings.append(f"File limit reached ({max_files}); remaining files were not inventoried.")
                return Inventory(files, sources, manifests, excluded_count + 1, warnings)

            files.append(path)
            if path.suffix.lower() in SOURCE_SUFFIXES:
                sources.append(path)
            if path.name in MANIFEST_NAMES or (
                path.name.startswith("requirements") and path.suffix.lower() == ".txt"
            ):
                manifests.append(path)

    return Inventory(
        files=sorted(files),
        source_files=sorted(sources),
        manifest_files=sorted(manifests),
        excluded_count=excluded_count,
        warnings=warnings,
    )
