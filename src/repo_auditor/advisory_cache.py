from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .dependencies import normalize_name
from .models import Dependency
from .osv import MAX_OSV_QUERIES, AdvisoryError, query_osv_batch

DEFAULT_TTL_SECONDS = 24 * 60 * 60


@dataclass(slots=True)
class AdvisoryLookup:
    vulnerabilities: dict[str, list[dict[str, Any]]]
    cache_hits: int
    network_queries: int
    missing: list[str]
    stale_entries: int


def default_cache_path() -> Path:
    cache_root = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME")
    if cache_root:
        return Path(cache_root) / "ps05-repository-auditor" / "osv-cache.sqlite3"
    return Path.home() / ".cache" / "ps05-repository-auditor" / "osv-cache.sqlite3"


def _unique_dependencies(dependencies: list[Dependency]) -> list[Dependency]:
    unique: dict[tuple[str, str, str], Dependency] = {}
    for dependency in dependencies:
        unique[(dependency.ecosystem.lower(), normalize_name(dependency.name), dependency.version)] = dependency
    return list(unique.values())


def _connect(cache_path: Path) -> sqlite3.Connection:
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(cache_path, timeout=5.0)
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS osv_cache (
                ecosystem TEXT NOT NULL,
                package_name TEXT NOT NULL,
                version TEXT NOT NULL,
                vulnerabilities_json TEXT NOT NULL,
                fetched_at REAL NOT NULL,
                PRIMARY KEY (ecosystem, package_name, version)
            )
            """
        )
        return connection
    except (OSError, sqlite3.Error) as error:
        raise AdvisoryError(f"Could not open OSV cache at {cache_path}: {error}") from error


def lookup_osv(
    dependencies: list[Dependency],
    cache_path: Path | None,
    offline: bool,
    timeout: float = 10.0,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> AdvisoryLookup:
    unique = _unique_dependencies(dependencies)
    if not unique:
        return AdvisoryLookup({}, 0, 0, [], 0)
    if len(unique) > MAX_OSV_QUERIES:
        raise AdvisoryError(f"OSV lookup limit exceeded ({MAX_OSV_QUERIES} unique package versions).")
    if timeout <= 0 or ttl_seconds < 0:
        raise ValueError("OSV timeout must be positive and cache TTL cannot be negative.")

    if cache_path is None:
        if offline:
            return AdvisoryLookup({}, 0, 0, [item.key for item in unique], 0)
        return AdvisoryLookup(
            query_osv_batch(unique, timeout=timeout),
            0,
            len(unique),
            [],
            0,
        )

    connection = _connect(cache_path)
    try:
        now = datetime.now(timezone.utc).timestamp()
        cached: dict[str, list[dict[str, Any]]] = {}
        stale_keys: set[str] = set()
        uncached: list[Dependency] = []
        try:
            for dependency in unique:
                row = connection.execute(
                    """
                    SELECT vulnerabilities_json, fetched_at
                    FROM osv_cache
                    WHERE ecosystem = ? AND package_name = ? AND version = ?
                    """,
                    (dependency.ecosystem.lower(), normalize_name(dependency.name), dependency.version),
                ).fetchone()
                if row is None:
                    uncached.append(dependency)
                    continue
                try:
                    vulnerability_list = json.loads(row[0])
                    age = max(0.0, now - float(row[1]))
                except (json.JSONDecodeError, TypeError, ValueError) as error:
                    raise AdvisoryError(f"OSV cache contains invalid JSON for {dependency.key}.") from error
                if not isinstance(vulnerability_list, list) or any(
                    not isinstance(item, dict) for item in vulnerability_list
                ):
                    raise AdvisoryError(f"OSV cache contains an invalid entry for {dependency.key}.")
                cached[dependency.key] = vulnerability_list
                if age > ttl_seconds:
                    stale_keys.add(dependency.key)
                    uncached.append(dependency)
        except sqlite3.Error as error:
            raise AdvisoryError(f"Could not read OSV cache at {cache_path}: {error}") from error

        if offline:
            missing = [item.key for item in uncached if item.key not in cached]
            return AdvisoryLookup(
                vulnerabilities=cached,
                cache_hits=len(cached),
                network_queries=0,
                missing=missing,
                stale_entries=len(stale_keys),
            )

        refresh_keys = {item.key for item in uncached}
        refresh = [item for item in unique if item.key in refresh_keys]
        network_results = query_osv_batch(refresh, timeout=timeout) if refresh else {}
        try:
            with connection:
                for dependency in refresh:
                    vulnerabilities = network_results.get(dependency.key)
                    if vulnerabilities is None:
                        raise AdvisoryError(f"OSV response did not contain a result for {dependency.key}.")
                    connection.execute(
                        """
                        INSERT INTO osv_cache (
                            ecosystem, package_name, version, vulnerabilities_json, fetched_at
                        ) VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(ecosystem, package_name, version) DO UPDATE SET
                            vulnerabilities_json = excluded.vulnerabilities_json,
                            fetched_at = excluded.fetched_at
                        """,
                        (
                            dependency.ecosystem.lower(),
                            normalize_name(dependency.name),
                            dependency.version,
                            json.dumps(vulnerabilities, separators=(",", ":"), ensure_ascii=False),
                            now,
                        ),
                    )
                    cached[dependency.key] = vulnerabilities
        except sqlite3.Error as error:
            raise AdvisoryError(f"Could not update OSV cache at {cache_path}: {error}") from error
        return AdvisoryLookup(
            vulnerabilities=cached,
            cache_hits=len(unique) - len(refresh),
            network_queries=len(refresh),
            missing=[],
            stale_entries=0,
        )
    finally:
        connection.close()
