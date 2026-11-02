from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .dependencies import normalize_name
from .models import Dependency, Finding, finding_id

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
MAX_OSV_QUERIES = 5_000
MAX_OSV_RESPONSE_BYTES = 5_000_000


class AdvisoryError(RuntimeError):
    """Raised when an advisory lookup cannot be completed reliably."""


def _severity(vulnerability: dict) -> str:
    database_specific = vulnerability.get("database_specific", {})
    if isinstance(database_specific, dict):
        value = database_specific.get("severity")
        if isinstance(value, str) and value.lower() in {"critical", "high", "medium", "low"}:
            return value.lower()
    severities = vulnerability.get("severity", [])
    if not isinstance(severities, list):
        return "unknown"
    for severity in severities:
        if isinstance(severity, dict):
            value = severity.get("score")
            if isinstance(value, str) and value.upper() in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                return value.lower()
    return "unknown"


def _fixed_versions(vulnerability: dict, ecosystem: str, name: str) -> list[str]:
    versions: set[str] = set()
    affected_items = vulnerability.get("affected", [])
    if not isinstance(affected_items, list):
        return []
    for affected in affected_items:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package", {})
        if not isinstance(package, dict):
            continue
        affected_ecosystem = package.get("ecosystem")
        if not isinstance(affected_ecosystem, str) or affected_ecosystem.lower() != ecosystem.lower():
            continue
        if normalize_name(str(package.get("name", ""))) != normalize_name(name):
            continue
        ranges = affected.get("ranges", [])
        if not isinstance(ranges, list):
            continue
        for version_range in ranges:
            if not isinstance(version_range, dict):
                continue
            events = version_range.get("events", [])
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    versions.add(event["fixed"])
    return sorted(versions)


def _references(vulnerability: dict) -> list[str]:
    references = vulnerability.get("references", [])
    if not isinstance(references, list):
        return []
    return sorted(
        {
            item["url"]
            for item in references
            if isinstance(item, dict)
            and isinstance(item.get("url"), str)
            and item["url"].startswith(("https://", "http://"))
        }
    )


def findings_from_vulnerabilities(
    dependency: Dependency,
    vulnerabilities: list[dict],
) -> list[Finding]:
    findings: list[Finding] = []
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        advisory_id = vulnerability.get("id")
        if not isinstance(advisory_id, str):
            continue
        summary = vulnerability.get("summary")
        description = summary if isinstance(summary, str) and summary else "The OSV database reports this version as affected."
        fixed_versions = _fixed_versions(vulnerability, dependency.ecosystem, dependency.name)
        remediation = (
            f"Upgrade to a fixed version: {', '.join(fixed_versions)}."
            if fixed_versions
            else "Review the advisory and update to a version confirmed to be outside the affected range."
        )
        findings.append(
            Finding(
                id=finding_id("dependency", "OSV", f"{advisory_id}:{dependency.key}"),
                rule_id="OSV",
                category="dependency",
                title=f"{advisory_id}: vulnerable dependency {dependency.name}@{dependency.version}",
                description=description,
                severity=_severity(vulnerability),
                status="confirmed",
                confidence=0.98,
                locations=[{"path": dependency.manifest, "line": None, "role": "dependency manifest"}],
                evidence=[
                    f"OSV returned advisory {advisory_id} for {dependency.ecosystem} package "
                    f"{dependency.name}@{dependency.version}.",
                    f"Dependency locator: {dependency.locator}.",
                ],
                remediation=remediation,
                references=_references(vulnerability),
                dependency={
                    "ecosystem": dependency.ecosystem,
                    "name": dependency.name,
                    "version": dependency.version,
                    "direct": dependency.direct,
                    "manifest": dependency.manifest,
                    "locator": dependency.locator,
                    "fixed_versions": fixed_versions,
                    "advisory_id": advisory_id,
                },
            )
        )
    return findings


def query_osv_batch(dependencies: list[Dependency], timeout: float = 10.0) -> dict[str, list[dict]]:
    unique: dict[tuple[str, str, str], Dependency] = {}
    for dependency in dependencies:
        unique[(dependency.ecosystem.lower(), normalize_name(dependency.name), dependency.version)] = dependency
    package_list = list(unique.values())
    if len(package_list) > MAX_OSV_QUERIES:
        raise AdvisoryError(f"OSV lookup limit exceeded ({MAX_OSV_QUERIES} unique package versions).")
    vulnerability_map: dict[str, list[dict]] = {}

    for offset in range(0, len(package_list), 100):
        chunk = package_list[offset : offset + 100]
        payload = {
            "queries": [
                {
                    "package": {"name": item.name, "ecosystem": item.ecosystem},
                    "version": item.version,
                }
                for item in chunk
            ]
        }
        request = Request(
            OSV_BATCH_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                body = response.read(MAX_OSV_RESPONSE_BYTES + 1)
                if len(body) > MAX_OSV_RESPONSE_BYTES:
                    raise AdvisoryError("OSV response exceeded the configured 5 MB limit.")
                document = json.loads(body.decode("utf-8"))
        except AdvisoryError:
            raise
        except (HTTPError, URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError) as error:
            raise AdvisoryError(f"OSV lookup failed: {error}") from error

        if not isinstance(document, dict):
            raise AdvisoryError("OSV returned a malformed JSON response.")
        results = document.get("results")
        if not isinstance(results, list) or len(results) != len(chunk):
            raise AdvisoryError("OSV returned an invalid query-batch response.")
        for dependency, item in zip(chunk, results, strict=True):
            if not isinstance(item, dict):
                raise AdvisoryError("OSV returned an invalid query result.")
            vulns = item.get("vulns", [])
            if not isinstance(vulns, list) or any(not isinstance(vuln, dict) for vuln in vulns):
                raise AdvisoryError("OSV returned an invalid vulnerability list.")
            vulnerability_map[dependency.key] = vulns

    return vulnerability_map
