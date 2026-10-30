from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Dependency, GraphEdge, GraphNode


PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
EXACT_REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)\s*$"
)
REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(slots=True)
class DependencyInventory:
    dependencies: list[Dependency] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    nodes: list[GraphNode] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    manifests_analyzed: int = 0


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _add_dependency(
    result: DependencyInventory,
    ecosystem: str,
    name: str,
    version: str,
    manifest: str,
    direct: bool,
    locator: str,
) -> None:
    result.dependencies.append(
        Dependency(
            ecosystem=ecosystem,
            name=name,
            version=version,
            manifest=manifest,
            direct=direct,
            locator=locator,
        )
    )


def _exact_pep508(specification: str) -> tuple[str, str] | None:
    requirement = specification.split(";", 1)[0].strip()
    match = EXACT_REQUIREMENT.fullmatch(requirement)
    if not match:
        return None
    return match.group(1), match.group(2)


def _pep508_name(specification: str) -> str | None:
    match = REQUIREMENT_NAME.match(specification)
    return match.group(1) if match else None


def _parse_requirements(path: Path, root: Path, result: DependencyInventory) -> None:
    relative = _relative(path, root)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        result.warnings.append(f"Could not read {relative}: {error}")
        return
    result.manifests_analyzed += 1
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http:", "https:")):
            if line:
                reason = "Requirement includes are not resolved" if line.startswith("-r") else "Unsupported requirement"
                result.warnings.append(f"{reason} at {relative}:{line_number}.")
            continue
        parsed = _exact_pep508(line)
        if parsed is None:
            result.warnings.append(
                f"Unpinned or unsupported requirement at {relative}:{line_number}; advisory matching skipped."
            )
            continue
        name, version = parsed
        if PACKAGE_NAME.fullmatch(name):
            _add_dependency(result, "PyPI", name, version, relative, True, f"{relative}:{line_number}")


def _poetry_direct_names(pyproject: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    project = pyproject.get("project", {})
    if not isinstance(project, dict):
        project = {}
    project_dependencies = project.get("dependencies", [])
    if isinstance(project_dependencies, list):
        for item in project_dependencies:
            if isinstance(item, str):
                name = _pep508_name(item)
                if name:
                    names.add(normalize_name(name))
    optional_dependencies = project.get("optional-dependencies", {})
    if isinstance(optional_dependencies, dict):
        for requirements in optional_dependencies.values():
            if isinstance(requirements, list):
                for item in requirements:
                    if isinstance(item, str):
                        name = _pep508_name(item)
                        if name:
                            names.add(normalize_name(name))
    tool = pyproject.get("tool", {})
    poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
    if isinstance(poetry, dict):
        dependencies = poetry.get("dependencies", {})
        if isinstance(dependencies, dict):
            names.update(normalize_name(name) for name in dependencies if name.lower() != "python")
        groups = poetry.get("group", {})
        if isinstance(groups, dict):
            for group in groups.values():
                if isinstance(group, dict) and isinstance(group.get("dependencies"), dict):
                    names.update(
                        normalize_name(name)
                        for name in group["dependencies"]
                        if name.lower() != "python"
                    )
    return names


def _parse_pyproject(path: Path, root: Path, result: DependencyInventory) -> set[str] | None:
    relative = _relative(path, root)
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        result.warnings.append(f"Could not parse {relative}: {error}")
        return None
    result.manifests_analyzed += 1
    direct_names = _poetry_direct_names(document)
    project = document.get("project", {})
    if not isinstance(project, dict):
        project = {}
        result.warnings.append(f"Invalid [project] structure in {relative}; project dependencies were skipped.")
    project_dependencies = project.get("dependencies", [])
    if not isinstance(project_dependencies, list):
        result.warnings.append(f"Invalid project.dependencies structure in {relative}.")
        project_dependencies = []
    for item in project_dependencies:
        if not isinstance(item, str):
            result.warnings.append(f"Unsupported project dependency declaration in {relative}.")
            continue
        parsed = _exact_pep508(item)
        if parsed:
            name, version = parsed
            _add_dependency(result, "PyPI", name, version, relative, True, f"{relative}:project.dependencies")
        else:
            result.warnings.append(f"Unpinned or unsupported dependency in {relative}; advisory matching skipped.")
    optional_dependencies = project.get("optional-dependencies", {})
    if isinstance(optional_dependencies, dict):
        for requirements in optional_dependencies.values():
            if not isinstance(requirements, list):
                result.warnings.append(f"Invalid optional dependency group in {relative}.")
                continue
            for item in requirements:
                if not isinstance(item, str):
                    continue
                parsed = _exact_pep508(item)
                if parsed:
                    _add_dependency(
                        result,
                        "PyPI",
                        parsed[0],
                        parsed[1],
                        relative,
                        True,
                        f"{relative}:project.optional-dependencies",
                    )
                else:
                    result.warnings.append(
                        f"Unpinned or unsupported optional dependency in {relative}; advisory matching skipped."
                    )
    elif "optional-dependencies" in project:
        result.warnings.append(f"Invalid project.optional-dependencies structure in {relative}.")

    tool = document.get("tool", {})
    poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
    dependencies = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}
    if isinstance(dependencies, dict):
        for name, specification in dependencies.items():
            if name.lower() == "python":
                continue
            version = specification.get("version") if isinstance(specification, dict) else specification
            if isinstance(version, str) and version.startswith("=="):
                version = version[2:].strip()
            elif isinstance(version, str) and not re.fullmatch(r"[0-9][A-Za-z0-9.+!_-]*", version):
                version = None
            if isinstance(version, str):
                _add_dependency(
                    result,
                    "PyPI",
                    name,
                    version,
                    relative,
                    True,
                    f"{relative}:tool.poetry.dependencies",
                )
            elif name.lower() != "python":
                result.warnings.append(f"Unpinned Poetry dependency {name} in {relative}.")
    elif isinstance(poetry, dict) and "dependencies" in poetry:
        result.warnings.append(f"Invalid Poetry dependencies structure in {relative}.")
    groups = poetry.get("group", {}) if isinstance(poetry, dict) else {}
    if isinstance(groups, dict):
        for group_name, group in groups.items():
            group_dependencies = group.get("dependencies", {}) if isinstance(group, dict) else {}
            if not isinstance(group_dependencies, dict):
                result.warnings.append(f"Invalid Poetry dependency group {group_name} in {relative}.")
                continue
            for name, specification in group_dependencies.items():
                version = specification.get("version") if isinstance(specification, dict) else specification
                if isinstance(version, str) and version.startswith("=="):
                    version = version[2:].strip()
                elif isinstance(version, str) and not re.fullmatch(r"[0-9][A-Za-z0-9.+!_-]*", version):
                    version = None
                if isinstance(version, str):
                    _add_dependency(
                        result,
                        "PyPI",
                        name,
                        version,
                        relative,
                        True,
                        f"{relative}:tool.poetry.group.{group_name}.dependencies",
                    )
                else:
                    result.warnings.append(f"Unpinned Poetry group dependency {name} in {relative}.")
    elif isinstance(poetry, dict) and "group" in poetry:
        result.warnings.append(f"Invalid Poetry group structure in {relative}.")
    return direct_names


def _parse_poetry_lock(
    path: Path,
    root: Path,
    result: DependencyInventory,
    direct_names: set[str],
    direct_names_known: bool,
) -> None:
    relative = _relative(path, root)
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        result.warnings.append(f"Could not parse {relative}: {error}")
        return
    result.manifests_analyzed += 1
    packages = document.get("package", [])
    if not isinstance(packages, list):
        result.warnings.append(f"Invalid package list in {relative}; lockfile entries were skipped.")
        return
    by_name: dict[str, list[dict[str, Any]]] = {}
    for package in packages:
        if not isinstance(package, dict):
            result.warnings.append(f"Invalid package entry in {relative}; entry was skipped.")
            continue
        name, version = package.get("name"), package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            result.warnings.append(f"Package without a name or version in {relative}.")
            continue
        package_dependencies = package.get("dependencies", {})
        if not isinstance(package_dependencies, dict):
            result.warnings.append(f"Invalid dependency list for {name}@{version} in {relative}.")
            package_dependencies = {}
        package_record = {"name": name, "version": version, "dependencies": package_dependencies}
        by_name.setdefault(normalize_name(name), []).append(package_record)
        _add_dependency(
            result,
            "PyPI",
            name,
            version,
            relative,
            normalize_name(name) in direct_names if direct_names_known else None,
            f"{relative}:{name}@{version}",
        )

    for package in packages:
        if not isinstance(package, dict):
            continue
        source = package.get("name")
        requirements = package.get("dependencies", {})
        source_version = package.get("version")
        if not isinstance(source, str) or not isinstance(source_version, str) or not isinstance(requirements, dict):
            continue
        source_id = f"pypi:{normalize_name(source)}@{source_version}"
        for target_name, constraint in requirements.items():
            candidates = by_name.get(normalize_name(str(target_name)), [])
            version_constraint = constraint.get("version") if isinstance(constraint, dict) else constraint
            if isinstance(version_constraint, str):
                exact_match = re.fullmatch(r"\s*==?\s*([0-9][A-Za-z0-9.+!_-]*)\s*", version_constraint)
                if exact_match:
                    candidates = [
                        candidate
                        for candidate in candidates
                        if candidate["version"] == exact_match.group(1)
                    ]
            if len(candidates) == 1:
                target = candidates[0]
                result.edges.append(
                    GraphEdge(
                        source=source_id,
                        target=f"pypi:{normalize_name(target['name'])}@{target['version']}",
                        kind="depends_on",
                        path=relative,
                    )
                )
            else:
                result.warnings.append(
                    f"Could not uniquely resolve locked dependency {target_name} from {source}@"
                    f"{source_version} in {relative}; graph edge omitted."
                )


def _parse_package_lock(path: Path, root: Path, result: DependencyInventory) -> None:
    relative = _relative(path, root)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        result.warnings.append(f"Could not parse {relative}: {error}")
        return
    if not isinstance(document, dict):
        result.warnings.append(f"Invalid JSON structure in {relative}; manifest was skipped.")
        return
    result.manifests_analyzed += 1
    packages = document.get("packages", {})
    if isinstance(packages, dict):
        package_records: dict[str, tuple[str, str]] = {}
        root_dependencies: set[str] = set()
        root_entry = packages.get("", {})
        root_dependencies_known = "" in packages and isinstance(root_entry, dict)
        if isinstance(root_entry, dict):
            root_deps = root_entry.get("dependencies", {})
            root_dev_deps = root_entry.get("devDependencies", {})
            if isinstance(root_deps, dict):
                root_dependencies.update(root_deps)
            elif "dependencies" in root_entry:
                root_dependencies_known = False
                result.warnings.append(f"Invalid root dependencies in {relative}; directness is unknown.")
            if isinstance(root_dev_deps, dict):
                root_dependencies.update(root_dev_deps)
            elif "devDependencies" in root_entry:
                root_dependencies_known = False
                result.warnings.append(f"Invalid root devDependencies in {relative}; directness is unknown.")

        for locator, package in packages.items():
            if not locator or not isinstance(package, dict) or not isinstance(package.get("version"), str):
                continue
            name = package.get("name")
            if not isinstance(name, str):
                marker = "node_modules/"
                name = locator.rsplit(marker, 1)[-1] if marker in locator else locator
            package_records[locator] = (name, package["version"])
            _add_dependency(
                result,
                "npm",
                name,
                package["version"],
                relative,
                (
                    normalize_name(name) in {normalize_name(value) for value in root_dependencies}
                    if root_dependencies_known
                    else None
                ),
                f"{relative}:{locator}",
            )

        by_name: dict[str, list[str]] = {}
        for locator, (name, _) in package_records.items():
            by_name.setdefault(normalize_name(name), []).append(locator)

        def find_package(parent: str, name: str) -> str | None:
            current = parent
            while current:
                candidate = f"{current}/node_modules/{name}"
                if candidate in package_records:
                    return candidate
                marker = "/node_modules/"
                current = current.rsplit(marker, 1)[0] if marker in current else ""
            root_candidate = f"node_modules/{name}"
            if root_candidate in package_records:
                return root_candidate
            matches = by_name.get(normalize_name(name), [])
            return matches[0] if len(matches) == 1 else None

        for locator, (name, _) in package_records.items():
            package = packages[locator]
            dependencies = package.get("dependencies", {})
            optional_dependencies = package.get("optionalDependencies", {})
            dependency_names = set(dependencies) if isinstance(dependencies, dict) else set()
            if isinstance(optional_dependencies, dict):
                dependency_names.update(optional_dependencies)
            for dependency_name in sorted(dependency_names):
                target_locator = find_package(locator, dependency_name)
                if target_locator is None:
                    result.warnings.append(
                        f"Could not resolve locked npm dependency {dependency_name} in {relative}."
                    )
                    continue
                target_name, target_version = package_records[target_locator]
                result.edges.append(
                    GraphEdge(
                        source=f"npm:{normalize_name(name)}@{package_records[locator][1]}",
                        target=f"npm:{normalize_name(target_name)}@{target_version}",
                        kind="depends_on",
                        path=relative,
                    )
                )
        return

    # npm lockfile v1 nests transitive packages under their parents.
    def visit_legacy(dependencies: Any, parent_id: str | None = None) -> None:
        if not isinstance(dependencies, dict):
            return
        for name, package in dependencies.items():
            if not isinstance(package, dict) or not isinstance(package.get("version"), str):
                continue
            version = package["version"]
            package_id = f"npm:{normalize_name(name)}@{version}"
            _add_dependency(
                result,
                "npm",
                name,
                version,
                relative,
                parent_id is None,
                f"{relative}:{name}@{version}",
            )
            if parent_id is not None:
                result.edges.append(
                    GraphEdge(parent_id, package_id, "depends_on", path=relative)
                )
            visit_legacy(package.get("dependencies"), package_id)

    legacy = document.get("dependencies")
    if isinstance(legacy, dict):
        visit_legacy(legacy)
    else:
        result.warnings.append(f"Unsupported npm lockfile structure in {relative}.")


def analyze_dependencies(root: Path, manifest_paths: list[Path]) -> DependencyInventory:
    result = DependencyInventory()
    direct_names_by_project: dict[Path, set[str] | None] = {}
    for path in manifest_paths:
        if path.name == "pyproject.toml":
            direct_names_by_project[path.parent] = _parse_pyproject(path, root, result)

    def nearest_project_dependencies(lock_path: Path) -> set[str] | None:
        parent = lock_path.parent
        while parent == root or root in parent.parents:
            if parent in direct_names_by_project:
                return direct_names_by_project[parent]
            if parent == root:
                break
            parent = parent.parent
        return None

    for path in manifest_paths:
        if path.name.startswith("requirements") and path.suffix.lower() == ".txt":
            _parse_requirements(path, root, result)
        elif path.name == "poetry.lock":
            direct_names = nearest_project_dependencies(path)
            _parse_poetry_lock(
                path,
                root,
                result,
                direct_names or set(),
                direct_names is not None,
            )
        elif path.name == "package-lock.json":
            _parse_package_lock(path, root, result)

    deduplicated: dict[tuple[str, str, str], Dependency] = {}
    for dependency in result.dependencies:
        key = (dependency.ecosystem, normalize_name(dependency.name), dependency.version)
        previous = deduplicated.get(key)
        if previous is None:
            deduplicated[key] = dependency
        else:
            direct_values = (previous.direct, dependency.direct)
            if True in direct_values:
                previous.direct = True
            elif all(value is False for value in direct_values):
                previous.direct = False
            else:
                previous.direct = None
            if dependency.manifest not in previous.manifest.split(", "):
                previous.manifest = f"{previous.manifest}, {dependency.manifest}"
    result.dependencies = sorted(
        deduplicated.values(),
        key=lambda item: (item.ecosystem.lower(), normalize_name(item.name), item.version),
    )
    if result.dependencies:
        result.nodes.append(GraphNode("project:root", "project", root.name))
    for dependency in result.dependencies:
        result.nodes.append(
            GraphNode(
                id=dependency.key,
                kind="dependency",
                label=f"{dependency.name}@{dependency.version}",
                attributes={
                    "ecosystem": dependency.ecosystem,
                    "direct": dependency.direct,
                    "manifest": dependency.manifest,
                },
            )
        )
        if dependency.direct:
            result.edges.append(
                GraphEdge(
                    source="project:root",
                    target=dependency.key,
                    kind="direct_dependency",
                    path=dependency.manifest.split(", ", 1)[0],
                )
            )
    result.edges = list(
        {
            (edge.source, edge.target, edge.kind, edge.path, edge.line): edge
            for edge in result.edges
        }.values()
    )
    return result
