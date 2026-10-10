"""Resolve npm lockfile package instances without mixing one repo's pins with another."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Dependency:
    path: str
    name: str
    version: str
    parent_path: str | None
    direct: bool


def _package_name(path: str) -> str:
    return path.rsplit("node_modules/", 1)[-1]


def _resolve(installed: set[str], parent_path: str, name: str) -> str | None:
    """Follow Node's upward node_modules resolution for a dependency name."""
    current = parent_path
    while True:
        candidate = f"{current}/node_modules/{name}" if current else f"node_modules/{name}"
        if candidate in installed:
            return candidate
        if not current:
            return None
        if "/node_modules/" in current:
            current = current.rsplit("/node_modules/", 1)[0]
        else:
            current = ""


def parse_lockfile(lockfile: dict[str, Any]) -> list[Dependency]:
    """Read lockfile v2/v3 `packages`; only production dependencies are traversed."""
    packages = lockfile.get("packages")
    if not isinstance(packages, dict) or "" not in packages:
        raise ValueError("A package-lock.json with a packages map (lockfile v2/v3) is required")
    installed = {path for path in packages if path}
    root = packages[""]
    rows: dict[str, Dependency] = {}
    queue: list[tuple[str, str, bool]] = [(name, "", True) for name in root.get("dependencies", {})]
    seen: set[str] = set()
    while queue:
        name, parent, direct = queue.pop(0)
        path = _resolve(installed, parent, name)
        if not path:
            raise ValueError(f"Lockfile has no installed package for {name} required by {parent or 'the root'}")
        package = packages[path]
        version = package.get("version")
        if not isinstance(version, str):
            raise ValueError(f"Lockfile has no version for {path}")
        if path not in rows:
            rows[path] = Dependency(path, _package_name(path), version, parent or None, direct)
        if path in seen:
            continue
        seen.add(path)
        for child_name in package.get("dependencies", {}):
            queue.append((child_name, path, False))
    return list(rows.values())


def edges_from_lockfile(lockfile: dict[str, Any], dependencies: list[Dependency]) -> list[tuple[str, str]]:
    """Return parent path -> child path; empty parent means the repo root."""
    packages = lockfile["packages"]
    installed = {item.path for item in dependencies}
    edges: set[tuple[str, str]] = set()
    for parent_path in [""] + [item.path for item in dependencies]:
        requested = packages[parent_path].get("dependencies", {})
        for name in requested:
            child = _resolve(installed, parent_path, name)
            if child:
                edges.add((parent_path, child))
    return sorted(edges)
