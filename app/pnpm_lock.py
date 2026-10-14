"""Trace production packages from a pnpm v9 project importer."""

from __future__ import annotations

from collections import deque
from typing import Any

from .lockfile import Dependency


def _key(name: str, reference: str) -> str:
    if reference.startswith(("link:", "workspace:", "file:", "github:", "git+", "http:")):
        raise ValueError(f"pnpm local or non-registry dependency {name} cannot be traced yet")
    if reference.startswith("npm:"):
        reference = reference[4:]
        if "@" not in reference:
            raise ValueError(f"Unsupported pnpm alias for {name}: {reference}")
        return reference
    return f"{name}@{reference}"


def _name_version(key: str) -> tuple[str, str]:
    base = key.split("(", 1)[0]
    if "@" not in base:
        raise ValueError(f"Invalid pnpm package key: {key}")
    name, version = base.rsplit("@", 1)
    if not name or not version:
        raise ValueError(f"Invalid pnpm package key: {key}")
    return name, version


def parse_pnpm_project(lockfile: dict[str, Any], importer: str) -> tuple[list[Dependency], list[tuple[str, str]]]:
    """Use the exact resolved keys in snapshots; never infer transitive versions."""
    if not str(lockfile.get("lockfileVersion", "")).startswith("9."):
        raise ValueError("Only pnpm-lock.yaml v9 is supported")
    importers = lockfile.get("importers")
    snapshots = lockfile.get("snapshots")
    if not isinstance(importers, dict) or importer not in importers or not isinstance(snapshots, dict):
        raise ValueError("pnpm lockfile needs importers and snapshots")
    root = importers[importer]
    if not isinstance(root, dict):
        raise ValueError("Invalid pnpm importer")
    queue: deque[tuple[str, str, str, bool]] = deque()
    for group in ("dependencies", "optionalDependencies"):
        for name, value in root.get(group, {}).items():
            if not isinstance(value, dict) or not isinstance(value.get("version"), str):
                raise ValueError(f"pnpm has no resolved version for {name}")
            queue.append(("", name, value["version"], True))
    rows: dict[str, Dependency] = {}
    edges: set[tuple[str, str]] = set()
    while queue:
        parent, requested_name, reference, direct = queue.popleft()
        key = _key(requested_name, reference)
        if key not in snapshots:
            raise ValueError(f"pnpm snapshot is missing for {key}")
        name, version = _name_version(key)
        edges.add((parent, key))
        if key in rows:
            continue
        rows[key] = Dependency(key, name, version, parent or None, direct)
        item = snapshots[key]
        if not isinstance(item, dict):
            raise ValueError(f"Invalid pnpm snapshot for {key}")
        for group in ("dependencies", "optionalDependencies"):
            for child_name, child_ref in item.get(group, {}).items():
                if not isinstance(child_ref, str):
                    raise ValueError(f"pnpm has no resolved version for {child_name}")
                queue.append((key, child_name, child_ref, False))
    return list(rows.values()), sorted(edges)
