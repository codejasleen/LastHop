"""Resolve production dependency paths from a Yarn Classic (v1) lockfile."""

from __future__ import annotations

import csv
import shlex
from collections import deque
from typing import Any

from .lockfile import Dependency


def _words(line: str) -> list[str]:
    try:
        return shlex.split(line)
    except ValueError as exc:
        raise ValueError("Invalid Yarn Classic lockfile quoting") from exc


def parse_yarn_project(text: str, package_json: dict[str, Any]) -> tuple[list[Dependency], list[tuple[str, str]]]:
    if "# yarn lockfile v1" not in text[:200].lower():
        raise ValueError("Only Yarn Classic yarn.lock v1 is supported")
    if package_json.get("workspaces"):
        raise ValueError("Yarn workspace lockfiles need workspace-aware traversal; no CVE verdict was made")
    selectors: dict[str, dict] = {}
    current: dict | None = None
    group: str | None = None
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if not line.startswith(" ") and line.endswith(":"):
            names = next(csv.reader([line[:-1]], skipinitialspace=True))
            current = {"version": None, "dependencies": {}}
            for name in names:
                selector = name.strip().strip('"')
                if selector in selectors:
                    raise ValueError(f"Duplicate Yarn selector: {selector}")
                selectors[selector] = current
            group = None
            continue
        if current is None:
            raise ValueError("Malformed Yarn Classic lockfile entry")
        if line.startswith("  ") and not line.startswith("    "):
            words = _words(line.strip().rstrip(":"))
            if not words:
                continue
            if words[0] == "version" and len(words) == 2:
                current["version"] = words[1]
            group = words[0] if line.strip().endswith(":") else None
            continue
        if line.startswith("    ") and group in ("dependencies", "optionalDependencies"):
            words = _words(line.strip())
            if len(words) != 2:
                raise ValueError("Malformed Yarn dependency declaration")
            current["dependencies"][words[0]] = words[1]
    queue: deque[tuple[str, str, str, bool]] = deque()
    for category in ("dependencies", "optionalDependencies"):
        for name, version_range in package_json.get(category, {}).items():
            queue.append(("", name, version_range, True))
    rows: dict[str, Dependency] = {}
    edges: set[tuple[str, str]] = set()
    while queue:
        parent, name, version_range, direct = queue.popleft()
        if not isinstance(version_range, str) or version_range.startswith(("file:", "link:", "workspace:", "git+")):
            raise ValueError(f"Yarn non-registry dependency {name} cannot be traced yet")
        selector = f"{name}@{version_range}"
        entry = selectors.get(selector)
        if entry is None or not isinstance(entry.get("version"), str):
            raise ValueError(f"Yarn lockfile has no exact resolution for {selector}")
        version = entry["version"]
        key = f"{name}@{version}"
        edges.add((parent, key))
        if key in rows:
            continue
        rows[key] = Dependency(key, name, version, parent or None, direct)
        for child, child_range in entry["dependencies"].items():
            queue.append((key, child, child_range, False))
    return list(rows.values()), sorted(edges)
