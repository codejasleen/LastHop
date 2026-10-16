"""Positive evidence from pinned, direct Python requirements only."""

from __future__ import annotations

import re

from packaging.utils import canonicalize_name

from .lockfile import Dependency


PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9_.!+\-]*)$")


def parse_requirements(text: str) -> tuple[list[Dependency], list[tuple[str, str]]]:
    """Do not pretend a requirements file resolves transitive packages."""
    rows = {}
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip()
        if not entry or entry.startswith(("-r", "-c")):
            continue
        match = PIN.fullmatch(entry)
        if not match:
            continue
        name = canonicalize_name(match.group(1))
        version = match.group(2)
        rows[name] = Dependency(name, name, version, None, True)
    dependencies = list(rows.values())
    return dependencies, [("", row.path) for row in dependencies]
