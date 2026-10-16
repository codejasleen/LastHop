"""Positive evidence from pinned, direct Python requirements only."""

from __future__ import annotations

import re

from packaging.utils import canonicalize_name

from .lockfile import Dependency


PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9_.!+\-]*)$")
COMMENT = re.compile(r"(^|\s)#.*$")


def _entries(text: str):
    """Yield one requirement per logical line. pip-compile --generate-hashes writes
    `pkg==1.0 \\` followed by `--hash=...` lines, so continuations must be joined and
    options (`--hash`) and environment markers (`; python_version...`) dropped."""
    buffer = ""
    for raw in text.splitlines():
        line = COMMENT.sub("", raw).rstrip()
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        logical, buffer = (buffer + line).strip(), ""
        requirement = logical.split(";", 1)[0]
        yield " ".join(token for token in requirement.split() if not token.startswith("--")).strip()


REQUIREMENT_START = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*==")


def _via(text: str) -> dict[str, list[str]]:
    """pip-compile records why each pin exists: `# via requests`, or a `# via` line followed
    by indented `#   parent` lines. `-r requirements.in` means the project asked for it directly."""
    parents: dict[str, list[str]] = {}
    current, collecting = None, False
    for raw in text.splitlines():
        stripped = raw.strip()
        start = REQUIREMENT_START.match(raw)
        if start:
            current, collecting = canonicalize_name(start.group(1)), False
            parents.setdefault(current, [])
        elif stripped.startswith("#") and current:
            body = stripped.lstrip("#").strip()
            if body.startswith("via"):
                collecting = True
                if body[3:].strip():
                    parents[current].append(body[3:].strip())
            elif collecting and body:
                parents[current].append(body)
        elif stripped and not stripped.startswith("--"):
            collecting = False
    return parents


def parse_requirements(text: str) -> tuple[list[Dependency], list[tuple[str, str]]]:
    """Pins are positive evidence. Edges come from pip-compile `# via` comments when present;
    a pin with no recorded parent is treated as a direct requirement of the project."""
    rows = {}
    for entry in _entries(text):
        if not entry or entry.startswith(("-r", "-c", "-e")):
            continue
        match = PIN.fullmatch(entry)
        if not match:
            continue
        name = canonicalize_name(match.group(1))
        version = match.group(2)
        rows[name] = Dependency(name, name, version, None, True)
    dependencies = list(rows.values())
    via = _via(text)
    edges: list[tuple[str, str]] = []
    for row in dependencies:
        reasons = via.get(row.path, [])
        parents = [canonicalize_name(r.split()[0]) for r in reasons if not r.startswith("-")]
        parents = [p for p in parents if p in rows and p != row.path]
        if not parents or any(r.startswith(("-r", "-c")) for r in reasons):
            edges.append(("", row.path))
        edges.extend((parent, row.path) for parent in parents)
    return dependencies, edges
