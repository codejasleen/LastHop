"""Bounded, static CommonJS/ESM import evidence for an npm parent package.

An absent static path is evidence about the inspected package entry only. It is
never proof that application code cannot execute a CLI or load a module dynamically.
"""

from __future__ import annotations

import io
import base64
import hashlib
import hmac
import json
import posixpath
import re
import tarfile
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from .sources import Snapshot


IMPORT = re.compile(r"\brequire\s*\(\s*['\"]([^'\"]+)['\"]\s*\)|\bimport\s*(?:[^;\n]*?\sfrom\s*)?['\"]([^'\"]+)['\"]")
JS_SUFFIXES = (".js", ".cjs", ".mjs")
MAX_ARCHIVE = 5_000_000
MAX_EXPANDED = 15_000_000


@dataclass(frozen=True)
class ModuleTrace:
    parent_path: str
    target_path: str
    package_name: str
    package_version: str
    source_url: str
    main: str
    bins: tuple[str, ...]
    files: tuple[str, ...]
    file_edges: tuple[tuple[str, str, int], ...]
    package_edges: tuple[tuple[str, int], ...]
    status: str
    evidence_file: str | None
    evidence_line: int | None


def _module_path(candidate: str, files: set[str], package_main: dict[str, str]) -> str | None:
    candidate = posixpath.normpath(candidate).lstrip("/")
    if candidate.startswith("../"):
        return None
    options = [candidate, *(candidate + suffix for suffix in JS_SUFFIXES)]
    if candidate in package_main:
        options.insert(0, posixpath.normpath(posixpath.join(candidate, package_main[candidate])))
    options.extend(f"{candidate}/index{suffix}" for suffix in JS_SUFFIXES)
    return next((path for path in options if path in files), None)


def _reachable(start: str, edges: tuple[tuple[str, str, int], ...]) -> set[str]:
    seen: set[str] = set()
    queue = [start]
    while queue:
        current = queue.pop()
        if current in seen:
            continue
        seen.add(current)
        queue.extend(dst for src, dst, _ in edges if src == current and dst not in seen)
    return seen


def trace_archive(data: bytes, parent_path: str, target_path: str, target_name: str, source_url: str) -> ModuleTrace:
    if len(data) > MAX_ARCHIVE:
        raise ValueError("Package archive exceeds the static analysis limit")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 1_500 or sum(member.size for member in members) > MAX_EXPANDED:
            raise ValueError("Package archive exceeds the static analysis limit")
        content: dict[str, bytes] = {}
        for member in members:
            if not member.isfile() or not member.name.startswith("package/") or member.size > 1_000_000:
                continue
            path = member.name[len("package/"):]
            if path.startswith("/") or ".." in path.split("/"):
                continue
            if path.endswith(JS_SUFFIXES) or path == "package.json" or path.endswith("/package.json") or path.startswith("bin/"):
                content[path] = archive.extractfile(member).read()
    package = json.loads(content["package.json"])
    files = {path for path in content if path != "package.json"}
    package_main: dict[str, str] = {}
    for path, raw in content.items():
        if path.endswith("/package.json"):
            try:
                package_main[posixpath.dirname(path)] = json.loads(raw).get("main", "index.js")
            except (ValueError, AttributeError):
                pass
    main = _module_path(package.get("main", "index.js"), files, package_main)
    if not main:
        raise ValueError("Package main entry could not be resolved")
    bin_value = package.get("bin") or {}
    raw_bins = [bin_value] if isinstance(bin_value, str) else list(bin_value.values()) if isinstance(bin_value, dict) else []
    bins = tuple(sorted({found for name in raw_bins if isinstance(name, str) if (found := _module_path(name, files, package_main))}))
    file_edges: set[tuple[str, str, int]] = set()
    package_edges: set[tuple[str, int]] = set()
    for path, raw in content.items():
        if path == "package.json":
            continue
        source = raw.decode("utf-8", "replace")
        for match in IMPORT.finditer(source):
            imported = match.group(1) or match.group(2)
            line = source.count("\n", 0, match.start()) + 1
            if imported == target_name or imported.startswith(target_name + "/"):
                package_edges.add((path, line))
            elif imported.startswith("."):
                resolved = _module_path(posixpath.join(posixpath.dirname(path), imported), files, package_main)
                if resolved:
                    file_edges.add((path, resolved, line))
    module_edges = tuple(sorted(file_edges))
    imports = tuple(sorted(package_edges))
    main_seen = _reachable(main, module_edges)
    cli_seen = set().union(*(_reachable(name, module_edges) for name in bins)) if bins else set()
    main_hit = next(((path, line) for path, line in imports if path in main_seen), None)
    cli_hit = next(((path, line) for path, line in imports if path in cli_seen), None)
    status = "runtime_static_path" if main_hit else "cli_only_static_path" if cli_hit else "no_static_path"
    evidence = main_hit or cli_hit
    return ModuleTrace(parent_path, target_path, package.get("name", ""), package.get("version", ""), source_url,
                       main, bins, tuple(sorted(files)), module_edges, imports, status,
                       evidence[0] if evidence else None, evidence[1] if evidence else None)


async def fetch_parent_trace(snapshot: Snapshot, parent_path: str, target_path: str, target_name: str) -> ModuleTrace:
    if snapshot.manager != "npm":
        raise ValueError("Module tracing currently supports npm lockfiles")
    package = snapshot.lockfile["packages"].get(parent_path, {})
    url = package.get("resolved", "")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "registry.npmjs.org" or not parsed.path.endswith(".tgz"):
        raise ValueError("Parent package has no supported public npm archive")
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        async with client.stream("GET", url) as response:
            response.raise_for_status()
            chunks = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > MAX_ARCHIVE:
                    raise ValueError("Package archive exceeds the static analysis limit")
                chunks.append(chunk)
    data = b"".join(chunks)
    integrity = package.get("integrity", "")
    algorithms = {"sha512", "sha384", "sha256", "sha1"}
    checks = [part.split("-", 1) for part in integrity.split() if "-" in part]
    checks = [(algorithm, value) for algorithm, value in checks if algorithm in algorithms]
    if not checks or not any(hmac.compare_digest(base64.b64encode(hashlib.new(algorithm, data).digest()).decode(), value)
                             for algorithm, value in checks):
        raise ValueError("Package archive does not match lockfile integrity")
    trace = trace_archive(data, parent_path, target_path, target_name, url)
    if trace.package_name != parent_path.rsplit("node_modules/", 1)[-1] or trace.package_version != package.get("version"):
        raise ValueError("Package archive identity differs from the committed lockfile")
    return trace
