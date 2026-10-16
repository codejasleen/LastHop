"""Read only public GitHub repository evidence."""

from __future__ import annotations

import base64
import io
import os
import re
import json
import zipfile
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

import httpx
import yaml


REPO_SLUG = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_project_cache: dict[str, tuple[float, list[Snapshot]]] = {}


def normalize_repo(repo: str) -> str:
    """Accept an owner/name slug or a GitHub repository URL."""
    repo = repo.strip()
    if repo.startswith("https://"):
        parsed = urlparse(repo)
        if parsed.netloc.lower() != "github.com" or parsed.username or parsed.password:
            raise ValueError("Enter a public github.com repository URL or owner/name")
        repo = parsed.path.strip("/")
        if repo.endswith(".git"):
            repo = repo[:-4]
    if not REPO_SLUG.fullmatch(repo):
        raise ValueError("Repository must be owner/name or https://github.com/owner/name")
    return repo


@dataclass(frozen=True)
class Snapshot:
    repo: str
    sha: str
    lockfile: dict[str, Any]
    package_json: dict[str, Any]
    owner: str | None
    services: list[dict[str, Any]]
    source: str
    lockfile_text: str | None = None
    manager: str = "npm"
    project_path: str = ""
    importer: str = "."
    lockfile_path: str = "package-lock.json"
    other_manifests: tuple[str, ...] = ()
    deployments: tuple[dict[str, Any], ...] = ()


def _headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "BlastRadius-demo"}
    if token := os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _content(client: httpx.AsyncClient, repo: str, path: str, ref: str) -> bytes | None:
    response = await client.get(f"https://api.github.com/repos/{repo}/contents/{path}", params={"ref": ref})
    if response.status_code == 404:
        return None
    response.raise_for_status()
    payload = response.json()
    if payload.get("size", 0) > 5_000_000:
        raise ValueError(f"{path} is too large for the importer (5 MB limit)")
    if payload.get("encoding") == "none" and payload.get("sha"):
        blob = await client.get(f"https://api.github.com/repos/{repo}/git/blobs/{payload['sha']}")
        blob.raise_for_status()
        payload = blob.json()
    if payload.get("encoding") != "base64":
        raise ValueError(f"GitHub did not return inline content for {path}")
    data = base64.b64decode(payload["content"])
    if len(data) > 5_000_000:
        raise ValueError(f"{path} is too large for the demo importer")
    return data


def _owner_from_codeowners(text: str | None) -> str | None:
    if not text:
        return None
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2 and parts[0] in ("*", "/"):
            return parts[1]
    return None


def _services_from_manifest(data: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not data:
        return []
    services = data.get("services", [])
    if not isinstance(services, list):
        raise ValueError("blast-radius.json services must be a list")
    parsed = []
    for service in services:
        name = service.get("name")
        route = service.get("public_route")
        exposure = service.get("exposure", "unknown")
        if not isinstance(name, str) or not name.strip():
            continue
        if exposure not in ("public", "internal", "unknown"):
            exposure = "unknown"
        if exposure == "public" and not isinstance(route, str):
            exposure = "unknown"
        parsed.append({"name": name[:100], "exposure": exposure, "public_route": route if isinstance(route, str) else None})
    return parsed[:20]


async def _fetch_public_projects_api(repo: str) -> list[Snapshot]:
    """Use GitHub's API when its public rate limit permits."""
    repo = normalize_repo(repo)
    async with httpx.AsyncClient(timeout=15, headers=_headers(), follow_redirects=False) as client:
        metadata = await client.get(f"https://api.github.com/repos/{repo}")
        metadata.raise_for_status()
        info = metadata.json()
        if info.get("private"):
            raise ValueError("Only public repositories may be imported")
        branch = info["default_branch"]
        sha_response = await client.get(f"https://api.github.com/repos/{repo}/commits/{branch}")
        sha_response.raise_for_status()
        sha = sha_response.json()["sha"]
        tree_response = await client.get(f"https://api.github.com/repos/{repo}/git/trees/{sha}", params={"recursive": 1})
        tree_response.raise_for_status()
        tree = tree_response.json()
        if tree.get("truncated"):
            raise ValueError("GitHub truncated this repository's file tree; a complete dependency search is unavailable")
        paths = {
            row["path"] for row in tree.get("tree", [])
            if row.get("type") == "blob" and not any(part in ("node_modules", "vendor") for part in row["path"].split("/"))
        }
        async def read_file(path: str) -> bytes | None:
            return await _content(client, repo, path, sha)

        return await _snapshots_from_files(repo, sha, paths, read_file)


async def _snapshots_from_files(
    repo: str, sha: str, paths: set[str], read_file: Callable[[str], Awaitable[bytes | None]]
) -> list[Snapshot]:
    from .deployments import parse_kubernetes
    excluded = {"node_modules", "vendor", "testdata", "fixtures", "__fixtures__"}
    paths = {path for path in paths if not excluded.intersection(path.split("/"))}
    other_manifests = tuple(sorted(paths.intersection({
        "go.mod", "Cargo.lock", "poetry.lock", "uv.lock", "Gemfile.lock", "pom.xml"
    })))
    locks: dict[str, tuple[str, str]] = {}
    ambiguous: set[str] = set()
    for path in sorted(paths):
        filename = path.rsplit("/", 1)[-1]
        if filename not in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
            continue
        folder = path.rpartition("/")[0]
        if folder in locks and locks[folder][0] != filename:
            ambiguous.add(folder or ".")
        else:
            locks[folder] = (filename, path)
    if ambiguous:
        raise ValueError(f"Multiple package-manager lockfiles in {', '.join(sorted(ambiguous))}; choose one lockfile before scanning")
    requirements = sorted(path for path in paths if path.rsplit("/", 1)[-1] == "requirements.txt")
    if not locks and not requirements:
        detail = f" Found {', '.join(other_manifests)} at the root." if other_manifests else ""
        raise ValueError("No supported npm, pnpm, Yarn lockfile or Python requirements.txt was found; no CVE verdict was made." + detail)
    if len(locks) > 20:
        raise ValueError("More than 20 lockfiles found; narrow project selection is not supported yet")
    if len(locks) + len(requirements) > 30:
        raise ValueError("More than 30 manifests found; narrow project selection is not supported yet")
    owners = None
    for owner_path in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
        if owner_path not in paths:
            continue
        owners = await read_file(owner_path)
        if owners:
            break
    owner = _owner_from_codeowners(owners.decode("utf-8") if owners else None)
    kubernetes_paths = sorted(path for path in paths if path.endswith((".yaml", ".yml")) and
                              any(part in ("kubernetes-manifests", "k8s", "kubernetes", "deploy") for part in path.split("/")))
    if len(kubernetes_paths) > 60:
        raise ValueError("More than 60 Kubernetes manifests found; deployment evidence is incomplete")
    kubernetes_files = {}
    for path in kubernetes_paths:
        content = await read_file(path)
        if content is not None:
            kubernetes_files[path] = content.decode("utf-8", errors="replace")
    deployments = tuple(parse_kubernetes(kubernetes_files))
    results: list[Snapshot] = []
    for folder, (filename, lock_path) in sorted(locks.items()):
        lock_bytes = await read_file(lock_path)
        if lock_bytes is None:
            raise ValueError(f"Lockfile disappeared at {lock_path}; retry the scan")
        manager = {"package-lock.json": "npm", "pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn"}[filename]
        if manager == "npm":
            lockfile = json.loads(lock_bytes)
            importers = ["."]
        elif manager == "pnpm":
            documents = list(yaml.safe_load_all(lock_bytes))
            if not documents or not isinstance(documents[-1], dict):
                raise ValueError(f"Invalid pnpm lockfile at {lock_path}")
            lockfile = documents[-1]
            importers = list(lockfile.get("importers", {}))
        else:
            lockfile = {}
            importers = ["."]
        if len(importers) + len(results) > 30:
            raise ValueError("More than 30 projects found; narrow project selection is not supported yet")
        for importer in importers:
            if importer.startswith("/") or ".." in importer.split("/"):
                raise ValueError(f"Invalid pnpm importer path: {importer}")
            project_path = "/".join(part for part in (folder, importer if importer != "." else "") if part)
            package_path = f"{project_path}/package.json" if project_path else "package.json"
            manifest_path = f"{project_path}/blast-radius.json" if project_path else "blast-radius.json"
            package_bytes = await read_file(package_path) if package_path in paths else None
            if manager == "yarn" and package_bytes is None:
                raise ValueError(f"Yarn project at {project_path or '.'} needs package.json to identify production dependencies")
            manifest_bytes = await read_file(manifest_path) if manifest_path in paths else None
            results.append(Snapshot(
                repo=repo if not project_path else f"{repo}::{project_path}",
                sha=sha,
                lockfile=lockfile,
                package_json=json.loads(package_bytes) if package_bytes else {},
                owner=owner,
                services=_services_from_manifest(json.loads(manifest_bytes) if manifest_bytes else None),
                source=f"https://github.com/{repo}/tree/{sha}" + (f"/{project_path}" if project_path else ""),
                lockfile_text=lock_bytes.decode("utf-8"),
                manager=manager,
                project_path=project_path,
                importer=importer,
                lockfile_path=lock_path,
                other_manifests=other_manifests,
                deployments=deployments,
            ))
    for requirement_path in requirements:
        folder = requirement_path.rpartition("/")[0]
        body = await read_file(requirement_path)
        if body is None:
            raise ValueError(f"Requirements file disappeared at {requirement_path}; retry the scan")
        project_id = f"{repo}::{folder or 'root'}#pip"
        results.append(Snapshot(
            repo=project_id, sha=sha, lockfile={}, package_json={}, owner=owner, services=[],
            source=f"https://github.com/{repo}/blob/{sha}/{requirement_path}",
            lockfile_text=body.decode("utf-8", errors="replace"), manager="pip",
            project_path=folder, lockfile_path=requirement_path,
            other_manifests=other_manifests, deployments=deployments,
        ))
    if not results:
        raise ValueError("No supported projects were found in the lockfiles")
    return results


async def _fetch_public_projects_archive(repo: str) -> list[Snapshot]:
    """Use a bounded public source archive when GitHub's API quota is exhausted."""
    async with httpx.AsyncClient(timeout=40, follow_redirects=False, headers={"User-Agent": "BlastRadius-demo"}) as client:
        async with client.stream("GET", f"https://codeload.github.com/{repo}/zip/HEAD") as response:
            response.raise_for_status()
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > 30_000_000:
                    raise ValueError("Public source archive exceeds the 30 MB scan limit")
                chunks.append(chunk)
    with zipfile.ZipFile(io.BytesIO(b"".join(chunks))) as archive:
        sha = archive.comment.decode("ascii", errors="ignore")
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError("Source archive did not identify its commit SHA; no scan was made")
        entries: dict[str, zipfile.ZipInfo] = {}
        members = archive.infolist()
        if len(members) > 50_000:
            raise ValueError("Public source archive has too many files")
        for member in members:
            if member.is_dir() or "/" not in member.filename:
                continue
            path = member.filename.split("/", 1)[1]
            if path:
                entries[path] = member

        async def read_file(path: str) -> bytes | None:
            member = entries.get(path)
            if member is None:
                return None
            if member.file_size > 5_000_000:
                raise ValueError(f"{path} is too large for the importer (5 MB limit)")
            return archive.read(member)

        return await _snapshots_from_files(repo, sha, set(entries), read_file)


async def fetch_public_projects(repo: str, *, force_refresh: bool = True) -> list[Snapshot]:
    repo = normalize_repo(repo)
    cached = _project_cache.get(repo)
    if not force_refresh and cached and time.monotonic() - cached[0] < 120:
        return cached[1]
    try:
        result = await _fetch_public_projects_api(repo)
    except httpx.HTTPStatusError as exc:
        limited = exc.response.headers.get("X-RateLimit-Remaining") == "0" or "rate limit" in exc.response.text.lower()
        if exc.response.status_code == 429 or (exc.response.status_code == 403 and limited):
            result = await _fetch_public_projects_archive(repo)
        else:
            raise
    _project_cache[repo] = (time.monotonic(), result)
    return result


async def fetch_public_repo(repo: str) -> Snapshot:
    """Return a root npm project for the current root-only draft PR workflow."""
    projects = await fetch_public_projects(repo)
    match = next((item for item in projects if not item.project_path and item.manager == "npm"), None)
    if match is None:
        raise ValueError("Automated draft PRs currently require a root npm package-lock.json")
    return match
