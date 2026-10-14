"""Read only public GitHub repository evidence."""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx


REPO_SLUG = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


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


async def fetch_public_repo(repo: str) -> Snapshot:
    import json

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
        lock_bytes = await _content(client, repo, "package-lock.json", sha)
        if lock_bytes is None:
            raise ValueError("This MVP supports public npm repos with package-lock.json at the root")
        package_bytes = await _content(client, repo, "package.json", sha)
        manifest_bytes = await _content(client, repo, "blast-radius.json", sha)
        owners = None
        for owner_path in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
            owners = await _content(client, repo, owner_path, sha)
            if owners:
                break
    return Snapshot(
        repo=repo,
        sha=sha,
        lockfile=json.loads(lock_bytes),
        package_json=json.loads(package_bytes) if package_bytes else {},
        owner=_owner_from_codeowners(owners.decode("utf-8") if owners else None),
        services=_services_from_manifest(json.loads(manifest_bytes) if manifest_bytes else None),
        source=f"https://github.com/{repo}/tree/{sha}",
        lockfile_text=lock_bytes.decode("utf-8"),
    )
