"""Reviewable lockfile fix proposals and human-approved draft pull requests."""

from __future__ import annotations

import difflib
import copy
import json
import os
import secrets
import time
from dataclasses import dataclass
from urllib.parse import quote, urlparse

import httpx

from .advisories import Advisory, is_affected
from .lockfile import parse_lockfile
from .sources import Snapshot, fetch_public_repo


PROPOSALS: dict[str, "Proposal"] = {}


@dataclass
class Proposal:
    repo: str
    sha: str
    advisory: str
    advisory_url: str
    package: str
    before: str
    after: str
    lockfile_text: str
    path: list[str]
    expires_at: float


def lockfile_refresh_plan(snapshot: Snapshot, advisory: Advisory, name: str) -> dict:
    """Prove the patched version fits the immediate parent's declared range."""
    if snapshot.manager != "npm" or snapshot.project_path:
        raise ValueError("Automated lockfile refresh currently requires a root npm project")
    matches = [d for d in parse_lockfile(snapshot.lockfile) if d.name == name
               and any(p.name == name and is_affected(d.version, p.vulnerable_range) is True for p in advisory.packages)]
    if len(matches) != 1:
        raise ValueError("A lockfile refresh needs exactly one affected installed package instance")
    dep = matches[0]
    parent = snapshot.lockfile["packages"][dep.parent_path or ""]
    declared = parent.get("dependencies", {}).get(name) or parent.get("optionalDependencies", {}).get(name)
    if not declared:
        raise ValueError("The parent has no production dependency declaration for this package")
    target = _safe_target(advisory, name, dep.version)
    fits = is_affected(target, declared)
    return {"package": name, "before": dep.version, "target": target, "dependency_path": dep.path, "parent": dep.parent_path or "",
            "parent_name": dep.parent_path.rsplit("node_modules/", 1)[-1] if dep.parent_path else "repo",
            "declared_range": declared, "direct": dep.direct, "strategy": "lockfile_refresh" if fits is True else "parent_upgrade_needed"}


def _safe_target(advisory: Advisory, name: str, installed: str) -> str:
    matching = [p for p in advisory.packages if p.name == name and is_affected(installed, p.vulnerable_range) is True]
    patched = [p.first_patched for p in matching if p.first_patched]
    if not patched:
        raise ValueError("The advisory has no first patched version for this installed package")
    # Multiple affected ranges can describe different release lines. Use the
    # patched version belonging to the matching installed range.
    return patched[0]


async def build_preview(snapshot: Snapshot, advisory: Advisory, package: str, path: list[str]) -> tuple[str, dict]:
    if snapshot.repo.startswith("demo/"):
        raise ValueError("Synthetic demo repos cannot receive real pull requests")
    plan = lockfile_refresh_plan(snapshot, advisory, package)
    installed, target = plan["before"], plan["target"]
    if plan["strategy"] != "lockfile_refresh":
        raise ValueError(f"First patched version {target} falls outside {plan['parent_name']}'s declared range {plan['declared_range']}; review a parent upgrade")
    original = snapshot.lockfile_text or json.dumps(snapshot.lockfile, indent=2, ensure_ascii=False) + "\n"
    registry_url = f"https://registry.npmjs.org/{quote(package, safe='')}/{quote(target, safe='')}"
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        response = await client.get(registry_url)
        response.raise_for_status()
        metadata = response.json()
    if metadata.get("name") != package or metadata.get("version") != target:
        raise ValueError("Registry metadata does not match the proposed package and version")
    dist = metadata.get("dist", {})
    resolved, integrity = dist.get("tarball"), dist.get("integrity")
    parsed = urlparse(resolved or "")
    if parsed.scheme != "https" or parsed.hostname != "registry.npmjs.org" or not integrity:
        raise ValueError("Registry did not provide a verified public npm tarball")
    updated = copy.deepcopy(snapshot.lockfile)
    current = updated["packages"][plan["dependency_path"]]
    for field in ("dependencies", "optionalDependencies", "peerDependencies"):
        if (current.get(field) or {}) != (metadata.get(field) or {}):
            raise ValueError(f"Patched package changes {field}; review an npm-generated upgrade")
    current.update({"version": target, "resolved": resolved, "integrity": integrity})
    legacy = updated.get("dependencies")
    if isinstance(legacy, dict):
        found = []
        def visit(entries: dict) -> None:
            for name, entry in entries.items():
                if not isinstance(entry, dict):
                    continue
                if name == package and entry.get("version") == installed:
                    found.append(entry)
                if isinstance(entry.get("dependencies"), dict):
                    visit(entry["dependencies"])
        visit(legacy)
        if len(found) != 1:
            raise ValueError("Legacy lockfile section does not identify exactly one matching package")
        if (found[0].get("requires") or {}) != (metadata.get("dependencies") or {}):
            raise ValueError("Patched package changes dependencies; review an npm-generated upgrade")
        found[0].update({"version": target, "resolved": resolved, "integrity": integrity})
    indent = 4 if '\n    "name"' in original[:200] else 2
    updated_text = json.dumps(updated, indent=indent, ensure_ascii=False) + "\n"
    parse_lockfile(updated)
    remaining = [d for d in parse_lockfile(updated) if d.name == package]
    if not remaining or any(is_affected(d.version, p.vulnerable_range) is not False
                            for d in remaining for p in advisory.packages if p.name == package):
        raise ValueError("npm did not resolve every installed instance to a verified unaffected version")
    after = next((d.version for d in remaining if d.path == plan["dependency_path"]), remaining[0].version)
    if updated_text == original:
        raise ValueError("npm produced no lockfile change")
    diff_lines = list(difflib.unified_diff(original.splitlines(), updated_text.splitlines(), fromfile="a/package-lock.json", tofile="b/package-lock.json", lineterm=""))
    if len(diff_lines) > 1000:
        raise ValueError("The lockfile change is too large for the reviewable fix preview")
    preview_id = secrets.token_urlsafe(24)
    PROPOSALS[preview_id] = Proposal(snapshot.repo, snapshot.sha, advisory.identifier, advisory.url, package, installed, after, updated_text, path, time.time() + 1800)
    return preview_id, {"repo": snapshot.repo, "package": package, "before": installed, "after": after,
                        "strategy": "lockfile_refresh", "parent": plan["parent_name"], "declared_range": plan["declared_range"],
                        "diff": "\n".join(diff_lines), "truncated": False, "proposal_id": preview_id}


async def create_draft_pr(proposal_id: str, admin_key: str) -> str:
    expected = os.getenv("BLASTRADIUS_ADMIN_KEY")
    token = os.getenv("GITHUB_TOKEN")
    if not expected or not token:
        raise ValueError("Draft PR creation requires BLASTRADIUS_ADMIN_KEY and GITHUB_TOKEN on the server")
    if not secrets.compare_digest(admin_key, expected):
        raise PermissionError("Incorrect approval key")
    proposal = PROPOSALS.get(proposal_id)
    if not proposal or proposal.expires_at < time.time():
        raise ValueError("Fix proposal expired; review a fresh diff")
    current = await fetch_public_repo(proposal.repo)
    if current.sha != proposal.sha:
        raise ValueError("Repository changed since review; investigate and preview again")
    headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}", "User-Agent": "BlastRadius-demo"}
    repo = proposal.repo
    branch = f"blastradius/{proposal.advisory.lower()}-{secrets.token_hex(4)}"
    async with httpx.AsyncClient(timeout=20, headers=headers) as client:
        meta = await client.get(f"https://api.github.com/repos/{repo}")
        meta.raise_for_status()
        base = meta.json()["default_branch"]
        created = await client.post(f"https://api.github.com/repos/{repo}/git/refs", json={"ref": f"refs/heads/{branch}", "sha": proposal.sha})
        created.raise_for_status()
        file = await client.get(f"https://api.github.com/repos/{repo}/contents/package-lock.json", params={"ref": proposal.sha})
        file.raise_for_status()
        import base64
        updated = await client.put(
            f"https://api.github.com/repos/{repo}/contents/package-lock.json",
            json={
                "message": f"fix: update {proposal.package} for {proposal.advisory}",
                "content": base64.b64encode(proposal.lockfile_text.encode()).decode(),
                "sha": file.json()["sha"],
                "branch": branch,
            },
        )
        updated.raise_for_status()
        proof = " → ".join(proposal.path)
        body = (
            f"## BlastRadius investigation\n\nAdvisory: {proposal.advisory} ({proposal.advisory_url})\n\n"
            f"Dependency path: `{proof}`\n\nResolved `{proposal.package}` from `{proposal.before}` to `{proposal.after}`. "
            "Only `package-lock.json` changed. This is a draft for human review; run the repository's tests before merging.\n\n"
            "BlastRadius checks package and declared network reachability, not function-level code reachability."
        )
        response = await client.post(
            f"https://api.github.com/repos/{repo}/pulls",
            json={"title": f"fix: address {proposal.advisory} in {proposal.package}", "head": branch, "base": base, "body": body, "draft": True},
        )
        response.raise_for_status()
    del PROPOSALS[proposal_id]
    return response.json()["html_url"]
