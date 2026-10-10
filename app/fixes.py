"""Reviewable lockfile fix proposals and human-approved draft pull requests."""

from __future__ import annotations

import difflib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from .advisories import Advisory, is_affected
from .lockfile import parse_lockfile
from .sources import Snapshot, fetch_public_repo


ROOT = Path(__file__).resolve().parent.parent
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


def _direct_dependency(snapshot: Snapshot, name: str) -> tuple[str, str]:
    root = snapshot.lockfile["packages"][""]
    declared = root.get("dependencies", {}).get(name)
    installed = snapshot.lockfile["packages"].get(f"node_modules/{name}", {}).get("version")
    if not declared or not installed:
        raise ValueError("Automated fixes currently support direct production dependencies only")
    return declared, installed


def _safe_target(advisory: Advisory, name: str, installed: str) -> str:
    matching = [p for p in advisory.packages if p.name == name and is_affected(installed, p.vulnerable_range) is True]
    patched = [p.first_patched for p in matching if p.first_patched]
    if not patched:
        raise ValueError("The advisory has no first patched version for this installed package")
    # Multiple affected ranges can describe different release lines. Use the
    # patched version belonging to the matching installed range.
    return patched[0]


def build_preview(snapshot: Snapshot, advisory: Advisory, package: str, path: list[str]) -> tuple[str, dict]:
    if snapshot.repo.startswith("demo/"):
        raise ValueError("Synthetic demo repos cannot receive real pull requests")
    declared, installed = _direct_dependency(snapshot, package)
    target = _safe_target(advisory, package, installed)
    if is_affected(target, declared) is not True:
        raise ValueError(f"First patched version {target} falls outside the declared range {declared}; manual review is needed")
    npm = shutil.which("npm")
    if not npm:
        raise ValueError("npm is required on the server to prepare a lockfile fix")
    npm_cache = ROOT / "work" / "npm-cache"
    npm_cache.mkdir(exist_ok=True)
    original = snapshot.lockfile_text or json.dumps(snapshot.lockfile, indent=2, ensure_ascii=False) + "\n"
    with tempfile.TemporaryDirectory(prefix="blastradius-", dir=ROOT / "work") as tmp:
        folder = Path(tmp)
        (folder / "package.json").write_text(json.dumps(snapshot.package_json, indent=2) + "\n", encoding="utf-8")
        (folder / "package-lock.json").write_text(original, encoding="utf-8")
        result = subprocess.run(
            [npm, "update", package, "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--cache", str(npm_cache)],
            cwd=folder, capture_output=True, text=True, timeout=90, check=False,
        )
        if result.returncode:
            raise ValueError(f"npm could not prepare the lockfile: {result.stderr[-300:]}")
        updated_text = (folder / "package-lock.json").read_text(encoding="utf-8")
        updated_package = json.loads((folder / "package.json").read_text(encoding="utf-8"))
    if updated_package != snapshot.package_json:
        raise ValueError("npm changed package.json; this fix needs manual review")
    updated = json.loads(updated_text)
    parse_lockfile(updated)
    after = updated["packages"].get(f"node_modules/{package}", {}).get("version")
    if not after or any(is_affected(after, p.vulnerable_range) is not False for p in advisory.packages if p.name == package):
        raise ValueError("npm did not resolve the direct dependency to a verified unaffected version")
    if updated_text == original:
        raise ValueError("npm produced no lockfile change")
    diff_lines = list(difflib.unified_diff(original.splitlines(), updated_text.splitlines(), fromfile="a/package-lock.json", tofile="b/package-lock.json", lineterm=""))
    if len(diff_lines) > 1000:
        raise ValueError("The lockfile change is too large for the reviewable fix preview")
    preview_id = secrets.token_urlsafe(24)
    PROPOSALS[preview_id] = Proposal(snapshot.repo, snapshot.sha, advisory.identifier, advisory.url, package, installed, after, updated_text, path, time.time() + 1800)
    return preview_id, {"repo": snapshot.repo, "package": package, "before": installed, "after": after, "diff": "\n".join(diff_lines), "truncated": False, "proposal_id": preview_id}


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
