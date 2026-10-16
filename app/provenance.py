"""Find a lockfile pin's introducing commit and its reviewed pull request."""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import httpx

from .sources import Snapshot, _headers


async def trace_lockfile_pin(snapshot: Snapshot, package_path: str, version: str) -> dict[str, Any]:
    """Verify the changed package key against an available parent commit."""
    root_repo = snapshot.repo.split("::")[0]
    if snapshot.manager != "npm" or not isinstance(snapshot.lockfile.get("packages"), dict):
        return {"status": "unsupported", "reason": "Provenance currently needs a package-lock v2/v3 package key."}
    path = snapshot.lockfile_path
    target = snapshot.lockfile["packages"].get(package_path)
    if not isinstance(target, dict) or target.get("version") != version:
        return {"status": "unverified", "reason": "The vulnerable package key does not match the pinned lockfile."}
    result = await asyncio.to_thread(_git_history_fallback, root_repo, snapshot.sha, path, package_path, version)
    if result.get("status") != "verified":
        return result
    # One or two REST calls enrich an already verified commit; API quota failure
    # does not erase the Git proof or promote an inferred PR to a verified one.
    try:
        async with httpx.AsyncClient(timeout=8, headers=_headers()) as client:
            prs = await client.get(f"https://api.github.com/repos/{root_repo}/commits/{result['commit']}/pulls")
            if prs.is_success:
                merged = next((pr for pr in prs.json() if pr.get("merged_at")), None)
                if merged:
                    result["pull_request"] = {"number": merged["number"], "url": merged["html_url"],
                                              "author": (merged.get("user") or {}).get("login"), "verification": "github_api"}
                    reviews = await client.get(f"https://api.github.com/repos/{root_repo}/pulls/{merged['number']}/reviews",
                                               params={"per_page": 100})
                    if reviews.is_success:
                        result["reviewers"] = sorted({review.get("user", {}).get("login") for review in reviews.json()
                                                      if review.get("state") == "APPROVED" and review.get("user", {}).get("login")})
                        result.pop("note", None)
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        pass
    return result


def _git_history_fallback(repo: str, sha: str, lockfile_path: str, package_path: str, version: str,
                          remote_url: str | None = None) -> dict[str, Any]:
    """Verify the exact lockfile change, deepening a shallow clone when needed."""
    def run(cwd: Path, *args: str) -> str:
        process = subprocess.run(["git", "-c", "http.sslBackend=openssl", *args], cwd=cwd,
                                 capture_output=True, text=True, timeout=60, check=False)
        if process.returncode:
            raise RuntimeError(process.stderr[:200] or "git history command failed")
        return process.stdout
    with tempfile.TemporaryDirectory(prefix="blastradius-provenance-") as folder:
        root = Path(folder)
        checkout = root / "source"
        try:
            run(root, "clone", "--filter=blob:none", "--no-checkout", "--depth=100",
                remote_url or f"https://github.com/{repo}.git", str(checkout))
            if run(checkout, "rev-parse", "HEAD").strip() != sha:
                return {"status": "unverified", "reason": "Repository head changed before history could be checked."}
            depths = (100, 500, 2000)
            for index, depth in enumerate(depths):
                if index:
                    run(checkout, "fetch", "--deepen=" + str(depth - depths[index - 1]), "origin")
                commits = run(checkout, "log", "-500", "--format=%H", "--", lockfile_path).splitlines()
                shallow = run(checkout, "rev-parse", "--is-shallow-repository").strip() == "true"
                for commit in commits:
                    if not re.fullmatch(r"[0-9a-f]{40}", commit):
                        continue
                    try:
                        after = json.loads(run(checkout, "show", f"{commit}:{lockfile_path}"))
                        after_version = (after.get("packages") or {}).get(package_path, {}).get("version")
                        if after_version != version:
                            continue
                        parents = run(checkout, "rev-list", "--parents", "-n", "1", commit).split()
                        parent_sha = parents[1] if len(parents) > 1 else None
                        if parent_sha is None and shallow:
                            # Git hides the parent of a shallow boundary commit. Its apparent
                            # file addition cannot establish when this version was introduced.
                            break
                        before = json.loads(run(checkout, "show", f"{parent_sha}:{lockfile_path}")) if parent_sha else {}
                        previous = (before.get("packages") or {}).get(package_path, {}).get("version")
                        if previous == version:
                            continue
                        author = run(checkout, "show", "-s", "--format=%an", commit).strip()
                        subject = run(checkout, "show", "-s", "--format=%s", commit).strip()
                        pr_match = re.search(r"\(#(\d+)\)$", subject)
                        pull_request = ({"number": int(pr_match.group(1)),
                                         "url": f"https://github.com/{repo}/pull/{pr_match.group(1)}",
                                         "author": None, "verification": "commit_subject"} if pr_match else None)
                        return {"status": "verified", "source": "git_history", "commit": commit,
                                "commit_url": f"https://github.com/{repo}/commit/{commit}", "previous_version": previous,
                                "version": version, "package_path": package_path, "lockfile_path": lockfile_path,
                                "author": author, "pull_request": pull_request, "reviewers": [],
                                "note": "PR and reviewer verification is pending GitHub API access."}
                    except (ValueError, KeyError, RuntimeError):
                        continue
                if not shallow or len(commits) >= 500:
                    break
        except (RuntimeError, subprocess.TimeoutExpired, OSError) as exc:
            return {"status": "unverified", "reason": f"Git history was unavailable: {exc.__class__.__name__}"}
    return {"status": "unverified", "reason": "No introducing commit was verified within 2,000 history commits or 500 lockfile changes."}
