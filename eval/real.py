"""Reproduce an npm-audit versus BlastRadius comparison on a public repository."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from app.main import LiveScanRequest, scan_live
from app.sources import fetch_public_projects


REPO = "GoogleCloudPlatform/microservices-demo"
CVE = "CVE-2026-12143"
GHSA = "GHSA-hmw2-7cc7-3qxx"
PACKAGE = "form-data"


def npm_audit(snapshot) -> bool | None:
    with tempfile.TemporaryDirectory(prefix="blastradius-audit-") as folder:
        root = Path(folder)
        (root / "package-lock.json").write_text(snapshot.lockfile_text or "", encoding="utf-8")
        (root / "package.json").write_text(json.dumps(snapshot.package_json), encoding="utf-8")
        try:
            npm = shutil.which("npm.cmd") or shutil.which("npm")
            if not npm:
                return None
            proc = subprocess.run([npm, "audit", "--omit=dev", "--package-lock-only", "--json"],
                                  cwd=root, capture_output=True, text=True, timeout=90, check=False)
            data = json.loads(proc.stdout)
            matches = data.get("vulnerabilities", {}).get(PACKAGE, {}).get("via", [])
            return any(isinstance(item, dict) and GHSA in item.get("url", "") for item in matches)
        except (subprocess.TimeoutExpired, OSError, ValueError):
            return None


async def main() -> None:
    snapshots = await fetch_public_projects(REPO)
    scan = await scan_live(LiveScanRequest(repo=REPO, advisory=CVE))
    by_repo = {row["repo"]: row for row in scan["results"]}
    lines = ["# Real-repository comparison", "",
             f"Generated {datetime.now(timezone.utc).isoformat()} from [{REPO}](https://github.com/{REPO})",
             f"at commit `{scan['source']['sha']}`. Advisory: [{CVE}](https://github.com/advisories/{GHSA}).",
             "", "Both tools read the same committed npm lockfiles. `npm audit` identifies an affected package; "
             "BlastRadius adds cross-service graph paths, declared Kubernetes reachability, and review priority. "
             "This is a feature comparison, not an exploitability or accuracy benchmark.", "",
             "| Project | npm audit: advisory | BlastRadius: affected path | Public entry path | Priority |", "|---|---|---|---|---|"]
    for snapshot in (item for item in snapshots if item.manager == "npm"):
        result = by_repo[snapshot.repo]
        audit = npm_audit(snapshot)
        path = result["vulnerable_paths"][0]["path"] if result["vulnerable_paths"] else []
        exposure = next((service["exposure_path"] for service in result["services"] if service.get("exposure_path")), [])
        exposure_text = " → ".join(node.get("name") or node.get("kind") or "Internet" for node in exposure)
        lines.append(f"| `{snapshot.project_path}` | {'yes' if audit is True else 'no' if audit is False else 'unknown'} "
                     f"| {' → '.join(path) if path else 'none'} | {exposure_text or 'unknown'} | {result.get('priority', 'Review')} |")
    lines += ["", f"FalkorDB shared-package fan-out: **{len({r['repo'] for r in scan['results'] if r['vulnerable_paths']})} affected projects**.",
              f"Kubernetes import: **{scan['source']['deployment']['workloads']} workloads**, "
              f"**{scan['source']['deployment']['calls']} service calls**, "
              f"**{scan['source']['deployment']['public_routes']} public entry**.",
              "", "The package and declared network paths do not establish function-level reachability or exploitability."]
    output = Path(__file__).with_name("online_boutique.md")
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__":
    asyncio.run(main())
