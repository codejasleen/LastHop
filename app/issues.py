"""GitHub issues drafted from the graph's evidence. BlastRadius writes the draft; a person edits it
and approves the final create. Nothing is filed without the approval key."""

from __future__ import annotations

import os
import secrets
from typing import Any

import httpx

from .advisories import Advisory, is_affected
from .graph import GraphStore


def _hop(node: dict) -> str:
    return "Internet" if node.get("id") == "internet" else node.get("name") or node.get("kind") or node.get("id")


def draft_issue(graph: GraphStore, project: str, advisory: Advisory, risk: dict[str, Any], fix: dict | None) -> dict:
    """Title and markdown body for one affected project, every statement taken from the graph."""
    ecosystem = "PyPI" if project.endswith("#pip") else "npm"
    service = project.split("::")[-1].replace("#pip", "").rstrip("/").split("/")[-1]
    vulnerable = [(pkg, path) for pkg in advisory.packages if pkg.ecosystem == ecosystem
                  for path in graph.paths_to(project, pkg.name)
                  if is_affected(path["version"], pkg.vulnerable_range, ecosystem) is True]
    if not vulnerable:
        raise ValueError("This project has no affected dependency path for the advisory")
    package, first = vulnerable[0]
    context = graph.context(project, advisory.identifier)
    paths = sorted({" → ".join([service] + [n.get("name") for n in path["nodes"][1:]]) for _, path in vulnerable}, key=len)
    entry = (graph.cut_points(project, first["dependency_id"]).get("shared_by_all") or [])
    exposed = next((s for s in context["services"] if s.get("exposure_path")), None)

    title = f"{advisory.identifier}: {package.name} {first['version']} in {service}" + (
        " is reachable from the internet" if exposed else "")
    risk_bits = [f"Advisory severity **{advisory.severity}**"]
    if risk.get("kev") is not None:
        risk_bits.append("**in CISA KEV (actively exploited)**" if risk["kev"] else "not in CISA KEV")
    if risk.get("epss") is not None:
        risk_bits.append(f"EPSS {risk['epss'] * 100:.2f}% ({round((risk.get('epss_percentile') or 0) * 100)}th percentile)")

    lines = [f"## {advisory.identifier}: {advisory.summary}", "",
             f"`{package.name} {first['version']}` is installed in **{service}**; the affected range is `{package.vulnerable_range}`. "
             + ", ".join(risk_bits) + ".", "", "### Is it reachable from the internet?"]
    if exposed:
        lines.append("Yes, declared in the Kubernetes manifests: " + " → ".join(_hop(n) for n in exposed["exposure_path"]))
        lines += [f"- {_hop(n)}: `{n['evidence']}`" for n in exposed["exposure_path"] if n.get("evidence")]
    elif context["services"]:
        lines.append(f"No path from the internet was found. The manifests declare "
                     f"{', '.join(s['name'] for s in context['services'])} as internal.")
    else:
        lines.append("Unknown: no Kubernetes manifest for this service was found, so exposure was not established.")
    lines += ["", f"### How the vulnerable package gets in ({len(paths)} dependency path{'s' if len(paths) != 1 else ''})"]
    lines += [f"- `{p}`" for p in paths[:5]] + ([f"- …and {len(paths) - 5} more"] if len(paths) > 5 else [])
    if entry:
        lines.append(f"\nEvery path enters through `{entry[0]['package']}`.")
    lines += ["", "### Suggested fix"]
    lines += _fix_lines(package, fix)
    owner = (context.get("owner") or "").lstrip("@")
    lines += ["", "### Evidence", f"- Scanned commit: `{(context.get('sha') or '')[:10]}`", f"- Advisory: {advisory.url}"]
    if owner:
        lines.append(f"- Owner (CODEOWNERS): {owner}")  # no @, so a draft never pings anyone
    if context.get("decisions"):
        last = context["decisions"][0]
        verdict = {"investigate": "Investigate further", "accepted_risk": "Risk accepted",
                   "remediated": "Remediated"}.get(last["verdict"], last["verdict"])
        lines.append(f"- Earlier team decision: {verdict} ({last['reason']})")
    lines += ["", "---", "_Drafted by BlastRadius from its FalkorDB graph and reviewed by a person before filing. "
              "It checks package and declared network reachability, not function-level code reachability._"]
    return {"title": title[:256], "body": "\n".join(lines), "project": project}


def _fix_lines(package, fix: dict | None) -> list[str]:
    target = (fix or {}).get("target") or (fix or {}).get("first_patched") or package.first_patched
    if not target:
        return ["No patched version is published yet; track the advisory."]
    strategy = (fix or {}).get("strategy")
    if strategy == "requirements_pin":
        checks = (fix or {}).get("parents_checked") or []
        return [f"Pin `{package.name}=={target}` in `{fix.get('file')}` (one-line change)."] + (
            ["Verified: " + "; ".join([f"{package.name} {target} is an available PyPI release"] + checks) + "."])
    if strategy == "lockfile_refresh":
        return [f"Update `{package.name}` to `{target}` in the lockfile; {target} fits "
                f"{fix.get('parent_name')}'s declared range `{fix.get('declared_range')}`."]
    note = (fix or {}).get("reason")
    return [f"Upgrade `{package.name}` to `{target}` (first patched version in the advisory)." + (f" Note: {note}." if note else "")]


async def create_issue(root: str, title: str, body: str, admin_key: str) -> dict:
    expected, token = os.getenv("BLASTRADIUS_ADMIN_KEY"), os.getenv("GITHUB_TOKEN")
    if not expected or not token:
        raise ValueError("Creating issues needs BLASTRADIUS_ADMIN_KEY and GITHUB_TOKEN on the server")
    if not secrets.compare_digest(admin_key, expected):
        raise PermissionError("Incorrect approval key")
    headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}", "User-Agent": "BlastRadius"}
    async with httpx.AsyncClient(timeout=20, headers=headers) as client:
        response = await client.post(f"https://api.github.com/repos/{root}/issues", json={"title": title, "body": body})
    if response.status_code == 410:
        raise ValueError(f"Issues are disabled on {root}. Turn them on in the repository's Settings → Features")
    if response.status_code in (401, 403, 404):
        raise ValueError(f"The GitHub token cannot create issues in {root}; give it Issues: Read and write for this repository")
    response.raise_for_status()
    data = response.json()
    return {"url": data["html_url"], "number": data["number"]}
