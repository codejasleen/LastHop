"""Small evidence agent that selects and calls BlastRadius MCP tools."""

from __future__ import annotations

import json
import re
import sys
from datetime import timedelta
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .sources import normalize_repo
from .llm import grounded_summary


ADVISORY_ID = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]{10,})\b", re.I)


def plan(question: str, repo: str | None, advisory: str | None) -> list[tuple[str, dict[str, str]]]:
    """Conservative fallback policy: only select allowlisted read tools."""
    advisory = (advisory or (ADVISORY_ID.search(question).group(0) if ADVISORY_ID.search(question) else None))
    if not advisory:
        raise ValueError("Give a CVE or GHSA identifier so the agent can select evidence tools")
    advisory = advisory.upper()
    if repo:
        repo = normalize_repo(repo)
    steps = []
    if repo:
        steps.append(("scan_public_repo", {"repo": repo, "advisory": advisory}))
        if any(word in question.lower() for word in ("rank", "priority", "blast", "impact", "bridge", "graph")):
            steps.append(("service_bridges", {"repo": repo}))
    steps.append(("advisory_fanout", {"advisory": advisory}))
    return steps


def _tool_value(result: Any) -> dict:
    if result.isError:
        raise RuntimeError("MCP evidence tool failed: " + "; ".join(getattr(item, "text", "") for item in result.content))
    if result.structuredContent:
        data = result.structuredContent
        return data.get("result", data) if isinstance(data, dict) else data
    for item in result.content:
        if getattr(item, "type", None) == "text":
            return json.loads(item.text)
    raise RuntimeError("MCP tool returned no structured evidence")


async def investigate(question: str, repo: str | None, advisory: str | None) -> dict:
    steps = plan(question, repo, advisory)
    lower = question.lower()
    wants_exposure = any(word in lower for word in ("exposure", "public", "internet", "reach", "path", "blast", "impact", "investigat"))
    wants_memory = any(word in lower for word in ("decision", "memory", "history", "last time", "previous"))
    wants_origin = any(word in lower for word in ("introduc", "commit", "who", "reviewer", "pull request", "origin"))
    server = StdioServerParameters(command=sys.executable, args=["-m", "app.mcp_server"])
    evidence: dict[str, dict] = {}
    trace = []
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            available = {tool.name for tool in (await session.list_tools()).tools}
            for name, arguments in steps:
                if name not in available:
                    raise RuntimeError(f"MCP tool {name} is unavailable")
                result = await session.call_tool(name, arguments, read_timeout_seconds=timedelta(seconds=90))
                value = _tool_value(result)
                evidence[name] = value
                trace.append({"tool": name, "arguments": arguments, "status": "ok"})
                if name == "scan_public_repo":
                    by_project = {}
                    for item in [row for row in value.get("results", []) if row.get("verdict") != "not_applicable"][:10]:
                        project = item["repo"]
                        by_project[project] = {}
                        followups = (["exposure_evidence"] if wants_exposure else []) + (["decision_memory"] if wants_memory else [])
                        for followup in followups:
                            args = {"repo": project, "advisory": arguments["advisory"]}
                            output = await session.call_tool(followup, args, read_timeout_seconds=timedelta(seconds=30))
                            by_project[project][followup] = _tool_value(output)
                            trace.append({"tool": followup, "arguments": args, "status": "ok"})
                    if wants_origin:
                        target = next((row for row in value.get("results", [])
                                       if row.get("provenance_supported") and row.get("vulnerable_paths")), None)
                        if target:
                            args = {"repo": target["repo"], "dependency_id": target["vulnerable_paths"][0]["dependency_id"]}
                            try:
                                output = await session.call_tool("introducing_commit", args,
                                                                 read_timeout_seconds=timedelta(seconds=40))
                                evidence["introducing_commit"] = _tool_value(output)
                                trace.append({"tool": "introducing_commit", "arguments": args, "status": "ok"})
                            except Exception:
                                evidence["introducing_commit"] = {"status": "unavailable", "reason": "Provenance lookup timed out."}
                                trace.append({"tool": "introducing_commit", "arguments": args, "status": "unavailable"})
                    evidence["project_context"] = by_project
    scan = evidence.get("scan_public_repo", {})
    results = scan.get("results", [])
    affected = [r for r in results if r.get("vulnerable_paths")]
    fanout = evidence.get("advisory_fanout", {})
    if affected:
        summary = f"{len(affected)} project(s) have affected package evidence. "
        summary += "Declared exposure and dependency paths are in the evidence below."
    elif results:
        summary = "No affected installed version was found in the scanned projects. Review coverage and unsupported manifests."
    else:
        summary = f"{fanout.get('count', 0)} affected ingested project(s) are linked to this advisory in FalkorDB."
    origin = evidence.get("introducing_commit")
    if origin and origin.get("status") == "verified":
        summary += f" Git history traces the pin to commit {origin['commit'][:10]} by {origin.get('author') or 'an unknown author'}."
    elif origin:
        summary += " The introducing commit could not be verified."
    stale = sum(decision.get("stale", False) for project in evidence.get("project_context", {}).values()
                for decision in project.get("decision_memory", {}).get("decisions", []))
    if stale:
        summary += f" {stale} earlier decision(s) need review after repository changes."
    facts = {"advisory": steps[0][1]["advisory"], "affected_projects": len(affected),
             "fanout_projects": fanout.get("count", 0), "stale_decisions": stale,
             "introducing_commit": origin,
             "results": [{"repo": row["repo"], "verdict": row["verdict"], "priority": row.get("priority"),
                          "paths": [p["path"] for p in row.get("vulnerable_paths", [])[:2]],
                          "exposure": [service.get("exposure_path", []) for service in row.get("services", [])]}
                         for row in results[:5]]}
    written, provider = await grounded_summary(question, facts)
    return {"summary": written or summary, "summary_source": provider, "tool_trace": trace, "evidence": evidence,
            "limits": "Package and declared network paths only; function-level reachability and runtime traffic are not measured."}
