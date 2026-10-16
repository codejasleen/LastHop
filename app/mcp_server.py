"""Bounded evidence tools for BlastRadius agents and external MCP clients."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .graph import GraphStore
from .main import LiveScanRequest, ProvenanceRequest, provenance, scan_live


mcp = FastMCP("BlastRadius", instructions="Use these read-only evidence tools. Never infer safety from missing evidence.")


@mcp.tool()
async def scan_public_repo(repo: str, advisory: str) -> dict:
    """Refresh a public GitHub repo at its latest commit and trace one CVE/GHSA through FalkorDB."""
    result = await scan_live(LiveScanRequest(repo=repo, advisory=advisory))
    for item in result["results"]:
        # Keep tool output small for free-tier models, but report the true total.
        item["vulnerable_path_count"] = len(item["vulnerable_paths"])
        item["vulnerable_paths"] = item["vulnerable_paths"][:5]
        item["checked_paths"] = item["checked_paths"][:5]
    return result


@mcp.tool()
def advisory_fanout(advisory: str) -> dict:
    """Read all currently ingested projects sharing an affected package version for this advisory."""
    rows = GraphStore().advisory_fanout(advisory.upper())
    return {"advisory": advisory.upper(), "affected_projects": rows, "count": len({row["repo"] for row in rows})}


@mcp.tool()
def decision_memory(repo: str, advisory: str) -> dict:
    """Read prior human decisions and flag ones recorded against a different repository commit."""
    context = GraphStore().context(repo, advisory.upper())
    return {"repo": repo, "current_sha": context["sha"], "decisions": context["decisions"]}


@mcp.tool()
def exposure_evidence(repo: str, advisory: str) -> dict:
    """Read declared service and Internet-to-service paths for an ingested project."""
    context = GraphStore().context(repo, advisory.upper())
    return {"repo": repo, "services": context["services"]}


@mcp.tool()
def service_bridges(repo: str) -> dict:
    """Rank service-call bridge nodes with FalkorDB algo.betweenness."""
    root = repo.split("::")[0]
    return {"repo": root, "algorithm": "algo.betweenness", "services": GraphStore().service_betweenness(root)}


@mcp.tool()
async def introducing_commit(repo: str, dependency_id: str) -> dict:
    """Verify the lockfile commit that introduced an affected npm pin; PR/reviewer may be unknown."""
    try:
        return await provenance(ProvenanceRequest(repo=repo, dependency_id=dependency_id))
    except Exception as exc:
        return {"status": "unavailable", "reason": f"Provenance lookup failed: {exc.__class__.__name__}"}


if __name__ == "__main__":
    mcp.run(transport="stdio")
