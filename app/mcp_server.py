"""Bounded evidence tools for BlastRadius agents and external MCP clients."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .graph import GraphStore
from .main import LiveScanRequest, ProvenanceRequest, provenance, scan_live


mcp = FastMCP("BlastRadius", instructions="Use these read-only evidence tools. Never infer safety from missing evidence.")


@mcp.tool()
def recall_investigations(repo: str, advisory: str | None = None) -> dict:
    """Memory: what earlier investigations of this repo concluded (newest first), with the commit they
    saw. Call this FIRST so you can compare today's result with the last one."""
    root = repo.split("::")[0]
    return {"repo": root, "previous": GraphStore().recall_investigations(root, advisory.upper() if advisory else None)}


@mcp.tool()
def graph_schema() -> dict:
    """The FalkorDB graph's node labels, relationship types and counts, and which repos are loaded.
    Use it to write query_graph Cypher."""
    return GraphStore().schema_summary()


@mcp.tool()
def query_graph(cypher: str) -> dict:
    """Run your own READ-ONLY openCypher query on the FalkorDB graph (3 s timeout, 50 rows) when no
    other tool answers the question. Schema: (Repo)-[:DEPENDS_ON]->(Dependency {name,version})-[:DEPENDS_ON]->(Dependency);
    (Dependency)-[:INSTANCE_OF]->(PackageVersion); (Advisory)-[:AFFECTS_VERSION]->(PackageVersion);
    (Repo)-[:RUNS]->(Service {name, exposure}); (Internet)-[:REACHES]->(Exposure)-[:ROUTES_TO]->(Service)-[:CALLS]->(Service);
    (Repo)-[:OWNED_BY]->(Owner); (Repo)-[:HAS_DECISION]->(Decision); (Investigation)-[:ABOUT]->(Advisory).
    Repo ids look like 'owner/repo::src/service'."""
    return GraphStore().read_query(cypher)


@mcp.tool()
def cut_points(project: str, dependency_id: str) -> dict:
    """For one affected project: which packages EVERY vulnerable dependency path passes through
    (the single places where one upgrade cuts all paths). Use the project id and dependency_id from scan_public_repo."""
    return GraphStore().cut_points(project, dependency_id)


@mcp.tool()
async def scan_public_repo(repo: str, advisory: str) -> dict:
    """Refresh a public GitHub repo at its latest commit, load its lockfiles and Kubernetes manifests
    into FalkorDB, and trace one CVE/GHSA: per project the verdict, dependency paths, internet
    exposure, owner and fix. Needed before any other per-repo tool."""
    result = await scan_live(LiveScanRequest(repo=repo, advisory=advisory))
    for item in result["results"]:
        # Keep tool output small for free-tier models, but report the true total.
        item["vulnerable_path_count"] = len(item["vulnerable_paths"])
        item["vulnerable_paths"] = item["vulnerable_paths"][:5]
        item["checked_paths"] = item["checked_paths"][:5]
    return result


@mcp.tool()
def advisory_fanout(advisory: str) -> dict:
    """List every ingested project (any repo) linked to an affected package version of this advisory."""
    rows = GraphStore().advisory_fanout(advisory.upper())
    return {"advisory": advisory.upper(), "affected_projects": rows, "count": len({row["repo"] for row in rows})}


@mcp.tool()
def graph_blast_radius(advisory: str) -> dict:
    """One FalkorDB query across EVERY loaded repo: each project installing an affected version,
    its dependency-path count, internet-exposure hops and past decisions. Use after scanning to find
    the same vulnerable version in other repos."""
    return GraphStore().blast_radius(advisory.upper())


@mcp.tool()
def decision_memory(repo: str, advisory: str) -> dict:
    """Human decisions recorded for ONE project and advisory (accept risk, remediated...), flagged
    stale when they were made on an older commit. `repo` is the project id from scan_public_repo."""
    context = GraphStore().context(repo, advisory.upper())
    return {"repo": repo, "current_sha": context["sha"], "decisions": context["decisions"]}


@mcp.tool()
def exposure_evidence(repo: str, advisory: str) -> dict:
    """For ONE project: its declared services and the shortest Internet -> ingress -> service-call path
    from the Kubernetes manifests (empty if not reachable). `repo` must be the project id from
    scan_public_repo's results, e.g. 'owner/repo::src/emailservice#pip', not the bare repo name."""
    context = GraphStore().context(repo, advisory.upper())
    return {"repo": repo, "services": context["services"]}


@mcp.tool()
def service_bridges(repo: str) -> dict:
    """Rank services by FalkorDB algo.betweenness on the service-call graph: high score = many call
    paths pass through it (a bridge, e.g. the frontend)."""
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
