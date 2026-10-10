"""FalkorDB is the source of truth for paths, ownership, and prior decisions."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from falkordb import FalkorDB

from .lockfile import edges_from_lockfile, parse_lockfile
from .sources import Snapshot


class GraphStore:
    def __init__(self) -> None:
        db = FalkorDB(host=os.getenv("FALKORDB_HOST", "localhost"), port=int(os.getenv("FALKORDB_PORT", "6379")))
        self.graph = db.select_graph(os.getenv("GRAPH_NAME", "blastradius"))

    def health(self) -> bool:
        self.graph.query("RETURN 1")
        return True

    def ingest(self, snapshot: Snapshot) -> dict[str, Any]:
        dependencies = parse_lockfile(snapshot.lockfile)
        edges = edges_from_lockfile(snapshot.lockfile, dependencies)
        repo = snapshot.repo
        # Replace only this repo's snapshot. MERGE makes each batch retry safe.
        # Decisions are durable memory; a fresh source snapshot must not erase them.
        self.graph.query("MATCH (n {repo_id:$repo}) WHERE NOT n:Decision DETACH DELETE n", {"repo": repo})
        self.graph.query(
            "MERGE (r:Repo {id:$repo}) SET r.repo_id=$repo, r.sha=$sha, r.source=$source, r.ingested_at=$now, r.complete=true",
            {"repo": repo, "sha": snapshot.sha, "source": snapshot.source, "now": datetime.now(timezone.utc).isoformat()},
        )
        self.graph.query(
            "MATCH (r:Repo {id:$repo}), (d:Decision {repo_id:$repo}) MERGE (r)-[:HAS_DECISION]->(d)",
            {"repo": repo},
        )
        rows = [
            {"id": f"{repo}:{d.path}", "repo": repo, "path": d.path, "name": d.name, "version": d.version}
            for d in dependencies
        ]
        if rows:
            self.graph.query(
                "UNWIND $rows AS row MERGE (d:Dependency {id:row.id}) "
                "SET d.repo_id=row.repo, d.path=row.path, d.name=row.name, d.version=row.version",
                {"rows": rows},
            )
        direct = [{"child": f"{repo}:{child}"} for parent, child in edges if not parent]
        nested = [{"parent": f"{repo}:{parent}", "child": f"{repo}:{child}"} for parent, child in edges if parent]
        if direct:
            self.graph.query(
                "MATCH (r:Repo {id:$repo}) UNWIND $rows AS row MATCH (d:Dependency {id:row.child}) MERGE (r)-[:DEPENDS_ON]->(d)",
                {"repo": repo, "rows": direct},
            )
        if nested:
            self.graph.query(
                "UNWIND $rows AS row MATCH (p:Dependency {id:row.parent}), (d:Dependency {id:row.child}) "
                "MERGE (p)-[:DEPENDS_ON]->(d)",
                {"rows": nested},
            )
        if snapshot.owner:
            self.graph.query(
                "MATCH (r:Repo {id:$repo}) MERGE (o:Owner {id:$owner_id}) "
                "SET o.repo_id=$repo, o.name=$owner MERGE (r)-[:OWNED_BY]->(o)",
                {"repo": repo, "owner_id": f"{repo}:{snapshot.owner}", "owner": snapshot.owner},
            )
        for service in snapshot.services:
            self.graph.query(
                "MATCH (r:Repo {id:$repo}) MERGE (s:Service {id:$id}) "
                "SET s.repo_id=$repo, s.name=$name, s.exposure=$exposure MERGE (r)-[:RUNS]->(s)",
                {"repo": repo, "id": f"{repo}:{service['name']}", "name": service["name"], "exposure": service.get("exposure", "unknown")},
            )
            if service.get("public_route"):
                self.graph.query(
                    "MATCH (s:Service {id:$id}) MERGE (e:Exposure {id:$exposure_id}) "
                    "SET e.repo_id=$repo, e.url=$url MERGE (s)-[:EXPOSES]->(e)",
                    {"repo": repo, "id": f"{repo}:{service['name']}", "exposure_id": f"{repo}:{service['name']}:route", "url": service["public_route"]},
                )
        return {"repo": repo, "sha": snapshot.sha, "dependencies": len(rows), "edges": len(edges), "services": len(snapshot.services)}

    def repositories(self) -> list[dict[str, str]]:
        rows = self.graph.ro_query("MATCH (r:Repo) RETURN r.id, r.sha, r.source ORDER BY r.id LIMIT 100", timeout=3000).result_set
        return [{"repo": r[0], "sha": r[1], "source": r[2]} for r in rows]

    def paths_to(self, repo: str, package_name: str) -> list[dict[str, Any]]:
        rows = self.graph.ro_query(
            "MATCH p=(r:Repo {id:$repo})-[:DEPENDS_ON*1..12]->(d:Dependency {name:$name}) "
            "RETURN p, d.version, d.id ORDER BY length(p) LIMIT 50",
            {"repo": repo, "name": package_name}, timeout=3000,
        ).result_set
        return [
            {"nodes": [node.properties for node in row[0].nodes()], "version": row[1], "dependency_id": row[2]}
            for row in rows
        ]

    def context(self, repo: str, advisory_id: str) -> dict[str, Any]:
        owner_rows = self.graph.ro_query(
            "MATCH (:Repo {id:$repo})-[:OWNED_BY]->(o:Owner) RETURN o.name LIMIT 1", {"repo": repo}, timeout=3000
        ).result_set
        service_rows = self.graph.ro_query(
            "MATCH (:Repo {id:$repo})-[:RUNS]->(s:Service) "
            "OPTIONAL MATCH (s)-[:EXPOSES]->(e:Exposure) RETURN s.name, s.exposure, e.url LIMIT 20",
            {"repo": repo}, timeout=3000,
        ).result_set
        decision_rows = self.graph.ro_query(
            "MATCH (:Repo {id:$repo})-[:HAS_DECISION]->(d:Decision {advisory_id:$advisory}) "
            "RETURN d.verdict, d.reason, d.created_at ORDER BY d.created_at DESC LIMIT 5",
            {"repo": repo, "advisory": advisory_id}, timeout=3000,
        ).result_set
        return {
            "owner": owner_rows[0][0] if owner_rows else None,
            "services": [{"name": row[0], "exposure": row[1], "public_route": row[2]} for row in service_rows],
            "decisions": [{"verdict": row[0], "reason": row[1], "created_at": row[2]} for row in decision_rows],
        }

    def link_advisory(self, advisory_id: str, summary: str, dependency_ids: list[str]) -> None:
        self.graph.query("MERGE (a:Advisory {id:$id}) SET a.summary=$summary", {"id": advisory_id, "summary": summary})
        if dependency_ids:
            self.graph.query(
                "MATCH (a:Advisory {id:$id}) UNWIND $ids AS dep_id MATCH (d:Dependency {id:dep_id}) "
                "MERGE (a)-[:AFFECTS]->(d)",
                {"id": advisory_id, "ids": dependency_ids},
            )

    def save_decision(self, repo: str, advisory_id: str, verdict: str, reason: str) -> None:
        if not self.graph.ro_query("MATCH (r:Repo {id:$repo}) RETURN r.id LIMIT 1", {"repo": repo}, timeout=3000).result_set:
            raise LookupError("Repository is not in the graph")
        self.graph.query(
            "MATCH (r:Repo {id:$repo}) CREATE (d:Decision {repo_id:$repo, advisory_id:$advisory, "
            "verdict:$verdict, reason:$reason, created_at:$now}) CREATE (r)-[:HAS_DECISION]->(d)",
            {"repo": repo, "advisory": advisory_id, "verdict": verdict, "reason": reason, "now": datetime.now(timezone.utc).isoformat()},
        )
