"""FalkorDB is the source of truth for paths, ownership, and prior decisions."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from falkordb import FalkorDB

from .lockfile import edges_from_lockfile, parse_lockfile
from .pnpm_lock import parse_pnpm_project
from .yarn_lock import parse_yarn_project
from .sources import Snapshot
from .module_trace import ModuleTrace


class GraphStore:
    def __init__(self) -> None:
        db = FalkorDB(host=os.getenv("FALKORDB_HOST", "localhost"), port=int(os.getenv("FALKORDB_PORT", "6379")))
        self.graph = db.select_graph(os.getenv("GRAPH_NAME", "blastradius"))

    def health(self) -> bool:
        self.graph.query("RETURN 1")
        return True

    def ingest(self, snapshot: Snapshot) -> dict[str, Any]:
        dependencies, edges = dependency_graph(snapshot)
        repo = snapshot.repo
        # Replace only this repo's snapshot. MERGE makes each batch retry safe.
        # Decisions are durable memory; a fresh source snapshot must not erase them.
        self.graph.query("MATCH (n {repo_id:$repo}) WHERE NOT n:Decision DETACH DELETE n", {"repo": repo})
        self.graph.query(
            "MERGE (r:Repo {id:$repo}) SET r.repo_id=$repo, r.sha=$sha, r.source=$source, "
            "r.manager=$manager, r.project_path=$project_path, r.ingested_at=$now, r.complete=true",
            {"repo": repo, "sha": snapshot.sha, "source": snapshot.source, "manager": snapshot.manager,
             "project_path": snapshot.project_path, "now": datetime.now(timezone.utc).isoformat()},
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
        rows = self.graph.ro_query("MATCH (r:Repo) RETURN r.id, r.sha, r.source, r.manager ORDER BY r.id LIMIT 100", timeout=3000).result_set
        return [{"repo": r[0], "sha": r[1], "source": r[2], "manager": r[3]} for r in rows]

    def prune_missing_projects(self, github_repo: str, current: set[str]) -> None:
        """Retire lockfile projects removed from a GitHub repo's latest snapshot."""
        for row in self.repositories():
            project = row["repo"]
            if (project == github_repo or project.startswith(f"{github_repo}::")) and project not in current:
                self.graph.query(
                    "MATCH (n {repo_id:$repo}) WHERE NOT n:Decision DETACH DELETE n",
                    {"repo": project},
                )

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

    def save_module_trace(self, repo: str, trace: ModuleTrace) -> None:
        """Keep the inspected file/import edges beside the dependency path."""
        parent_id = f"{repo}:{trace.parent_path}"
        target_id = f"{repo}:{trace.target_path}"
        analysis_id = f"{parent_id}:analysis:{trace.target_path}"
        self.graph.query(
            "MATCH (parent:Dependency {id:$parent}), (target:Dependency {id:$target}) "
            "MERGE (a:ModuleAnalysis {id:$id}) SET a.repo_id=$repo, a.status=$status, "
            "a.source_url=$url, a.main_file=$main, a.evidence_file=$evidence_file, "
            "a.evidence_line=$evidence_line "
            "MERGE (parent)-[:HAS_MODULE_ANALYSIS]->(a) MERGE (a)-[:ANALYZES]->(target)",
            {"parent": parent_id, "target": target_id, "id": analysis_id, "repo": repo,
             "status": trace.status, "url": trace.source_url, "main": trace.main,
             "evidence_file": trace.evidence_file or "", "evidence_line": trace.evidence_line or 0},
        )
        rows = [{"id": f"{parent_id}:module:{file}", "repo": repo, "file": file} for file in trace.files]
        self.graph.query(
            "UNWIND $rows AS row MERGE (m:ModuleFile {id:row.id}) SET m.repo_id=row.repo, m.file=row.file",
            {"rows": rows},
        )
        self.graph.query(
            "MATCH (a:ModuleAnalysis {id:$id}), (m:ModuleFile {id:$module}) MERGE (a)-[:MAIN_ENTRY]->(m)",
            {"id": analysis_id, "module": f"{parent_id}:module:{trace.main}"},
        )
        if trace.bins:
            self.graph.query(
                "MATCH (a:ModuleAnalysis {id:$id}) UNWIND $ids AS module_id "
                "MATCH (m:ModuleFile {id:module_id}) MERGE (a)-[:CLI_ENTRY]->(m)",
                {"id": analysis_id, "ids": [f"{parent_id}:module:{file}" for file in trace.bins]},
            )
        if trace.file_edges:
            self.graph.query(
                "UNWIND $rows AS row MATCH (src:ModuleFile {id:row.src}), (dst:ModuleFile {id:row.dst}) "
                "MERGE (src)-[edge:IMPORTS_MODULE]->(dst) SET edge.line=row.line",
                {"rows": [{"src": f"{parent_id}:module:{src}", "dst": f"{parent_id}:module:{dst}", "line": line}
                          for src, dst, line in trace.file_edges]},
            )
        if trace.package_edges:
            self.graph.query(
                "MATCH (target:Dependency {id:$target}) UNWIND $rows AS row "
                "MATCH (src:ModuleFile {id:row.src}) MERGE (src)-[edge:IMPORTS_PACKAGE]->(target) SET edge.line=row.line",
                {"target": target_id, "rows": [{"src": f"{parent_id}:module:{file}", "line": line}
                                                for file, line in trace.package_edges]},
            )

    def module_evidence(self, repo: str, parent_path: str, target_path: str) -> dict[str, Any] | None:
        analysis_id = f"{repo}:{parent_path}:analysis:{target_path}"
        rows = self.graph.ro_query(
            "MATCH (p:Dependency)-[:HAS_MODULE_ANALYSIS]->(a:ModuleAnalysis {id:$id}) "
            "RETURN a.source_url, a.main_file, p.name, p.version LIMIT 1",
            {"id": analysis_id}, timeout=3000,
        ).result_set
        if not rows:
            return None
        url, main, parent_name, parent_version = rows[0]
        # The verdict is read from actual import paths in FalkorDB, not from the
        # cached status string computed while parsing the archive.
        def path_from(entry: str) -> list:
            return self.graph.ro_query(
                f"MATCH (a:ModuleAnalysis {{id:$id}})-[:{entry}]->(start:ModuleFile), "
                "(a)-[:ANALYZES]->(target:Dependency) "
                "MATCH p=(start)-[:IMPORTS_MODULE*0..16]->(last:ModuleFile)-[imp:IMPORTS_PACKAGE]->(target) "
                "RETURN last.file, imp.line ORDER BY length(p) LIMIT 1",
                {"id": analysis_id}, timeout=3000,
            ).result_set
        runtime_path = path_from("MAIN_ENTRY")
        cli_path = path_from("CLI_ENTRY") if not runtime_path else []
        status = "runtime_static_path" if runtime_path else "cli_only_static_path" if cli_path else "no_static_path"
        file, line = (runtime_path or cli_path or [[None, None]])[0]
        return {"status": status, "parent": parent_name, "parent_version": parent_version,
                "main": main, "file": file or None, "line": line or None, "source_url": url,
                "scope": "Static imports within the immediate parent package; dynamic loads and CLI execution are not ruled out."}

    def context(self, repo: str, advisory_id: str) -> dict[str, Any]:
        repo_rows = self.graph.ro_query(
            "MATCH (r:Repo {id:$repo}) RETURN r.manager, r.project_path LIMIT 1", {"repo": repo}, timeout=3000
        ).result_set
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
            "manager": repo_rows[0][0] if repo_rows and repo_rows[0][0] else "npm",
            "project_path": repo_rows[0][1] if repo_rows and repo_rows[0][1] else "",
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


def dependency_graph(snapshot: Snapshot) -> tuple[list, list[tuple[str, str]]]:
    if snapshot.manager == "npm":
        dependencies = parse_lockfile(snapshot.lockfile)
        return dependencies, edges_from_lockfile(snapshot.lockfile, dependencies)
    if snapshot.manager == "pnpm":
        return parse_pnpm_project(snapshot.lockfile, snapshot.importer)
    if snapshot.manager == "yarn":
        return parse_yarn_project(snapshot.lockfile_text or "", snapshot.package_json)
    raise ValueError(f"Unsupported package manager: {snapshot.manager}")
