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
from .pip_requirements import parse_requirements


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
            "r.manager=$manager, r.project_path=$project_path, r.ingested_at=$now, r.complete=$complete",
            {"repo": repo, "sha": snapshot.sha, "source": snapshot.source, "manager": snapshot.manager,
             "project_path": snapshot.project_path, "complete": snapshot.manager != "pip",
             "now": datetime.now(timezone.utc).isoformat()},
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
            # Instances remain repo-specific; PackageVersion is shared across repos.
            self.graph.query(
                "UNWIND $rows AS row MATCH (d:Dependency {id:row.id}) "
                "MERGE (p:PackageVersion {id:$ecosystem + ':' + row.name + '@' + row.version}) "
                "SET p.ecosystem=$ecosystem, p.name=row.name, p.version=row.version "
                "MERGE (d)-[:INSTANCE_OF]->(p)",
                {"rows": rows, "ecosystem": "PyPI" if snapshot.manager == "pip" else "npm"},
            )
            self.graph.query(
                "MATCH (d:Dependency {repo_id:$repo}), (c:Commit) "
                "WHERE c.dependency_id=d.id AND c.introduced_version=d.version AND c.snapshot_sha=$sha "
                "MERGE (c)-[:INTRODUCED_PIN]->(d)",
                {"repo": repo, "sha": snapshot.sha},
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

    def ingest_deployments(self, github_repo: str, snapshots: list[Snapshot]) -> dict[str, int]:
        """Store real manifest routes and workload calls beside package projects."""
        workloads = snapshots[0].deployments if snapshots else ()
        self.graph.query("MATCH (n {deployment_repo:$repo}) WHERE n:Service OR n:Exposure DETACH DELETE n", {"repo": github_repo})
        if not workloads:
            return {"workloads": 0, "calls": 0, "public_routes": 0}
        project_by_workload = {}
        for snapshot in snapshots:
            leaf = snapshot.project_path.rsplit("/", 1)[-1].lower()
            if leaf:
                project_by_workload[leaf] = snapshot.repo
        for workload in workloads:
            name = workload["name"]
            identifier = f"{github_repo}:workload:{name}"
            project = project_by_workload.get(name.lower())
            self.graph.query(
                "MERGE (s:Service {id:$id}) SET s.name=$name, s.deployment_repo=$root, "
                "s.exposure=$exposure, s.evidence=$source",
                {"id": identifier, "name": name, "root": github_repo, "source": workload["source"],
                 "exposure": "public" if workload["public_routes"] else "internal"},
            )
            if project:
                self.graph.query("MATCH (r:Repo {id:$repo}), (s:Service {id:$id}) MERGE (r)-[:RUNS]->(s)",
                                 {"repo": project, "id": identifier})
            for route in workload["public_routes"]:
                route_id = f"{identifier}:route:{route['service']}"
                self.graph.query(
                    "MERGE (i:Internet {id:'internet'}) MERGE (e:Exposure {id:$route}) "
                    "SET e.deployment_repo=$repo, e.kind=$kind, e.evidence=$evidence, e.url=$url "
                    "WITH i,e MATCH (s:Service {id:$service}) "
                    "MERGE (i)-[:REACHES]->(e) MERGE (e)-[:ROUTES_TO]->(s)",
                    {"route": route_id, "repo": github_repo, "kind": route["kind"], "evidence": route["source"],
                     "url": route.get("host") or route["service"], "service": identifier},
                )
        count = 0
        for workload in workloads:
            for call in workload["calls"]:
                if not call.get("workload"):
                    continue
                self.graph.query(
                    "MATCH (a:Service {id:$source}), (b:Service {id:$target}) "
                    "MERGE (a)-[c:CALLS]->(b) SET c.evidence=$evidence, c.variable=$variable",
                    {"source": f"{github_repo}:workload:{workload['name']}",
                     "target": f"{github_repo}:workload:{call['workload']}",
                     "evidence": call["source"], "variable": call["variable"]},
                )
                count += 1
        return {"workloads": len(workloads), "calls": count,
                "public_routes": sum(len(row["public_routes"]) for row in workloads)}

    def prune_missing_projects(self, github_repo: str, current: set[str]) -> None:
        """Retire lockfile projects removed from a GitHub repo's latest snapshot."""
        for row in self.repositories():
            project = row["repo"]
            if (project == github_repo or project.startswith(f"{github_repo}::")) and project not in current:
                self.graph.query(
                    "MATCH (n {repo_id:$repo}) WHERE NOT n:Decision DETACH DELETE n",
                    {"repo": project},
                )
        self.graph.query("MATCH (p:PackageVersion) WHERE NOT (p)<-[:INSTANCE_OF]-(:Dependency) DELETE p")

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
            "MATCH (r:Repo {id:$repo}) RETURN r.manager, r.project_path, r.sha, r.complete LIMIT 1", {"repo": repo}, timeout=3000
        ).result_set
        owner_rows = self.graph.ro_query(
            "MATCH (:Repo {id:$repo})-[:OWNED_BY]->(o:Owner) RETURN o.name LIMIT 1", {"repo": repo}, timeout=3000
        ).result_set
        service_rows = self.graph.ro_query(
            "MATCH (:Repo {id:$repo})-[:RUNS]->(s:Service) "
            "OPTIONAL MATCH (s)-[:EXPOSES]->(e:Exposure) RETURN s.name, s.exposure, e.url LIMIT 20",
            {"repo": repo}, timeout=3000,
        ).result_set
        exposure_rows = self.graph.ro_query(
            "MATCH (r:Repo {id:$repo})-[:RUNS]->(s:Service), (i:Internet {id:'internet'}) "
            "WITH s, shortestPath((i)-[:REACHES|ROUTES_TO|CALLS*1..12]->(s)) AS p "
            "RETURN s.id, p LIMIT 20",
            {"repo": repo}, timeout=3000,
        ).result_set
        exposure_paths = {row[0]: [node.properties for node in row[1].nodes()] for row in exposure_rows if row[1]}
        decision_rows = self.graph.ro_query(
            "MATCH (:Repo {id:$repo})-[:HAS_DECISION]->(d:Decision {advisory_id:$advisory}) "
            "RETURN d.verdict, d.reason, d.created_at, d.snapshot_sha ORDER BY d.created_at DESC LIMIT 5",
            {"repo": repo, "advisory": advisory_id}, timeout=3000,
        ).result_set
        return {
            "manager": repo_rows[0][0] if repo_rows and repo_rows[0][0] else "npm",
            "project_path": repo_rows[0][1] if repo_rows and repo_rows[0][1] else "",
            "sha": repo_rows[0][2] if repo_rows else None,
            "complete": repo_rows[0][3] if repo_rows else False,
            "owner": owner_rows[0][0] if owner_rows else None,
            "services": [{"name": row[0], "exposure": "public" if any(path[-1].get("name") == row[0] for path in exposure_paths.values()) else row[1],
                          "public_route": row[2] or next((path[1].get("url") for path in exposure_paths.values() if path[-1].get("name") == row[0]), None),
                          "exposure_path": next((path for path in exposure_paths.values() if path[-1].get("name") == row[0]), [])}
                         for row in service_rows],
            "decisions": [{"verdict": row[0], "reason": row[1], "created_at": row[2],
                           "snapshot_sha": row[3], "stale": not row[3] or row[3] != repo_rows[0][2]}
                          for row in decision_rows],
        }


    def link_advisory(self, advisory_id: str, summary: str, dependency_ids: list[str]) -> None:
        self.graph.query("MERGE (a:Advisory {id:$id}) SET a.summary=$summary", {"id": advisory_id, "summary": summary})
        if dependency_ids:
            self.graph.query(
                "MATCH (a:Advisory {id:$id}) UNWIND $ids AS dep_id MATCH (d:Dependency {id:dep_id}) "
                "MERGE (a)-[:AFFECTS]->(d)",
                {"id": advisory_id, "ids": dependency_ids},
            )
            self.graph.query(
                "MATCH (a:Advisory {id:$id}) UNWIND $ids AS dep_id "
                "MATCH (d:Dependency {id:dep_id})-[:INSTANCE_OF]->(p:PackageVersion) "
                "MERGE (a)-[:AFFECTS_VERSION]->(p)",
                {"id": advisory_id, "ids": dependency_ids},
            )

    def advisory_fanout(self, advisory_id: str) -> list[dict[str, Any]]:
        """A single graph read joins one advisory to all installed project instances."""
        rows = self.graph.ro_query(
            "MATCH (a:Advisory {id:$id})-[:AFFECTS_VERSION]->(p:PackageVersion)"
            "<-[:INSTANCE_OF]-(d:Dependency) "
            "MATCH path=(r:Repo)-[:DEPENDS_ON*1..12]->(d) "
            "RETURN r.id, p.name, p.version, length(path), r.sha "
            "ORDER BY r.id, length(path) LIMIT 100",
            {"id": advisory_id}, timeout=3000,
        ).result_set
        return [{"repo": row[0], "package": row[1], "version": row[2],
                 "dependency_hops": row[3], "sha": row[4]} for row in rows]

    def service_betweenness(self, github_repo: str) -> list[dict[str, Any]]:
        """Rank declared service-call bridges using FalkorDB's algorithm procedure."""
        rows = self.graph.ro_query(
            "CALL algo.betweenness({nodeLabels:['Service'], relationshipTypes:['CALLS']}) "
            "YIELD node, score WITH node, score WHERE node.deployment_repo=$repo "
            "RETURN node.name, score ORDER BY score DESC LIMIT 20",
            {"repo": github_repo}, timeout=3000,
        ).result_set
        return [{"service": name, "betweenness": score} for name, score in rows]

    def save_decision(self, repo: str, advisory_id: str, verdict: str, reason: str) -> None:
        repo_rows = self.graph.ro_query("MATCH (r:Repo {id:$repo}) RETURN r.sha LIMIT 1", {"repo": repo}, timeout=3000).result_set
        if not repo_rows:
            raise LookupError("Repository is not in the graph")
        self.graph.query(
            "MATCH (r:Repo {id:$repo}) CREATE (d:Decision {repo_id:$repo, advisory_id:$advisory, "
            "verdict:$verdict, reason:$reason, created_at:$now, snapshot_sha:$sha}) CREATE (r)-[:HAS_DECISION]->(d)",
            {"repo": repo, "advisory": advisory_id, "verdict": verdict, "reason": reason,
             "sha": repo_rows[0][0], "now": datetime.now(timezone.utc).isoformat()},
        )

    def save_provenance(self, repo: str, dependency_id: str, evidence: dict[str, Any]) -> None:
        if evidence.get("status") != "verified":
            return
        snapshot_rows = self.graph.ro_query("MATCH (r:Repo {id:$repo}) RETURN r.sha LIMIT 1",
                                            {"repo": repo}, timeout=3000).result_set
        if not snapshot_rows:
            return
        self.graph.query(
            "MATCH (d:Dependency {id:$dependency}) "
            "MERGE (c:Commit {id:$commit}) SET c.url=$url, c.deployment_repo=$repo, "
            "c.dependency_id=$dependency, c.introduced_version=$version, c.snapshot_sha=$sha "
            "MERGE (c)-[:INTRODUCED_PIN]->(d) "
            "MERGE (author:Person {id:$author_id}) SET author.role='author' "
            "MERGE (author)-[:AUTHORED]->(c)",
            {"dependency": dependency_id, "commit": evidence["commit"], "url": evidence["commit_url"],
             "repo": repo.split("::")[0], "version": evidence.get("version"),
             "sha": snapshot_rows[0][0],
             "author_id": f"{evidence['commit']}:author"},
        )
        pr = evidence.get("pull_request")
        if pr:
            pr_id = f"{repo.split('::')[0]}#{pr['number']}"
            self.graph.query(
                "MATCH (c:Commit {id:$commit}) MERGE (pr:PullRequest {id:$pr}) "
                "SET pr.url=$url, pr.deployment_repo=$repo, pr.verification=$verification "
                "MERGE (pr)-[:CONTAINS]->(c)",
                {"commit": evidence["commit"], "pr": pr_id, "url": pr["url"], "repo": repo.split("::")[0],
                 "verification": pr.get("verification", "github_api")},
            )
            for index, _reviewer in enumerate(evidence.get("reviewers", [])):
                self.graph.query(
                    "MATCH (pr:PullRequest {id:$pr}) MERGE (p:Person {id:$reviewer}) "
                    "SET p.role='reviewer' MERGE (p)-[:APPROVED]->(pr)",
                    {"pr": pr_id, "reviewer": f"{pr_id}:reviewer:{index}"},
                )

    def saved_provenance(self, dependency_id: str) -> dict[str, Any] | None:
        rows = self.graph.ro_query(
            "MATCH (c:Commit)-[:INTRODUCED_PIN]->(d:Dependency {id:$dependency}) "
            "OPTIONAL MATCH (pr:PullRequest)-[:CONTAINS]->(c) "
            "RETURN c.id, c.url, d.version, pr.id, pr.url, pr.verification LIMIT 1",
            {"dependency": dependency_id}, timeout=3000,
        ).result_set
        if not rows:
            return None
        commit, url, version, pr_id, pr_url, verification = rows[0]
        return {"status": "verified", "source": "stored_graph", "commit": commit, "commit_url": url,
                "version": version, "author": None, "reviewers": [],
                "pull_request": {"number": int(pr_id.rsplit("#", 1)[-1]), "url": pr_url,
                                 "verification": verification} if pr_id else None,
                "note": "Public author/reviewer names are not retained in FalkorDB."}


def dependency_graph(snapshot: Snapshot) -> tuple[list, list[tuple[str, str]]]:
    if snapshot.manager == "npm":
        dependencies = parse_lockfile(snapshot.lockfile)
        return dependencies, edges_from_lockfile(snapshot.lockfile, dependencies)
    if snapshot.manager == "pnpm":
        return parse_pnpm_project(snapshot.lockfile, snapshot.importer)
    if snapshot.manager == "yarn":
        return parse_yarn_project(snapshot.lockfile_text or "", snapshot.package_json)
    if snapshot.manager == "pip":
        return parse_requirements(snapshot.lockfile_text or "")
    raise ValueError(f"Unsupported package manager: {snapshot.manager}")
