"""BlastRadius API and web UI."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tarfile

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .advisories import Advisory, fetch_advisory, is_affected
from .graph import GraphStore, dependency_graph
from .fixes import build_preview, create_draft_pr, lockfile_refresh_plan
from .module_trace import fetch_parent_trace
from .risk_signals import assign_priority, fetch_risk_signals
from .sources import SourceAcquisitionError, fetch_public_projects, fetch_public_repo
from .webhooks import verify_push


ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title="BlastRadius", version="0.1.0")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


class IngestRequest(BaseModel):
    repo: str = Field(min_length=3, max_length=120)


class InvestigationRequest(BaseModel):
    advisory: str = Field(min_length=8, max_length=30)
    repo: str | None = None


class LiveScanRequest(BaseModel):
    repo: str = Field(min_length=3, max_length=200)
    advisory: str = Field(min_length=8, max_length=30)


class DecisionRequest(BaseModel):
    repo: str
    advisory: str
    verdict: str = Field(pattern="^(investigate|accepted_risk|remediated)$")
    reason: str = Field(min_length=4, max_length=500)


class PreviewRequest(BaseModel):
    repo: str
    advisory: str
    package: str


class ApproveRequest(BaseModel):
    proposal_id: str
    admin_key: str


class AgentRequest(BaseModel):
    question: str = Field(min_length=5, max_length=500)
    repo: str | None = None
    advisory: str | None = None


class ProvenanceRequest(BaseModel):
    repo: str
    dependency_id: str


def store() -> GraphStore:
    try:
        return GraphStore()
    except Exception as exc:
        raise HTTPException(503, f"FalkorDB is unavailable: {exc.__class__.__name__}") from exc


@app.get("/")
def home() -> FileResponse:
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/health")
def health() -> dict:
    try:
        store().health()
        return {"database": "connected"}
    except Exception:
        return {"database": "unavailable"}


@app.get("/api/repos")
def repositories() -> list[dict]:
    return store().repositories()


@app.post("/api/agent")
async def agent_investigation(request: AgentRequest) -> dict:
    from .agent import investigate

    try:
        return await investigate(request.question, request.repo, request.advisory)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"Agent investigation failed: {exc.__class__.__name__}: {exc}") from exc


@app.post("/api/provenance")
async def provenance(request: ProvenanceRequest) -> dict:
    from .provenance import trace_lockfile_pin

    graph = store()
    repo_record = next((row for row in graph.repositories() if row["repo"] == request.repo), None)
    if not repo_record:
        raise HTTPException(404, "Repository is not in the graph")
    if not request.dependency_id.startswith(request.repo + ":"):
        raise HTTPException(400, "Dependency ID does not belong to the selected project")
    if cached := graph.saved_provenance(request.dependency_id):
        return cached
    snapshot = next((s for s in await fetch_public_projects(request.repo.split("::")[0], force_refresh=False) if s.repo == request.repo), None)
    if snapshot is None or snapshot.sha != repo_record["sha"]:
        raise HTTPException(409, "Repository changed since scan; scan it again before tracing provenance")
    if snapshot.manager != "npm":
        raise HTTPException(400, "Introducing-commit tracing currently supports npm lockfiles")
    package_path = request.dependency_id.removeprefix(request.repo + ":")
    item = snapshot.lockfile.get("packages", {}).get(package_path, {})
    evidence = await trace_lockfile_pin(snapshot, package_path, item.get("version", ""))
    graph.save_provenance(request.repo, request.dependency_id, evidence)
    return evidence


@app.post("/api/repos/ingest")
async def ingest_repo(request: IngestRequest) -> dict:
    try:
        snapshots = await fetch_public_projects(request.repo)
        for snapshot in snapshots:
            dependency_graph(snapshot)
        graph = store()
        ingested = [graph.ingest(snapshot) for snapshot in snapshots]
        graph.prune_missing_projects(snapshots[0].repo.split("::")[0], {snapshot.repo for snapshot in snapshots})
        deployment = graph.ingest_deployments(snapshots[0].repo.split("::")[0], snapshots)
        return {"ingested": ingested, "deployment": deployment}
    except (ValueError, LookupError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"Repository import failed: {exc.__class__.__name__}") from exc


@app.post("/api/webhooks/github")
async def github_push(request: Request) -> dict:
    body = await request.body()
    try:
        repo = verify_push(body, request.headers.get("X-Hub-Signature-256"), request.headers.get("X-GitHub-Event"))
        if not repo:
            return {"refreshed": False}
        graph = store()
        if not any(row["repo"] == repo or row["repo"].startswith(f"{repo}::") for row in graph.repositories()):
            return {"refreshed": False, "reason": "repository not connected"}
        snapshots = await fetch_public_projects(repo)
        for snapshot in snapshots:
            dependency_graph(snapshot)
        ingested = [graph.ingest(snapshot) for snapshot in snapshots]
        graph.prune_missing_projects(repo, {snapshot.repo for snapshot in snapshots})
        deployment = graph.ingest_deployments(repo, snapshots)
        return {"refreshed": True, "snapshots": ingested, "deployment": deployment}
    except PermissionError as exc:
        raise HTTPException(401, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


def _verdict(paths: list[dict], checked: list[dict], context: dict, uncertain: bool) -> tuple[str, str]:
    if context.get("manager") == "pip":
        if paths:
            if any(s["exposure"] == "public" and s["public_route"] for s in context["services"]):
                return "declared_exposed", "A pinned Python requirement is affected, and a declared public path reaches this service. Installation and function-level use are unverified."
            if context["services"] and all(s["exposure"] == "internal" for s in context["services"]):
                return "declared_internal", "A pinned Python requirement is affected; the deployment manifests declare this service internal only."
            return "declared_exposure_unknown", "A pinned Python requirement is affected; deployment exposure or actual installation is not established."
        if checked and not uncertain:
            # An exact `==` pin is what pip installs, so a pin outside every affected range is positive evidence.
            return "not_affected_version", "The package is pinned with ==, and the pinned version is outside the advisory's affected ranges."
        return "insufficient_evidence", "No affected Python pin was observed. requirements.txt does not prove transitive dependency completeness, so absence is inconclusive."
    if paths:
        services = context["services"]
        if any(s["exposure"] == "public" and s["public_route"] for s in services):
            return "affected_exposed", "The affected package is installed in a service with a declared path from a public entry point. This does not prove exploitability."
        if services and all(s["exposure"] == "internal" for s in services):
            return "affected_internal_declared", "The deployment manifest declares only internal services."
        return "affected_exposure_unknown", "A vulnerable dependency path exists; network exposure is not established."
    if uncertain:
        return "insufficient_evidence", "The advisory version range could not be evaluated."
    if not checked:
        return "not_present", "The named package is not present in this repo's production dependency graph."
    return "not_affected_version", "The package is present, but its installed version is outside the advisory's affected ranges."


def investigate_one(graph: GraphStore, repo: str, advisory: Advisory) -> dict:
    context = graph.context(repo, advisory.identifier)
    vulnerable_paths: list[dict] = []
    checked_paths: list[dict] = []
    uncertain = False
    fix_candidates = []
    ecosystem = "PyPI" if context.get("manager") == "pip" else "npm"
    eligible = [package for package in advisory.packages if package.ecosystem == ecosystem]
    for package in eligible:
        for path in graph.paths_to(repo, package.name):
            match = is_affected(path["version"], package.vulnerable_range, package.ecosystem)
            path_info = {
                "package": package.name,
                "version": path["version"],
                "range": package.vulnerable_range,
                "affected": match,
                "path": [node.get("name") or node.get("id") for node in path["nodes"]],
                "dependency_id": path["dependency_id"],
                "evidence_kind": "declared_pin" if context.get("manager") == "pip" else "installed_lockfile",
            }
            checked_paths.append(path_info)
            if match is True:
                vulnerable_paths.append(path_info)
                if package.first_patched and context.get("manager") != "pip":
                    fix_candidates.append({"package": package.name, "first_patched": package.first_patched, "direct": len(path["nodes"]) == 2})
                elif package.first_patched and not any(c["package"] == package.name for c in fix_candidates):
                    # The advisory does name a fix; pip-compile files carry hashes, so the pin must be
                    # regenerated rather than hand-edited. Report it as a manual step, never as "no fix".
                    fix_candidates.append({
                        "package": package.name, "first_patched": package.first_patched, "before": path["version"],
                        "direct": len(path["nodes"]) == 2, "strategy": "manual_review",
                        "reason": f"regenerate the pinned requirements, e.g. pip-compile --upgrade-package "
                                  f"{package.name}=={package.first_patched}",
                    })
            elif match is None:
                uncertain = True
    verdict, explanation = (_verdict(vulnerable_paths, checked_paths, context, uncertain) if eligible else
                            ("not_applicable", f"This advisory has no {ecosystem} package mapping for this project."))
    graph.link_advisory(advisory.identifier, advisory.summary, [p["dependency_id"] for p in vulnerable_paths])
    return {
        "repo": repo,
        "verdict": verdict,
        "explanation": explanation,
        "vulnerable_paths": vulnerable_paths,
        "checked_paths": checked_paths,
        "owner": context["owner"],
        "services": context["services"],
        "prior_decisions": context["decisions"],
        "fix_candidates": fix_candidates,
        "fix_supported": context.get("manager", "npm") == "npm",
        "provenance_supported": context.get("manager", "npm") == "npm",
    }


async def enrich_live_result(graph: GraphStore, snapshot, advisory: Advisory, result: dict) -> None:
    """Attach bounded source evidence and a checked fix plan to a live result."""
    result["module_evidence"] = []
    result["priority"] = "Review"
    if result["vulnerable_paths"]:
        try:
            result["cut_points"] = graph.cut_points(snapshot.repo, result["vulnerable_paths"][0]["dependency_id"])
        except Exception:  # a timeout here must not cost the verdict itself
            result["cut_points"] = None
    if snapshot.manager != "npm" or not result["vulnerable_paths"]:
        return
    dependencies, edges = dependency_graph(snapshot)
    by_path = {dep.path: dep for dep in dependencies}
    for candidate in result["fix_candidates"]:
        try:
            candidate.update(lockfile_refresh_plan(snapshot, advisory, candidate["package"]))
        except ValueError as exc:
            candidate["strategy"] = "manual_review"
            candidate["reason"] = str(exc)
    analyzed = set()
    for vulnerable in result["vulnerable_paths"][:3]:
        target_path = vulnerable["dependency_id"].removeprefix(snapshot.repo + ":")
        for parent_path, child_path in edges:
            if child_path != target_path or not parent_path or (parent_path, target_path) in analyzed:
                continue
            analyzed.add((parent_path, target_path))
            if parent_path not in by_path:
                continue
            try:
                trace = await fetch_parent_trace(snapshot, parent_path, target_path, vulnerable["package"])
                graph.save_module_trace(snapshot.repo, trace)
                evidence = graph.module_evidence(snapshot.repo, parent_path, target_path)
                if evidence:
                    result["module_evidence"].append(evidence)
            except (ValueError, httpx.HTTPError, OSError, KeyError, tarfile.TarError):
                result["module_evidence"].append({"status": "unavailable", "parent": by_path[parent_path].name,
                                                  "scope": "Package source could not be inspected; no module-level conclusion was made."})


@app.post("/api/investigate")
async def investigate(request: InvestigationRequest) -> dict:
    try:
        advisory = await fetch_advisory(request.advisory)
        if not advisory.packages:
            raise ValueError("This advisory has no supported npm/PyPI package mapping, so a dependency verdict is unavailable")
        graph = store()
        repos = graph.repositories()
        selected = [
            r["repo"] for r in repos
            if (request.repo is None or r["repo"] == request.repo)
        ]
        if not selected:
            raise HTTPException(404, "No matching repository has been ingested")
        results = [investigate_one(graph, repo, advisory) for repo in selected]
        order = {"affected_exposed": 0, "declared_exposed": 1, "affected_exposure_unknown": 2, "declared_exposure_unknown": 3, "affected_internal_declared": 4, "declared_internal": 4, "insufficient_evidence": 5, "not_affected_version": 6, "not_present": 7, "not_applicable": 8}
        results.sort(key=lambda row: (order[row["verdict"]], row["repo"]))
        return {
            "advisory": {"id": advisory.identifier, "summary": advisory.summary, "severity": advisory.severity, "url": advisory.url, "packages": sorted({f"{p.ecosystem}:{p.name}" for p in advisory.packages})},
            "results": results,
        }
    except HTTPException:
        raise
    except (ValueError, LookupError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"Investigation failed: {exc.__class__.__name__}: {exc}") from exc


@app.post("/api/scan/live")
async def scan_live(request: LiveScanRequest) -> dict:
    """Fetch a public repo's current default-branch commit and investigate a CVE."""
    try:
        advisory = await fetch_advisory(request.advisory)
        if not advisory.packages:
            raise ValueError("This advisory has no supported npm/PyPI package mapping, so a dependency verdict is unavailable")
        snapshots = await fetch_public_projects(request.repo)
        for snapshot in snapshots:
            dependency_graph(snapshot)
        graph = store()
        imported = [graph.ingest(snapshot) for snapshot in snapshots]
        graph.prune_missing_projects(snapshots[0].repo.split("::")[0], {snapshot.repo for snapshot in snapshots})
        deployment = graph.ingest_deployments(snapshots[0].repo.split("::")[0], snapshots)
        signals = await fetch_risk_signals(advisory.identifier)
        results = []
        for snapshot, stored in zip(snapshots, imported):
            result = investigate_one(graph, snapshot.repo, advisory)
            # How many installed packages were searched: the proof behind "not present".
            result["dependency_count"] = stored["dependencies"]
            result["manifest"] = snapshot.lockfile_path
            await enrich_live_result(graph, snapshot, advisory, result)
            result["priority"], result["priority_reasons"] = assign_priority(result, signals)
            results.append(result)
        order = {"affected_exposed": 0, "declared_exposed": 1, "affected_exposure_unknown": 2, "declared_exposure_unknown": 3, "affected_internal_declared": 4, "declared_internal": 4, "insufficient_evidence": 5, "not_affected_version": 6, "not_present": 7, "not_applicable": 8}
        results.sort(key=lambda row: (order[row["verdict"]], row["repo"]))
        return {
            "advisory": {"id": advisory.identifier, "summary": advisory.summary, "severity": advisory.severity, "url": advisory.url, "packages": sorted({f"{p.ecosystem}:{p.name}" for p in advisory.packages})},
            "risk_signals": signals,
            "results": results,
            "source": {"repo": snapshots[0].repo.split("::")[0], "sha": snapshots[0].sha, "scanned_at": datetime.now(timezone.utc).isoformat(),
                       "dependencies": sum(row["dependencies"] for row in imported), "projects": len(snapshots),
                       "managers": sorted({snapshot.manager for snapshot in snapshots}),
                       "project_paths": [snapshot.project_path or "." for snapshot in snapshots],
                       "other_manifests": list(snapshots[0].other_manifests), "deployment": deployment},
        }
    except HTTPException:
        raise
    except (ValueError, LookupError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except SourceAcquisitionError as exc:
        raise HTTPException(503, str(exc)) from exc
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            raise HTTPException(404, "GitHub repository or advisory was not found") from exc
        if exc.response.status_code in (403, 429) and exc.response.headers.get("X-RateLimit-Remaining") == "0":
            raise HTTPException(429, "GitHub API rate limit reached. Set GITHUB_TOKEN on the server or retry after the limit resets") from exc
        raise HTTPException(502, f"GitHub returned HTTP {exc.response.status_code}") from exc
    except httpx.RequestError as exc:
        raise HTTPException(502, "GitHub is unreachable; try again shortly") from exc
    except Exception as exc:
        raise HTTPException(502, f"Live scan failed: {exc.__class__.__name__}") from exc


@app.get("/api/graph/blast-radius/{advisory_id}")
def graph_blast_radius(advisory_id: str) -> dict:
    """The cross-repo blast radius as one FalkorDB query (query text and timing included)."""
    try:
        return store().blast_radius(advisory_id.upper())
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"Graph query failed: {exc.__class__.__name__}: {exc}") from exc


@app.post("/api/decisions")
def save_decision(request: DecisionRequest) -> dict:
    try:
        store().save_decision(request.repo, request.advisory, request.verdict, request.reason)
        return {"saved": True}
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.post("/api/fixes/preview")
async def preview_fix(request: PreviewRequest) -> dict:
    try:
        graph = store()
        repo_record = next((r for r in graph.repositories() if r["repo"] == request.repo), None)
        if repo_record is None:
            raise HTTPException(404, "Repository is not in the graph")
        advisory = await fetch_advisory(request.advisory)
        paths = graph.paths_to(request.repo, request.package)
        affected = [
            path for path in paths
            if any(
                p.name == request.package and is_affected(path["version"], p.vulnerable_range) is True
                for p in advisory.packages
            )
        ]
        if not affected:
            raise ValueError("No affected dependency path supports an automated fix")
        snapshot = next((s for s in await fetch_public_projects(request.repo.split("::")[0]) if s.repo == request.repo), None)
        if snapshot is None:
            raise ValueError("Project is no longer present at the latest commit")
        if snapshot.sha != repo_record["sha"]:
            raise ValueError("Repository changed since ingestion; import it again before proposing a fix")
        _, preview = await build_preview(snapshot, advisory, request.package, [node.get("name") or node.get("id") for node in affected[0]["nodes"]])
        return preview
    except HTTPException:
        raise
    except (ValueError, LookupError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"Fix preview failed: {exc.__class__.__name__}: {exc}") from exc


@app.post("/api/fixes/approve")
async def approve_fix(request: ApproveRequest) -> dict:
    try:
        return {"pull_request_url": await create_draft_pr(request.proposal_id, request.admin_key)}
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"Draft PR failed: {exc.__class__.__name__}: {exc}") from exc
