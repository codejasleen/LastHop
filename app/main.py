"""BlastRadius API and web UI."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .advisories import Advisory, fetch_advisory, is_affected
from .graph import GraphStore
from .fixes import build_preview, create_draft_pr
from .sources import fetch_public_repo
from .webhooks import verify_push


ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title="BlastRadius", version="0.1.0")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


class IngestRequest(BaseModel):
    repo: str = Field(min_length=3, max_length=120)


class InvestigationRequest(BaseModel):
    advisory: str = Field(min_length=8, max_length=30)
    repo: str | None = None


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


@app.post("/api/demo/seed")
def seed_demo() -> dict:
    from demo.fixtures import demo_snapshots

    graph = store()
    return {"ingested": [graph.ingest(snapshot) for snapshot in demo_snapshots()]}


@app.post("/api/repos/ingest")
async def ingest_repo(request: IngestRequest) -> dict:
    try:
        snapshot = await fetch_public_repo(request.repo)
        return store().ingest(snapshot)
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
        if not any(row["repo"] == repo for row in graph.repositories()):
            return {"refreshed": False, "reason": "repository not connected"}
        return {"refreshed": True, "snapshot": graph.ingest(await fetch_public_repo(repo))}
    except PermissionError as exc:
        raise HTTPException(401, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


def _verdict(paths: list[dict], checked: list[dict], context: dict, uncertain: bool) -> tuple[str, str]:
    if paths:
        services = context["services"]
        if any(s["exposure"] == "public" and s["public_route"] for s in services):
            return "affected_exposed", "A vulnerable dependency path reaches a repo with a declared public service."
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
    for package in advisory.packages:
        for path in graph.paths_to(repo, package.name):
            match = is_affected(path["version"], package.vulnerable_range)
            path_info = {
                "package": package.name,
                "version": path["version"],
                "range": package.vulnerable_range,
                "affected": match,
                "path": [node.get("name") or node.get("id") for node in path["nodes"]],
                "dependency_id": path["dependency_id"],
            }
            checked_paths.append(path_info)
            if match is True:
                vulnerable_paths.append(path_info)
                if package.first_patched:
                    fix_candidates.append({"package": package.name, "first_patched": package.first_patched, "direct": len(path["nodes"]) == 2})
            elif match is None:
                uncertain = True
    verdict, explanation = _verdict(vulnerable_paths, checked_paths, context, uncertain)
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
    }


@app.post("/api/investigate")
async def investigate(request: InvestigationRequest) -> dict:
    try:
        advisory = await fetch_advisory(request.advisory)
        if not advisory.packages:
            raise ValueError("This advisory has no npm package mapping, so a dependency verdict is unavailable")
        graph = store()
        repos = graph.repositories()
        selected = [r["repo"] for r in repos if request.repo is None or r["repo"] == request.repo]
        if not selected:
            raise HTTPException(404, "No matching repository has been ingested")
        results = [investigate_one(graph, repo, advisory) for repo in selected]
        order = {"affected_exposed": 0, "affected_exposure_unknown": 1, "affected_internal_declared": 2, "insufficient_evidence": 3, "not_affected_version": 4, "not_present": 5}
        results.sort(key=lambda row: (order[row["verdict"]], row["repo"]))
        return {
            "advisory": {"id": advisory.identifier, "summary": advisory.summary, "severity": advisory.severity, "url": advisory.url},
            "results": results,
        }
    except HTTPException:
        raise
    except (ValueError, LookupError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"Investigation failed: {exc.__class__.__name__}: {exc}") from exc


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
            if len(path["nodes"]) == 2 and any(
                p.name == request.package and is_affected(path["version"], p.vulnerable_range) is True
                for p in advisory.packages
            )
        ]
        if not affected:
            raise ValueError("No affected direct dependency path supports an automated fix")
        snapshot = await fetch_public_repo(request.repo)
        if snapshot.sha != repo_record["sha"]:
            raise ValueError("Repository changed since ingestion; import it again before proposing a fix")
        _, preview = build_preview(snapshot, advisory, request.package, [node.get("name") or node.get("id") for node in affected[0]["nodes"]])
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
