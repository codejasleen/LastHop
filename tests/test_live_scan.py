import asyncio

import pytest

from app.advisories import Advisory, AffectedPackage
from app.main import LiveScanRequest, scan_live
from app.sources import Snapshot, normalize_repo


def test_github_repository_url_is_normalized():
    assert normalize_repo("https://github.com/acme/service") == "acme/service"
    assert normalize_repo("https://github.com/acme/service.git/") == "acme/service"
    assert normalize_repo("acme/service") == "acme/service"
    with pytest.raises(ValueError):
        normalize_repo("https://example.com/acme/service")
    with pytest.raises(ValueError):
        normalize_repo("https://github.com/acme/service/tree/main")


def test_live_scan_refreshes_repository_before_tracing(monkeypatch):
    advisory_fixture = Advisory("CVE-2026-12143", "Test advisory", "high", "", [AffectedPackage("form-data", "<2.5.6", "2.5.6")])
    snapshot = Snapshot("acme/service", "current-sha", {"packages": {"": {"dependencies": {}}}}, {}, "@team", [], "GitHub")
    events = []

    class FakeGraph:
        def ingest(self, item):
            events.append(("ingest", item.sha))
            return {"dependencies": 1}

        def prune_missing_projects(self, repo, current):
            pass

        def ingest_deployments(self, repo, snapshots):
            return {"workloads": 0, "calls": 0, "public_routes": 0}

        def context(self, repo, advisory):
            return {"owner": "@team", "services": [], "decisions": []}

        def paths_to(self, repo, package):
            events.append(("query", repo))
            return [{"nodes": [{"id": repo}, {"name": "form-data"}], "version": "2.5.5", "dependency_id": "acme/service:form-data"}]

        def link_advisory(self, advisory, summary, dependency_ids):
            pass

    async def fetch_repo(repo):
        assert repo == "https://github.com/acme/service"
        return [snapshot]

    async def fetch_advisory(identifier):
        assert identifier == "CVE-2026-12143"
        return advisory_fixture

    async def fetch_signals(identifier):
        return {"kev": False, "epss": None}

    monkeypatch.setattr("app.main.fetch_public_projects", fetch_repo)
    monkeypatch.setattr("app.main.fetch_advisory", fetch_advisory)
    monkeypatch.setattr("app.main.fetch_risk_signals", fetch_signals)
    monkeypatch.setattr("app.main.store", FakeGraph)
    response = asyncio.run(scan_live(LiveScanRequest(repo="https://github.com/acme/service", advisory="CVE-2026-12143")))
    assert events == [("ingest", "current-sha"), ("query", "acme/service")]
    assert response["source"]["sha"] == "current-sha"
    assert response["results"][0]["vulnerable_paths"][0]["path"] == ["acme/service", "form-data"]
