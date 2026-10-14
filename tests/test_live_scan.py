import asyncio

import pytest

from app.advisories import DEMO_ADVISORY
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
    snapshot = Snapshot("acme/service", "current-sha", {"packages": {}}, {}, "@team", [], "GitHub")
    events = []

    class FakeGraph:
        def ingest(self, item):
            events.append(("ingest", item.sha))
            return {"dependencies": 1}

        def context(self, repo, advisory):
            return {"owner": "@team", "services": [], "decisions": []}

        def paths_to(self, repo, package):
            events.append(("query", repo))
            return [{"nodes": [{"id": repo}, {"name": "render-kit"}], "version": "1.2.0", "dependency_id": "acme/service:render-kit"}]

        def link_advisory(self, advisory, summary, dependency_ids):
            pass

    async def fetch_repo(repo):
        assert repo == "https://github.com/acme/service"
        return snapshot

    async def fetch_advisory(identifier):
        assert identifier == "DEMO-2026-001"
        return DEMO_ADVISORY

    monkeypatch.setattr("app.main.fetch_public_repo", fetch_repo)
    monkeypatch.setattr("app.main.fetch_advisory", fetch_advisory)
    monkeypatch.setattr("app.main.store", FakeGraph)
    response = asyncio.run(scan_live(LiveScanRequest(repo="https://github.com/acme/service", advisory="DEMO-2026-001")))
    assert events == [("ingest", "current-sha"), ("query", "acme/service")]
    assert response["source"]["sha"] == "current-sha"
    assert response["results"][0]["vulnerable_paths"][0]["path"] == ["acme/service", "render-kit"]
