import asyncio
import io
import json
import zipfile

import httpx
import pytest
from fastapi import HTTPException

from app.advisories import Advisory, AffectedPackage, fetch_advisory, is_affected
from app.main import LiveScanRequest, scan_live
from app.sources import Snapshot, SourceAcquisitionError, SourceArchiveError, fetch_public_projects


def test_public_archive_fallback_keeps_commit_and_project_scope(monkeypatch):
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"qs": "6.5.3"}},
        "node_modules/qs": {"version": "6.5.3"},
    }}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("demo-HEAD/go.mod", "module example.com/demo\n")
        archive.writestr("demo-HEAD/src/payments/go.mod", "module example.com/payments\n")
        archive.writestr("demo-HEAD/tests/pom.xml", "<project/>\n")
        archive.writestr("demo-HEAD/docs/package-lock.json", json.dumps(lock))
        archive.writestr("demo-HEAD/testdata/yarn.lock", "# yarn lockfile v1\n")
        archive.comment = b"a" * 40

    def handler(request):
        if request.url.host == "api.github.com":
            return httpx.Response(403, json={"message": "rate limit exceeded"}, headers={"X-RateLimit-Remaining": "0"})
        if request.url.host == "codeload.github.com":
            return httpx.Response(200, content=buffer.getvalue())
        return httpx.Response(404)

    real_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr("app.sources.httpx.AsyncClient", lambda **kwargs: real_client(transport=transport, **kwargs))
    projects = asyncio.run(fetch_public_projects("acme/demo"))
    assert len(projects) == 1
    assert projects[0].repo == "acme/demo::docs"
    assert projects[0].sha == "a" * 40
    assert projects[0].other_manifests == ("go.mod", "src/payments/go.mod")


def test_rate_limited_api_and_failed_archive_use_shallow_git(monkeypatch):
    events = []
    request = httpx.Request("GET", "https://api.github.com/repos/acme/demo")
    response = httpx.Response(403, request=request, headers={"X-RateLimit-Remaining": "0"})
    expected = [Snapshot("acme/demo", "a" * 40, {}, {}, None, [], "public git")]

    async def api(_repo):
        raise httpx.HTTPStatusError("rate limited", request=request, response=response)

    async def archive(_repo):
        events.append("archive")
        raise SourceArchiveError("codeload unavailable")

    async def git(_repo):
        events.append("git")
        return expected

    monkeypatch.setattr("app.sources._fetch_public_projects_api", api)
    monkeypatch.setattr("app.sources._fetch_public_projects_archive", archive)
    monkeypatch.setattr("app.sources._fetch_public_projects_git", git)
    assert asyncio.run(fetch_public_projects("acme/demo")) == expected
    assert events == ["archive", "git"]


def test_both_public_fallbacks_fail_with_actionable_error(monkeypatch):
    request = httpx.Request("GET", "https://api.github.com/repos/acme/demo")
    response = httpx.Response(403, request=request, headers={"X-RateLimit-Remaining": "0"})

    async def api(_repo):
        raise httpx.HTTPStatusError("rate limited", request=request, response=response)

    async def archive(_repo):
        raise SourceArchiveError("codeload unavailable")

    async def git(_repo):
        raise SourceAcquisitionError("git unavailable")

    monkeypatch.setattr("app.sources._fetch_public_projects_api", api)
    monkeypatch.setattr("app.sources._fetch_public_projects_archive", archive)
    monkeypatch.setattr("app.sources._fetch_public_projects_git", git)
    with pytest.raises(SourceAcquisitionError, match="Set GITHUB_TOKEN"):
        asyncio.run(fetch_public_projects("acme/demo"))


def test_scan_reports_source_fallback_failure_as_service_unavailable(monkeypatch):
    async def advisory(_identifier):
        return Advisory("CVE-2026-12143", "Test advisory", "high", "", [
            AffectedPackage("form-data", "<2.5.6", "2.5.6")])

    async def projects(_repo):
        raise SourceAcquisitionError("GitHub API rate limited; public fallbacks unavailable")

    monkeypatch.setattr("app.main.fetch_advisory", advisory)
    monkeypatch.setattr("app.main.fetch_public_projects", projects)
    with pytest.raises(HTTPException) as failure:
        asyncio.run(scan_live(LiveScanRequest(repo="acme/demo", advisory="CVE-2026-12143")))
    assert failure.value.status_code == 503
    assert "fallbacks unavailable" in failure.value.detail


def test_osv_fallback_resolves_cve_alias_and_exact_npm_range(monkeypatch):
    def handler(request):
        if request.url.host == "api.github.com":
            return httpx.Response(403, json={"message": "rate limit exceeded"}, headers={"X-RateLimit-Remaining": "0"})
        if request.url.path.endswith("CVE-2022-24999"):
            return httpx.Response(200, json={"id": "CVE-2022-24999", "aliases": ["GHSA-hrpp-h998-j3pp"], "affected": []})
        if request.url.path.endswith("GHSA-hrpp-h998-j3pp"):
            return httpx.Response(200, json={"id": "GHSA-hrpp-h998-j3pp", "summary": "qs advisory", "database_specific": {"severity": "HIGH"},
                                             "affected": [{"package": {"ecosystem": "npm", "name": "qs"},
                                                           "ranges": [{"type": "SEMVER", "events": [{"introduced": "6.9.0"}, {"fixed": "6.9.7"}]}]}]})
        return httpx.Response(404)

    real_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr("app.advisories.httpx.AsyncClient", lambda **kwargs: real_client(transport=transport, **kwargs))
    advisory = asyncio.run(fetch_advisory("CVE-2022-24999"))
    assert advisory.identifier == "CVE-2022-24999"
    assert advisory.severity == "high"
    assert advisory.packages[0].name == "qs"
    assert is_affected("6.9.6", advisory.packages[0].vulnerable_range) is True
    assert is_affected("6.9.7", advisory.packages[0].vulnerable_range) is False
