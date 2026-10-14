import asyncio
import io
import json
import zipfile

import httpx

from app.advisories import fetch_advisory, is_affected
from app.sources import fetch_public_projects


def test_public_archive_fallback_keeps_commit_and_project_scope(monkeypatch):
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"qs": "6.5.3"}},
        "node_modules/qs": {"version": "6.5.3"},
    }}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("demo-HEAD/go.mod", "module example.com/demo\n")
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
    assert projects[0].other_manifests == ("go.mod",)


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
