import asyncio
import base64
import json

import httpx

from app.graph import dependency_graph
from app.sources import fetch_public_projects


def test_discovers_nested_npm_and_pnpm_projects_at_one_commit(monkeypatch):
    npm = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"qs": "6.5.0"}},
        "node_modules/qs": {"version": "6.5.0"},
    }}
    pnpm = """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.0.0
        version: 4.17.20
snapshots:
  lodash@4.17.20: {}
"""
    files = {
        "frontend/package-lock.json": json.dumps(npm).encode(),
        "legacy/package.json": json.dumps({"dependencies": {"lodash": "^4.0.0"}}).encode(),
        "legacy/yarn.lock": b'# yarn lockfile v1\n\nlodash@^4.0.0:\n  version "4.17.20"\n',
        "tools/pnpm-lock.yaml": pnpm.encode(),
    }

    def handler(request):
        path = request.url.path
        if path == "/repos/acme/mono":
            return httpx.Response(200, json={"private": False, "default_branch": "main"})
        if path == "/repos/acme/mono/commits/main":
            return httpx.Response(200, json={"sha": "commit-123"})
        if path == "/repos/acme/mono/git/trees/commit-123":
            return httpx.Response(200, json={"truncated": False, "tree": [
                {"path": name, "type": "blob"} for name in files
            ]})
        prefix = "/repos/acme/mono/contents/"
        if path.startswith(prefix) and path[len(prefix):] in files:
            content = files[path[len(prefix):]]
            return httpx.Response(200, json={"encoding": "base64", "size": len(content),
                                             "content": base64.b64encode(content).decode()})
        return httpx.Response(404)

    real_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr("app.sources.httpx.AsyncClient", lambda **kwargs: real_client(transport=transport, **kwargs))
    snapshots = asyncio.run(fetch_public_projects("acme/mono"))
    assert [(item.repo, item.manager) for item in snapshots] == [
        ("acme/mono::frontend", "npm"), ("acme/mono::legacy", "yarn"),
        ("acme/mono::tools", "pnpm")
    ]
    assert [[dep.name for dep in dependency_graph(item)[0]] for item in snapshots] == [["qs"], ["lodash"], ["lodash"]]
