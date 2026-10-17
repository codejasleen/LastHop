import asyncio
from types import SimpleNamespace

import httpx
import pytest

import app.issues as issues

PROJECT = "o/boutique::src/emailservice#pip"
ADVISORY = SimpleNamespace(identifier="CVE-2026-44432", summary="urllib3: decompression bomb", severity="high",
                           url="https://github.com/advisories/GHSA-x", packages=[
                               SimpleNamespace(name="urllib3", ecosystem="PyPI", vulnerable_range=">= 2.6.0, < 2.7.0",
                                               first_patched="2.7.0")])


class FakeGraph:
    def paths_to(self, project, name):
        return [{"version": "2.6.3", "dependency_id": f"{project}:urllib3",
                 "nodes": [{"id": project}, {"name": "requests"}, {"name": "urllib3"}]}]

    def context(self, project, advisory):
        path = [{"id": "internet"}, {"kind": "LoadBalancer", "evidence": "k8s/frontend.yaml"},
                {"name": "frontend", "evidence": "k8s/frontend.yaml"}, {"name": "emailservice", "evidence": "k8s/email.yaml"}]
        return {"sha": "38e7348eb289", "owner": "@org/maintainers", "decisions": [],
                "services": [{"name": "emailservice", "exposure": "public", "exposure_path": path}]}

    def cut_points(self, project, dependency_id):
        return {"shared_by_all": [{"package": "requests"}]}


def test_draft_is_written_from_graph_facts_and_never_pings_owners():
    fix = {"strategy": "requirements_pin", "target": "2.7.0", "file": "src/emailservice/requirements.txt",
           "parents_checked": ["requests 2.32.5 allows urllib3<3,>=1.21.1"]}
    draft = issues.draft_issue(FakeGraph(), PROJECT, ADVISORY, {"kev": False, "epss": 0.0088, "epss_percentile": 0.58}, fix)
    assert draft["title"] == "CVE-2026-44432: urllib3 2.6.3 in emailservice is reachable from the internet"
    body = draft["body"]
    assert "Internet → LoadBalancer → frontend → emailservice" in body
    assert "`emailservice → requests → urllib3`" in body and "enters through `requests`" in body
    assert "Pin `urllib3==2.7.0` in `src/emailservice/requirements.txt`" in body
    assert "Owner (CODEOWNERS): org/maintainers" in body and "@org" not in body


def test_issue_is_not_filed_without_the_approval_key(monkeypatch):
    monkeypatch.setenv("BLASTRADIUS_ADMIN_KEY", "right")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    with pytest.raises(PermissionError):
        asyncio.run(issues.create_issue("o/boutique", "title", "body text long enough", "wrong"))


def test_disabled_issues_on_a_fork_give_a_clear_message(monkeypatch):
    monkeypatch.setenv("BLASTRADIUS_ADMIN_KEY", "right")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    real = httpx.AsyncClient
    monkeypatch.setattr(issues.httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(lambda request: httpx.Response(410)), **kw))
    with pytest.raises(ValueError, match="Issues are disabled"):
        asyncio.run(issues.create_issue("o/boutique", "title", "body text long enough", "right"))


def test_filed_issue_returns_its_link(monkeypatch):
    monkeypatch.setenv("BLASTRADIUS_ADMIN_KEY", "right")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    sent = []

    def handler(request):
        sent.append((request.url.path, request.read()))
        return httpx.Response(201, json={"html_url": "https://github.com/o/boutique/issues/7", "number": 7})
    real = httpx.AsyncClient
    monkeypatch.setattr(issues.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    assert asyncio.run(issues.create_issue("o/boutique", "title", "body text long enough", "right")) == {
        "url": "https://github.com/o/boutique/issues/7", "number": 7}
    assert sent[0][0] == "/repos/o/boutique/issues"
