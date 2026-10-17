import asyncio
from types import SimpleNamespace

import httpx
import pytest

import app.fixes as fixes

REQUIREMENTS = (
    "requests==2.32.5\n    # via -r requirements.in\n"
    "urllib3==2.6.3\n    # via requests\n"
)
ADVISORY = SimpleNamespace(identifier="CVE-2026-44432", url="https://example.test/advisory", packages=[
    SimpleNamespace(name="urllib3", ecosystem="PyPI", vulnerable_range=">= 2.6.0, < 2.7.0", first_patched="2.7.0")])


def snapshot(text=REQUIREMENTS):
    return SimpleNamespace(manager="pip", lockfile_text=text, lockfile_path="src/emailservice/requirements.txt",
                           repo="o/r::src/emailservice#pip", sha="38e7348")


def fake_pypi(monkeypatch, urllib3_range="<3,>=1.21.1"):
    def handler(request):
        if request.url.path == "/pypi/urllib3/2.7.0/json":
            return httpx.Response(200, json={"info": {"yanked": False}})
        if request.url.path == "/pypi/requests/2.32.5/json":
            return httpx.Response(200, json={"info": {"requires_dist": [
                f"urllib3{urllib3_range}", 'PySocks!=1.5.7,>=1.5.6; extra == "socks"']}})
        return httpx.Response(404)
    real = httpx.AsyncClient
    monkeypatch.setattr(fixes.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler)))


def test_safe_pin_plan_includes_its_checks(monkeypatch):
    fake_pypi(monkeypatch)
    plan = asyncio.run(fixes.requirements_pin_plan(snapshot(), ADVISORY, "urllib3"))
    assert plan["before"] == "2.6.3"
    assert plan["target"] == "2.7.0"
    assert plan["strategy"] == "requirements_pin"
    assert plan["parents_checked"] == ["requests 2.32.5 allows urllib3<3,>=1.21.1"]


def test_parent_that_excludes_the_fix_blocks_the_plan(monkeypatch):
    fake_pypi(monkeypatch, urllib3_range="<2.7,>=1.21.1")
    with pytest.raises(ValueError, match="upgrade requests first"):
        asyncio.run(fixes.requirements_pin_plan(snapshot(), ADVISORY, "urllib3"))


def test_hashed_requirements_are_never_hand_edited(monkeypatch):
    fake_pypi(monkeypatch)
    hashed = REQUIREMENTS.replace("urllib3==2.6.3\n", "urllib3==2.6.3 \\\n    --hash=sha256:abc\n")
    with pytest.raises(ValueError, match="regenerate it"):
        asyncio.run(fixes.requirements_pin_plan(snapshot(hashed), ADVISORY, "urllib3"))
