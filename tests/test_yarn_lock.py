import pytest

from app.yarn_lock import parse_yarn_project


YARN = """# yarn lockfile v1

server@^1.0.0:
  version "1.0.2"
  dependencies:
    qs "^6.5.0"

qs@^6.5.0, qs@~6.5.0:
  version "6.5.3"

dev-only@^2.0.0:
  version "2.0.0"
"""


def test_yarn_classic_traces_only_production_from_exact_resolution():
    manifest = {"dependencies": {"server": "^1.0.0"}, "devDependencies": {"dev-only": "^2.0.0"}}
    deps, edges = parse_yarn_project(YARN, manifest)
    assert {(dep.name, dep.version) for dep in deps} == {("server", "1.0.2"), ("qs", "6.5.3")}
    assert edges == [("", "server@1.0.2"), ("server@1.0.2", "qs@6.5.3")]


def test_yarn_classic_refuses_missing_or_newer_format():
    with pytest.raises(ValueError, match="no exact resolution"):
        parse_yarn_project(YARN, {"dependencies": {"server": "^2.0.0"}})
    with pytest.raises(ValueError, match="Only Yarn Classic"):
        parse_yarn_project("__metadata:\n  version: 8", {"dependencies": {}})
    with pytest.raises(ValueError, match="workspace-aware"):
        parse_yarn_project(YARN, {"workspaces": ["packages/*"]})
