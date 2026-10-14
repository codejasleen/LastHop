import pytest

from app.pnpm_lock import parse_pnpm_project


def test_pnpm_v9_keeps_exact_nested_versions_and_production_paths():
    lock = {
        "lockfileVersion": "9.0",
        "importers": {".": {"dependencies": {"server": {"version": "1.0.0"}},
                            "devDependencies": {"dev-only": {"version": "1.0.0"}}}},
        "snapshots": {
            "server@1.0.0": {"dependencies": {"shared": "1.0.0"}},
            "shared@1.0.0": {},
            "dev-only@1.0.0": {},
        },
    }
    deps, edges = parse_pnpm_project(lock, ".")
    assert {(dep.name, dep.version) for dep in deps} == {("server", "1.0.0"), ("shared", "1.0.0")}
    assert edges == [("", "server@1.0.0"), ("server@1.0.0", "shared@1.0.0")]


def test_pnpm_rejects_incomplete_or_workspace_paths():
    lock = {"lockfileVersion": "9.0", "importers": {".": {"dependencies": {"local": {"version": "link:packages/local"}}}}, "snapshots": {}}
    with pytest.raises(ValueError, match="cannot be traced"):
        parse_pnpm_project(lock, ".")
    lock["importers"]["."]["dependencies"]["local"]["version"] = "1.0.0"
    with pytest.raises(ValueError, match="snapshot is missing"):
        parse_pnpm_project(lock, ".")
