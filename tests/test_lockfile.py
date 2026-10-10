import pytest

from app.lockfile import edges_from_lockfile, parse_lockfile


def test_repo_specific_nested_pin_and_hoisted_resolution():
    lock = {"packages": {
        "": {"dependencies": {"server": "1.0.0", "shared": "2.0.0"}},
        "node_modules/server": {"version": "1.0.0", "dependencies": {"shared": "^1.0.0", "nested": "1.0.0"}},
        "node_modules/server/node_modules/shared": {"version": "1.0.0"},
        "node_modules/server/node_modules/nested": {"version": "1.0.0", "dependencies": {"shared": "^1.0.0"}},
        "node_modules/shared": {"version": "2.0.0"},
    }}
    deps = parse_lockfile(lock)
    assert {(d.path, d.version) for d in deps} == {
        ("node_modules/server", "1.0.0"),
        ("node_modules/shared", "2.0.0"),
        ("node_modules/server/node_modules/shared", "1.0.0"),
        ("node_modules/server/node_modules/nested", "1.0.0"),
    }
    edges = edges_from_lockfile(lock, deps)
    assert ("node_modules/server", "node_modules/server/node_modules/shared") in edges
    assert ("node_modules/server/node_modules/nested", "node_modules/server/node_modules/shared") in edges


def test_missing_lockfile_node_is_not_treated_as_complete_inventory():
    with pytest.raises(ValueError, match="no installed package"):
        parse_lockfile({"packages": {"": {"dependencies": {"missing": "1.0.0"}}}})
