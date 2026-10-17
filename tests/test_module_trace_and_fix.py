import io
import json
import tarfile

from app.advisories import Advisory, AffectedPackage
from app.fixes import lockfile_refresh_plan
from app.module_trace import trace_archive
from app.sources import Snapshot


def _archive(files: dict[str, str]) -> bytes:
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for name, body in files.items():
            raw = body.encode()
            member = tarfile.TarInfo("package/" + name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    return data.getvalue()


def test_parent_main_and_cli_get_distinct_static_paths():
    archive = _archive({
        "package.json": json.dumps({"name": "parent", "version": "1.0.0", "main": "lib/index.js", "bin": {"parent": "bin/parent"}}),
        "lib/index.js": "module.exports = require('./runtime')\n",
        "lib/runtime.js": "module.exports = 1\n",
        "bin/parent": "#!/usr/bin/env node\nconst args = require('target')(process.argv.slice(2))\n",
    })
    trace = trace_archive(archive, "node_modules/parent", "node_modules/target", "target", "https://registry.npmjs.org/parent/-/parent-1.0.0.tgz")
    assert trace.status == "cli_only_static_path"
    assert trace.evidence_file == "bin/parent"
    assert trace.evidence_line == 2
    assert ("lib/index.js", "lib/runtime.js", 1) in trace.file_edges


def test_transitive_lockfile_fix_plan_checks_parent_range():
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"parent": "1.0.0", "unrelated": "1.0.0"}},
        "node_modules/parent": {"version": "1.0.0", "dependencies": {"target": "^1.2.5"}},
        "node_modules/target": {"version": "1.2.5", "resolved": "https://registry.npmjs.org/target/-/target-1.2.5.tgz", "integrity": "sha512-old"},
        "node_modules/unrelated": {"version": "1.0.0"},
    }}
    snapshot = Snapshot("owner/repo", "sha", lock, {"dependencies": {"parent": "1.0.0", "unrelated": "1.0.0"}}, None, [], "GitHub",
                        lockfile_text=json.dumps(lock, indent=2) + "\n")
    advisory = Advisory("CVE-2021-44906", "Example", "critical", "https://example.test", [AffectedPackage("target", ">=1.0.0 <1.2.6", "1.2.6")])
    plan = lockfile_refresh_plan(snapshot, advisory, "target")
    assert plan["strategy"] == "lockfile_refresh"
    assert plan["parent_name"] == "parent"
    assert plan["target"] == "1.2.6"
    assert plan["declared_range"] == "^1.2.5"
