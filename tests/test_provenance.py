"""Git history must not confuse a shallow clone boundary with an introducer."""

import json
import shutil
import subprocess

import pytest

from app.provenance import _git_history_fallback


def test_shallow_boundary_is_deepened_to_real_introducer(tmp_path):
    if not shutil.which("git"):
        pytest.skip("Git is required for provenance tracing")

    source = tmp_path / "source"
    source.mkdir()

    def git(*args):
        return subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "-c", "user.name=Test Author",
             "-c", "user.email=test@example.invalid", *args],
            cwd=source, capture_output=True, text=True, check=True,
        ).stdout.strip()

    git("init", "--initial-branch=main")
    lockfile = source / "package-lock.json"

    def pin(version):
        lockfile.write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/fixture": {"version": version},
        }}), encoding="utf-8")
        git("add", "package-lock.json")
        git("commit", "-m", "Change pinned version")

    pin("1.0.0")
    pin("2.0.0")
    introducer = git("rev-parse", "HEAD")
    for number in range(100):
        git("commit", "--allow-empty", "-m", f"Later change {number}")

    result = _git_history_fallback(
        "example/repo", git("rev-parse", "HEAD"), "package-lock.json",
        "node_modules/fixture", "2.0.0", source.as_uri(),
    )

    assert result["status"] == "verified"
    assert result["commit"] == introducer
    assert result["previous_version"] == "1.0.0"
