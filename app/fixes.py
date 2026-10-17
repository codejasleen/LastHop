"""Evidence-checked fix plans for GitHub issue drafts."""

from __future__ import annotations

import httpx
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from .advisories import Advisory, is_affected
from .lockfile import parse_lockfile
from .pip_requirements import _via, parse_requirements
from .sources import Snapshot


def lockfile_refresh_plan(snapshot: Snapshot, advisory: Advisory, name: str) -> dict:
    """Prove the patched version fits the immediate parent's declared range."""
    if snapshot.manager != "npm":
        raise ValueError("Automated lockfile refresh currently requires an npm project")
    matches = [d for d in parse_lockfile(snapshot.lockfile) if d.name == name
               and any(p.name == name and is_affected(d.version, p.vulnerable_range) is True for p in advisory.packages)]
    if len(matches) != 1:
        raise ValueError("A lockfile refresh needs exactly one affected installed package instance")
    dep = matches[0]
    parent = snapshot.lockfile["packages"][dep.parent_path or ""]
    declared = parent.get("dependencies", {}).get(name) or parent.get("optionalDependencies", {}).get(name)
    if not declared:
        raise ValueError("The parent has no production dependency declaration for this package")
    target = _safe_target(advisory, name, dep.version)
    fits = is_affected(target, declared)
    return {"package": name, "before": dep.version, "target": target, "dependency_path": dep.path, "parent": dep.parent_path or "",
            "parent_name": dep.parent_path.rsplit("node_modules/", 1)[-1] if dep.parent_path else "repo",
            "declared_range": declared, "direct": dep.direct, "strategy": "lockfile_refresh" if fits is True else "parent_upgrade_needed"}


def _safe_target(advisory: Advisory, name: str, installed: str) -> str:
    matching = [p for p in advisory.packages if p.name == name and is_affected(installed, p.vulnerable_range) is True]
    patched = [p.first_patched for p in matching if p.first_patched]
    if not patched:
        raise ValueError("The advisory has no first patched version for this installed package")
    # Multiple affected ranges can describe different release lines. Use the
    # patched version belonging to the matching installed range.
    return patched[0]


async def requirements_pin_plan(snapshot: Snapshot, advisory: Advisory, name: str) -> dict:
    """Prove a one-line requirements.txt pin change is safe: the patched version exists on PyPI,
    is not yanked, and every package that pulls this one in (pip-compile `# via`) allows it."""
    if snapshot.manager != "pip":
        raise ValueError("A requirements pin fix needs a Python requirements.txt project")
    name = canonicalize_name(name)
    text = snapshot.lockfile_text or ""
    installed = {dep.name: dep.version for dep in parse_requirements(text)[0]}
    if name not in installed:
        raise ValueError(f"{name} is not pinned in {snapshot.lockfile_path}")
    before = installed[name]
    patched = [p.first_patched for p in advisory.packages if canonicalize_name(p.name) == name and p.first_patched
               and is_affected(before, p.vulnerable_range, "PyPI") is True]
    if not patched:
        raise ValueError("The advisory has no patched version for the installed release")
    target = patched[0]
    if "--hash" in text:
        raise ValueError(f"this file pins hashes, so regenerate it: pip-compile --upgrade-package {name}=={target}")
    checked = []
    async with httpx.AsyncClient(timeout=15) as client:
        release = await client.get(f"https://pypi.org/pypi/{name}/{target}/json")
        if release.status_code != 200 or release.json().get("info", {}).get("yanked"):
            raise ValueError(f"{name} {target} is not an available release on PyPI")
        for parent in [canonicalize_name(r.split()[0]) for r in _via(text).get(name, []) if not r.startswith("-")]:
            if parent not in installed:
                continue
            meta = await client.get(f"https://pypi.org/pypi/{parent}/{installed[parent]}/json")
            meta.raise_for_status()
            for spec in meta.json().get("info", {}).get("requires_dist") or []:
                requirement = Requirement(spec)
                if canonicalize_name(requirement.name) != name or (requirement.marker and "extra" in str(requirement.marker)):
                    continue
                if not requirement.specifier.contains(target, prereleases=True):
                    raise ValueError(f"{parent} {installed[parent]} requires {name}{requirement.specifier}, "
                                     f"which excludes {target}; upgrade {parent} first")
                checked.append(f"{parent} {installed[parent]} allows {name}{requirement.specifier or ' (any)'}")
    return {"package": name, "before": before, "target": target, "strategy": "requirements_pin",
            "file": snapshot.lockfile_path, "parents_checked": checked}
