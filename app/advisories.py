"""Public GitHub advisory lookup and npm version matching."""

from __future__ import annotations

import re
import os
from dataclasses import dataclass

import httpx
from semantic_version import NpmSpec, Version
from packaging.specifiers import SpecifierSet
from packaging.version import Version as PythonVersion
from packaging.utils import canonicalize_name


IDENTIFIER = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]{10,})$", re.I)


@dataclass(frozen=True)
class AffectedPackage:
    name: str
    vulnerable_range: str
    first_patched: str | None
    ecosystem: str = "npm"


@dataclass(frozen=True)
class Advisory:
    identifier: str
    summary: str
    severity: str
    url: str
    packages: list[AffectedPackage]


def _osv_packages(item: dict) -> list[AffectedPackage]:
    packages: list[AffectedPackage] = []
    for affected in item.get("affected", []):
        package = affected.get("package", {})
        ecosystem = package.get("ecosystem")
        if ecosystem not in ("npm", "PyPI") or not package.get("name"):
            continue
        name = canonicalize_name(package["name"]) if ecosystem == "PyPI" else package["name"]
        for entry in affected.get("ranges", []):
            if entry.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            introduced: str | None = None
            for event in entry.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event and introduced is not None:
                    fixed = event["fixed"]
                    low = f">={introduced} " if introduced != "0" else ""
                    packages.append(AffectedPackage(name, f"{low}<{fixed}", fixed, ecosystem))
                    introduced = None
                elif "last_affected" in event and introduced is not None:
                    low = f">={introduced} " if introduced != "0" else ""
                    packages.append(AffectedPackage(name, f"{low}<={event['last_affected']}", None, ecosystem))
                    introduced = None
            if introduced is not None:
                packages.append(AffectedPackage(name, f">={introduced}" if introduced != "0" else ">=0.0.0", None, ecosystem))
        if not affected.get("ranges"):
            for version in affected.get("versions", []):
                packages.append(AffectedPackage(name, f"=={version}", None, ecosystem))
    return packages


async def _fetch_osv_advisory(identifier: str) -> Advisory:
    async with httpx.AsyncClient(timeout=15, headers={"User-Agent": "LastHop-demo"}) as client:
        response = await client.get(f"https://api.osv.dev/v1/vulns/{identifier}")
        if response.status_code == 404:
            raise LookupError("No public advisory was found for that identifier")
        response.raise_for_status()
        item = response.json()
        packages = _osv_packages(item)
        if not packages:
            for alias in item.get("aliases", []):
                if not alias.startswith("GHSA-"):
                    continue
                alias_response = await client.get(f"https://api.osv.dev/v1/vulns/{alias}")
                if alias_response.status_code == 404:
                    continue
                alias_response.raise_for_status()
                candidate = alias_response.json()
                packages = _osv_packages(candidate)
                if packages:
                    item = candidate
                    break
    return Advisory(
        identifier=identifier,
        summary=item.get("summary") or item.get("details", "No summary supplied")[:180],
        severity=str(item.get("database_specific", {}).get("severity", "unknown")).lower(),
        url=f"https://osv.dev/vulnerability/{item.get('id', identifier)}",
        packages=packages,
    )


async def fetch_advisory(identifier: str) -> Advisory:
    identifier = identifier.upper().strip()
    if not IDENTIFIER.fullmatch(identifier):
        raise ValueError("Enter a CVE or GHSA identifier")
    params = {"cve_id" if identifier.startswith("CVE-") else "ghsa_id": identifier}
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "LastHop-demo"}
    if token := os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(timeout=12, headers=headers) as client:
        response = await client.get("https://api.github.com/advisories", params=params)
        limited = response.headers.get("X-RateLimit-Remaining") == "0" or "rate limit" in response.text.lower()
        if response.status_code == 429 or (response.status_code == 403 and limited):
            return await _fetch_osv_advisory(identifier)
        response.raise_for_status()
        results = response.json()
    if not results:
        raise LookupError("No public advisory was found for that identifier")
    item = results[0]
    packages = [
        AffectedPackage(
            name=canonicalize_name(row["package"]["name"]) if row["package"]["ecosystem"] in ("pip", "PyPI") else row["package"]["name"],
            vulnerable_range=row["vulnerable_version_range"],
            first_patched=(
                row.get("first_patched_version", {}).get("identifier")
                if isinstance(row.get("first_patched_version"), dict)
                else row.get("first_patched_version")
            ),
            ecosystem="PyPI" if row["package"]["ecosystem"] in ("pip", "PyPI") else "npm",
        )
        for advisory in results for row in advisory.get("vulnerabilities", [])
        if row.get("package", {}).get("ecosystem") in ("npm", "pip", "PyPI")
    ]
    return Advisory(
        identifier=identifier,
        summary=item.get("summary", "No summary supplied"),
        severity=item.get("severity", "unknown"),
        url=item.get("html_url", ""),
        packages=packages,
    )


def is_affected(version: str, vulnerable_range: str, ecosystem: str = "npm") -> bool | None:
    """None means the advisory range or installed version cannot be interpreted."""
    try:
        normalized = re.sub(r"([<>=~^]+)\s+", r"\1", vulnerable_range.replace(",", " "))
        normalized = re.sub(r"\s+", " ", normalized).strip()
        if ecosystem == "PyPI":
            return PythonVersion(version) in SpecifierSet(",".join(normalized.split()))
        return Version.coerce(version) in NpmSpec(normalized)
    except (ValueError, TypeError):
        return None
