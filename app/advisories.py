"""Public GitHub advisory lookup and npm version matching."""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx
from semantic_version import NpmSpec, Version


IDENTIFIER = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]{10,}|DEMO-2026-001)$", re.I)


@dataclass(frozen=True)
class AffectedPackage:
    name: str
    vulnerable_range: str
    first_patched: str | None


@dataclass(frozen=True)
class Advisory:
    identifier: str
    summary: str
    severity: str
    url: str
    packages: list[AffectedPackage]


DEMO_ADVISORY = Advisory(
    identifier="DEMO-2026-001",
    summary="Synthetic template parsing vulnerability for the live demo",
    severity="critical",
    url="",
    packages=[AffectedPackage("render-kit", "<1.2.4", "1.2.4")],
)


async def fetch_advisory(identifier: str) -> Advisory:
    identifier = identifier.upper().strip()
    if not IDENTIFIER.fullmatch(identifier):
        raise ValueError("Enter a CVE or GHSA identifier")
    if identifier == DEMO_ADVISORY.identifier:
        return DEMO_ADVISORY
    params = {"cve_id" if identifier.startswith("CVE-") else "ghsa_id": identifier, "ecosystem": "npm"}
    async with httpx.AsyncClient(timeout=12, headers={"Accept": "application/vnd.github+json", "User-Agent": "BlastRadius-demo"}) as client:
        response = await client.get("https://api.github.com/advisories", params=params)
        response.raise_for_status()
        results = response.json()
    if not results:
        raise LookupError("No public npm advisory was found for that identifier")
    item = results[0]
    packages = [
        AffectedPackage(
            name=row["package"]["name"],
            vulnerable_range=row["vulnerable_version_range"],
            first_patched=(
                row.get("first_patched_version", {}).get("identifier")
                if isinstance(row.get("first_patched_version"), dict)
                else row.get("first_patched_version")
            ),
        )
        for row in item.get("vulnerabilities", [])
        if row.get("package", {}).get("ecosystem") == "npm"
    ]
    return Advisory(
        identifier=identifier,
        summary=item.get("summary", "No summary supplied"),
        severity=item.get("severity", "unknown"),
        url=item.get("html_url", ""),
        packages=packages,
    )


def is_affected(version: str, vulnerable_range: str) -> bool | None:
    """None means the advisory range or installed version cannot be interpreted."""
    try:
        normalized = re.sub(r"([<>=~^]+)\s+", r"\1", vulnerable_range.replace(",", " "))
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return Version.coerce(version) in NpmSpec(normalized)
    except (ValueError, TypeError):
        return None
