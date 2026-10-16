"""Current, source-linked KEV and EPSS context; failed lookups stay unknown."""

from __future__ import annotations

import time
from typing import Any

import httpx


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
_kev_cache: tuple[float, set[str], str | None] | None = None


async def fetch_risk_signals(identifier: str) -> dict[str, Any]:
    global _kev_cache
    result: dict[str, Any] = {"kev": None, "epss": None, "epss_percentile": None,
                              "kev_source": KEV_URL, "epss_source": EPSS_URL, "epss_date": None}
    if not identifier.startswith("CVE-"):
        return result
    async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
        try:
            if _kev_cache is None or time.monotonic() - _kev_cache[0] > 3600:
                response = await client.get(KEV_URL)
                response.raise_for_status()
                payload = response.json()
                identifiers = {row["cveID"] for row in payload["vulnerabilities"]}
                _kev_cache = (time.monotonic(), identifiers, payload.get("dateReleased"))
            result["kev"] = identifier in _kev_cache[1]
            result["kev_catalog_date"] = _kev_cache[2]
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            pass
        try:
            response = await client.get(EPSS_URL, params={"cve": identifier})
            response.raise_for_status()
            rows = response.json().get("data", [])
            if rows:
                result["epss"] = float(rows[0]["epss"])
                result["epss_percentile"] = float(rows[0]["percentile"])
                result["epss_date"] = rows[0].get("date")
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            pass
    return result


def assign_priority(result: dict, signals: dict) -> tuple[str, list[str]]:
    if not result.get("vulnerable_paths"):
        return "None", ["No affected installed package path"]
    if any(path.get("evidence_kind") == "declared_pin" for path in result["vulnerable_paths"]):
        return "Review", ["Affected pinned Python requirement", "Installation and transitive dependencies are unverified"]
    statuses = {row["status"] for row in result.get("module_evidence", [])}
    exposed = result["verdict"] == "affected_exposed"
    reasons = []
    if exposed:
        reasons.append("Declared path from public entry point")
    else:
        reasons.append("Public exposure unproven")
    if "runtime_static_path" in statuses:
        reasons.append("Static import path from package main")
    elif "cli_only_static_path" in statuses:
        reasons.append("Static import seen in CLI only; dynamic/runtime use unresolved")
    if signals.get("kev") is True:
        reasons.append("Listed in CISA KEV")
    if signals.get("epss") is not None:
        reasons.append(f"EPSS {signals['epss']:.2%}")
    exploitation = signals.get("kev") is True or (signals.get("epss") or 0) >= 0.1
    if exposed and "runtime_static_path" in statuses and exploitation:
        return "P1", reasons
    if (exposed and exploitation) or (exposed and "runtime_static_path" in statuses):
        return "P2", reasons
    if "cli_only_static_path" in statuses:
        return "P3", reasons
    return "Review", reasons
