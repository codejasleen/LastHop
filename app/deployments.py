"""Extract bounded, declared Kubernetes network evidence from repository YAML."""

from __future__ import annotations

import re
from typing import Any

import yaml


HOST = re.compile(r"^(?:https?://)?([a-z][a-z0-9-]*)(?::\d+)?(?:/.*)?$", re.I)


def parse_kubernetes(files: dict[str, str]) -> list[dict[str, Any]]:
    """Return workloads and routes with source paths; no runtime claim is made."""
    deployments: dict[str, dict[str, Any]] = {}
    services: list[dict[str, Any]] = []
    ingresses: list[dict[str, Any]] = []
    for path, source in files.items():
        try:
            docs = yaml.safe_load_all(source)
            for doc in docs:
                if not isinstance(doc, dict):
                    continue
                name = doc.get("metadata", {}).get("name")
                if not isinstance(name, str) or not name:
                    continue
                kind = doc.get("kind")
                spec = doc.get("spec") or {}
                if kind == "Deployment":
                    template = spec.get("template") or {}
                    labels = (template.get("metadata") or {}).get("labels") or {}
                    calls = []
                    for container in (template.get("spec") or {}).get("containers") or []:
                        for env in container.get("env") or []:
                            if not isinstance(env, dict) or not str(env.get("name", "")).endswith(("_ADDR", "_URL", "_HOST")):
                                continue
                            match = HOST.fullmatch(str(env.get("value", "")))
                            if match:
                                calls.append({"target": match.group(1), "variable": env["name"], "source": path})
                    deployments[name] = {"name": name, "labels": labels, "calls": calls, "source": path}
                elif kind == "Service":
                    services.append({"name": name, "selector": spec.get("selector") or {},
                                     "type": spec.get("type", "ClusterIP"), "source": path})
                elif kind == "Ingress":
                    for rule in spec.get("rules") or []:
                        for entry in ((rule.get("http") or {}).get("paths") or []):
                            target = ((entry.get("backend") or {}).get("service") or {}).get("name")
                            if target:
                                ingresses.append({"target": target, "host": rule.get("host"), "source": path})
        except yaml.YAMLError:
            continue
    for item in deployments.values():
        item["public_routes"] = []
        item["service_names"] = []
        for service in services:
            selector = service["selector"]
            if selector and all(item["labels"].get(key) == value for key, value in selector.items()):
                item["service_names"].append(service["name"])
                if service["type"] == "LoadBalancer":
                    item["public_routes"].append({"kind": "LoadBalancer", "service": service["name"], "source": service["source"]})
        for ingress in ingresses:
            if ingress["target"] in item["service_names"]:
                item["public_routes"].append({"kind": "Ingress", "service": ingress["target"],
                                              "host": ingress["host"], "source": ingress["source"]})
    service_to_workload = {service: workload["name"] for workload in deployments.values() for service in workload["service_names"]}
    for item in deployments.values():
        for call in item["calls"]:
            call["workload"] = service_to_workload.get(call["target"])
    return list(deployments.values())
