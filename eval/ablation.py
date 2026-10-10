"""Small, reproducible synthetic comparison: package alerts vs graph triage."""

import os

from app.advisories import DEMO_ADVISORY
from app.graph import GraphStore
from app.main import investigate_one
from demo.fixtures import demo_snapshots


def main() -> None:
    os.environ["GRAPH_NAME"] = "blastradius_eval"
    graph = GraphStore()
    snapshots = demo_snapshots()
    for snapshot in snapshots:
        graph.ingest(snapshot)
    results = [investigate_one(graph, snapshot.repo, DEMO_ADVISORY) for snapshot in snapshots]
    package_only = sum(bool(result["vulnerable_paths"]) for result in results)
    public_priorities = sum(result["verdict"] == "affected_exposed" for result in results)
    print("Synthetic evaluation — DEMO-2026-001")
    print(f"Package-only alerts: {package_only}/{len(results)} repos")
    print(f"Graph-evidenced public priorities: {public_priorities}/{len(results)} repos")
    for result in results:
        print(f"  {result['repo']}: {result['verdict']}")
    print("The comparison is an illustrative fixture, not a real-world accuracy claim.")


if __name__ == "__main__":
    main()
