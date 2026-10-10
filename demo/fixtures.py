"""Clearly labeled synthetic data for a deterministic judge demo."""

from app.sources import Snapshot


def demo_snapshots() -> list[Snapshot]:
    storefront = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"web-framework": "3.0.0"}},
            "node_modules/web-framework": {"version": "3.0.0", "dependencies": {"render-kit": "^1.2.0"}},
            "node_modules/web-framework/node_modules/render-kit": {"version": "1.2.0"},
        },
    }
    internal = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"render-kit": "1.2.0"}},
            "node_modules/render-kit": {"version": "1.2.0"},
        },
    }
    worker = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"safe-parser": "2.0.0"}},
            "node_modules/safe-parser": {"version": "2.0.0"},
        },
    }
    return [
        Snapshot("demo/storefront", "synthetic-001", storefront, {}, "@web-team", [
            {"name": "storefront", "exposure": "public", "public_route": "https://store.example.test"}
        ], "synthetic demo fixture"),
        Snapshot("demo/internal-api", "synthetic-001", internal, {}, "@platform-team", [
            {"name": "internal-api", "exposure": "internal", "public_route": None}
        ], "synthetic demo fixture"),
        Snapshot("demo/worker", "synthetic-001", worker, {}, "@ops-team", [
            {"name": "worker", "exposure": "internal", "public_route": None}
        ], "synthetic demo fixture"),
    ]
