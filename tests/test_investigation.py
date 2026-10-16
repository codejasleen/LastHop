from app.advisories import Advisory, AffectedPackage, is_affected
from app.main import investigate_one


TEST_ADVISORY = Advisory("CVE-2026-12143", "Test advisory", "high", "", [AffectedPackage("form-data", "<2.5.6", "2.5.6")])


class FakeGraph:
    def __init__(self, path, exposure):
        self.path = path
        self.exposure = exposure
        self.linked = []

    def paths_to(self, repo, package):
        return self.path

    def context(self, repo, advisory):
        return {"owner": "@team", "services": self.exposure, "decisions": []}

    def link_advisory(self, advisory, summary, dependency_ids):
        self.linked = dependency_ids


def test_affected_public_result_carries_graph_path():
    graph = FakeGraph(
        [{"nodes": [{"id": "example/service"}, {"name": "retry-request"}, {"name": "form-data"}], "version": "2.5.5", "dependency_id": "example/service:form-data"}],
        [{"name": "storefront", "exposure": "public", "public_route": "https://example.test"}],
    )
    result = investigate_one(graph, "example/service", TEST_ADVISORY)
    assert result["verdict"] == "affected_exposed"
    assert result["vulnerable_paths"][0]["path"] == ["example/service", "retry-request", "form-data"]
    assert graph.linked == ["example/service:form-data"]


def test_unknown_exposure_stays_unknown():
    graph = FakeGraph([{"nodes": [{"id": "repo"}, {"name": "form-data"}], "version": "2.5.5", "dependency_id": "repo:form-data"}], [])
    assert investigate_one(graph, "repo", TEST_ADVISORY)["verdict"] == "affected_exposure_unknown"


def test_npm_semver_not_lexicographic():
    assert is_affected("1.2.10", "<1.2.4") is False
    assert is_affected("1.2.0", "<1.2.4") is True
    assert is_affected("6.10.1", ">= 6.10.0, < 6.10.3") is True
