import json

from app.agent import _compact, _reason


def test_scan_result_is_compacted_to_affected_facts():
    scan = {
        "source": {"repo": "o/r", "sha": "38e7348eb289", "projects": 2, "other_manifests": ["src/frontend/go.mod"]},
        "advisory": {"id": "CVE-1", "summary": "s", "severity": "high", "packages": ["PyPI:urllib3"]},
        "risk_signals": {"kev": False, "epss": 0.01, "epss_percentile": 0.5},
        "results": [
            {"repo": "o/r::src/email#pip", "verdict": "declared_exposed", "owner": "@team", "vulnerable_path_count": 3,
             "vulnerable_paths": [{"path": ["o/r::src/email#pip", "requests", "urllib3"], "package": "urllib3",
                                   "version": "2.6.3", "dependency_id": "o/r::src/email#pip:urllib3"}],
             "fix_candidates": [{"first_patched": "2.7.0", "strategy": "manual_review", "reason": "regenerate"}]},
            {"repo": "o/r::src/cart", "verdict": "not_applicable", "vulnerable_paths": []},
        ],
    }
    facts = json.loads(_compact("scan_public_repo", scan))
    assert facts["affected"][0]["internet"] == "reachable from the internet"
    assert facts["affected"][0]["shortest_path"] == ["requests", "urllib3"]
    assert facts["affected"][0]["fix"][0]["to"] == "2.7.0"
    assert facts["other_ecosystem"] == ["o/r::src/cart"]
    assert facts["not_analyzed_manifests"] == ["src/frontend/go.mod"]


def test_cut_points_always_carry_their_meaning():
    facts = json.loads(_compact("cut_points", {"shared_by_all": [{"package": "requests", "version": "2.32.5"}],
                                               "rows": [{"package": "requests", "through": 3, "total": 3}]}))
    assert facts["all_paths_pass_through"] == ["requests@2.32.5"]
    assert "does not remove the vulnerable version" in facts["meaning"]


def test_large_outputs_are_truncated_for_free_tier_models():
    assert len(_compact("query_graph", {"rows": ["x" * 50] * 500})) <= 3520


def test_reason_prefers_content_then_reasoning():
    assert _reason({"content": "Need exposure for emailservice."}) == "Need exposure for emailservice."
    assert _reason({"content": "", "reasoning": "Check memory first."}) == "Check memory first."
