import asyncio
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace

from app.agent import _compact, _reason, _remember, investigate
from app.graph import GraphStore


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


def test_agent_limits_llm_chosen_calls_and_requests_tool_free_final(monkeypatch):
    import app.agent as agent

    called_tools = []
    choices = []

    @asynccontextmanager
    async def fake_stdio(_server):
        yield None, None

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

        async def initialize(self):
            pass

        async def list_tools(self):
            return SimpleNamespace(tools=[SimpleNamespace(name=name, description="", inputSchema={})
                                          for name in ("query_graph", "graph_blast_radius")])

        async def call_tool(self, name, arguments, **_kwargs):
            called_tools.append(name)
            value = {"rows": []} if name == "graph_blast_radius" else {"rows": [], "cypher": arguments["cypher"]}
            return SimpleNamespace(isError=False, structuredContent={"result": value}, content=[])

    class FakeGraphStore:
        def schema_summary(self):
            return {}

    async def fake_chat(_messages, _tools, tool_choice="auto"):
        choices.append(tool_choice)
        if tool_choice == "none":
            return {"content": "Final answer."}, "fake", "fake-model"
        return {"content": "Checking graph paths.", "tool_calls": [
            {"id": f"call-{n}", "function": {"name": "query_graph", "arguments": json.dumps({"cypher": f"RETURN {n}"})}}
            for n in range(12)
        ]}, "fake", "fake-model"

    monkeypatch.setattr(agent, "stdio_client", fake_stdio)
    monkeypatch.setattr(agent, "ClientSession", lambda *_args: FakeSession())
    monkeypatch.setattr(agent, "GraphStore", FakeGraphStore)
    monkeypatch.setattr(agent, "chat_with_tools", fake_chat)

    result = asyncio.run(investigate("Check CVE-2022-24999", None, "CVE-2022-24999"))
    assert called_tools.count("query_graph") == 10
    assert called_tools.count("graph_blast_radius") == 1  # guard is outside the LLM budget
    assert choices == ["auto", "none"]
    assert result["agent"]["chosen_by_llm"] == 10
    assert any(step.get("reason") == "tool budget reached" for step in result["tool_trace"])
    assert result["summary"] == "Final answer."


def test_read_query_caps_trailing_limit_in_database_query():
    sent = []

    class FakeGraph:
        def ro_query(self, cypher, **kwargs):
            sent.append((cypher, kwargs))
            return SimpleNamespace(header=[], result_set=[], run_time_ms=1.0)

    store = GraphStore.__new__(GraphStore)
    store.graph = FakeGraph()
    result = store.read_query("MATCH (n) RETURN n LIMIT 1000;", limit=1000)
    assert sent == [("MATCH (n) RETURN n LIMIT 50", {"timeout": 3000})]
    assert result["cypher"] == sent[0][0]


def test_failed_or_partial_scan_does_not_create_memory(monkeypatch):
    import app.agent as agent

    writes = []

    class NoWrites:
        def save_investigation(self, *args, **kwargs):
            writes.append((args, kwargs))
            return "unexpected"

    monkeypatch.setattr(agent, "GraphStore", NoWrites)
    output = {"summary": "Scan failed", "evidence": {"scan_public_repo": {"results": [{"repo": "o/r"}]}},
              "tool_trace": [{"tool": "scan_public_repo", "status": "error"}]}
    assert _remember("o/r", "CVE-2022-24999", "question", output) is None
    output["tool_trace"][0]["status"] = "ok"
    output["evidence"]["scan_public_repo"]["results"] = []
    assert _remember("o/r", "CVE-2022-24999", "question", output) is None
    assert writes == []
