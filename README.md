# LastHop

**From a CVE alert to the services that need attention—with the path to back it up.**

**Graph Hacks track:** Agents That Act on Connected Data

Give LastHop a public GitHub repository and a CVE or GHSA ID. It uses FalkorDB to connect affected package versions, project dependency chains, Kubernetes services, public entry points, and past decisions. The result shows **what is affected, how the package got there, and what the deployment files say about public reachability**. Missing evidence stays unknown.

## Try the live example

With Docker Desktop running, from this project folder:

```sh
docker compose up --build
```

Open [LastHop](http://127.0.0.1:8000) and select **Try Online Boutique**, or enter:

| Field | Value |
|---|---|
| Public GitHub repo | `GoogleCloudPlatform/microservices-demo` |
| CVE | `CVE-2026-12143` |

At the [evaluated commit](eval/online_boutique.md), two Node projects install affected `form-data@2.5.5`. Kubernetes manifests declare routes from `frontend-external` to both services. A live scan reads the latest commit, so its result may change.

| Screen | What it shows |
|---|---|
| **Overview** | Installed version, dependency path, declared exposure, priority, and fix plan per project. |
| **Blast radius** | A cross-project FalkorDB query, dependency-path counts, and public-route hop counts. |
| **Agent run** | Tools chosen by the model, returned evidence, and labeled guard or fallback steps. |
| **History** | Previous investigations and human decisions, including when the scanned commit changed. |

These are **installed package and declared network paths**, not proof that the vulnerable function runs or can be exploited. The [comparison with `npm audit`](eval/online_boutique.md) records the exact source commit.

<details>
<summary>Local Python setup and optional keys</summary>

For a local Python process, use Docker Desktop, Python 3.11+, and Git. In PowerShell:

```powershell
docker compose up -d falkordb
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The app is at <http://127.0.0.1:8000>; the FalkorDB Browser is at <http://127.0.0.1:3000>. [Health](http://127.0.0.1:8000/api/health) should report `{"database":"connected"}`. The first scan needs network access to GitHub and advisory sources.

No key is needed to scan a public repo. For higher GitHub API limits or model-selected tool calls, copy `.env.example` to `.env`, add `GITHUB_TOKEN`, `GROQ_API_KEY`, or `OPENROUTER_API_KEY`, and restart. Without a model key, LastHop runs a labeled deterministic tool sequence. `GEMINI_API_KEY` supports the optional summary helper, not model-selected calls. Git ignores `.env`.

Creating a GitHub issue also requires `LASTHOP_ADMIN_KEY` and a `GITHUB_TOKEN` with Issues write permission for the target repository. The app binds to localhost by default.

</details>

## Why FalkorDB is necessary

One package release can be installed through different chains in several projects. Each project may run a service reached through other services. LastHop keeps those relationships in FalkorDB so the agent can retrieve a **path**, rather than assemble one from disconnected scanner results.

### Graph data model

```text
Advisory ─AFFECTS_VERSION→ PackageVersion ←INSTANCE_OF─ Dependency
                                                       ↑ DEPENDS_ON
Repo ─DEPENDS_ON→ Dependency ─DEPENDS_ON→ Dependency ──┘

Internet ─REACHES→ Exposure ─ROUTES_TO→ Service ─CALLS→ Service ←RUNS─ Repo
Repo ─HAS_DECISION→ Decision     Investigation ─ABOUT→ Advisory
```

| Design choice | Why it matters |
|---|---|
| **Project-specific `Dependency`** | Keeps one repo's parent chain and pinned version from leaking into another. |
| **Shared `PackageVersion`** | Lets one advisory fan out to every project installing the same ecosystem, name, and version. |
| **`Service`, `Exposure`, and `CALLS` edges** | Connect packages to workloads and declared public routes from Kubernetes manifests. |
| **`Decision` and `Investigation` nodes** | Preserve human and agent history across rescans; a changed commit flags a decision for review. |

The graph also records owners, approved GitHub issues, verified introducing commits/PRs, and bounded module-import traces when evidence exists. Ingestion replaces the current source snapshot but retains decisions and investigations. Batched `UNWIND … MERGE` statements make imports retry-safe; see [`app/graph.py`](app/graph.py).

### The Cypher behind blast radius

The **Blast radius** tab runs this query. It joins one advisory to shared versions, project-specific dependency paths, services, public-route hops, and past decisions **in one FalkorDB read**:

```cypher
MATCH (a:Advisory {id:$id})-[:AFFECTS_VERSION]->(pv:PackageVersion)<-[:INSTANCE_OF]-(d:Dependency)
MATCH dep=(r:Repo)-[:DEPENDS_ON*1..12]->(d)
WITH r.id AS rid, pv, count(dep) AS paths, min(length(dep)) AS hops
MATCH (r:Repo {id:rid})
OPTIONAL MATCH (r)-[:RUNS]->(s:Service)
OPTIONAL MATCH e=(:Internet)-[:REACHES]->(:Exposure)-[:ROUTES_TO]->(:Service)-[:CALLS*0..8]->(s)
WITH r, pv, paths, hops, s, min(length(e)) AS internet_hops
OPTIONAL MATCH (r)-[:HAS_DECISION]->(dec:Decision {advisory_id:$id})
RETURN split(r.id, '::')[0] AS repo, r.id AS project, pv.name + '@' + pv.version AS package,
       paths, hops, s.name AS service, internet_hops, collect(DISTINCT dec.verdict) AS decisions
ORDER BY internet_hops, repo, project LIMIT 100
```

`internet_hops = null` means **no route was found in the ingested manifests**. It does not mean the service is safe.

<details>
<summary>Other graph queries and algorithm</summary>

**Dependency proof path:**

```cypher
MATCH p=(r:Repo {id:$repo})-[:DEPENDS_ON*1..12]->(d:Dependency {name:$name})
RETURN p, d.version, d.id ORDER BY length(p) LIMIT 50
```

**Shortest declared public route:**

```cypher
MATCH (r:Repo {id:$repo})-[:RUNS]->(s:Service), (i:Internet {id:'internet'})
WITH s, shortestPath((i)-[:REACHES|ROUTES_TO|CALLS*1..12]->(s)) AS p
RETURN s.id, p LIMIT 20
```

**Service-call bridges:**

```cypher
CALL algo.betweenness({nodeLabels:['Service'], relationshipTypes:['CALLS']})
YIELD node, score
WITH node, score WHERE node.deployment_repo=$repo
RETURN node.name, score ORDER BY score DESC LIMIT 20
```

Betweenness describes topology, **not** exploitability. LastHop also counts which intermediate packages appear on every path to a vulnerable instance (`cut_points` in [`app/graph.py`](app/graph.py)). Such a package is a place to investigate a fix, not proof that upgrading it alone removes the vulnerability.

</details>

## Agent, action, and limits

- **Tools:** The MCP server exposes scanning, blast radius, exposure, memory, graph schema/query, cut points, service bridges, and provenance. Run it for an external MCP client with `.\.venv\Scripts\python.exe -m app.mcp_server`. The web UI calls `POST /api/agent`.
- **Grounded answer:** A configured Groq or OpenRouter model chooses tools. Required scan and blast-radius calls run as labeled guards if skipped. Model wording is path-checked; the displayed answer is assembled from returned evidence. No model key means a labeled deterministic fallback.
- **Bounded reads:** `query_graph` rejects write clauses, caps results at 50 rows, and uses FalkorDB `GRAPH.RO_QUERY` with a 3-second timeout. The model never receives database credentials. Fixed path queries also have depth, row, and time limits.
- **Human action:** LastHop checks whether a patched npm or Python version fits declared parent constraints. It drafts a GitHub issue with evidence or a manual-review reason. A person can edit it; only an approved, credentialed action files it. LastHop does not modify repository files.

**Coverage:** npm `package-lock.json` v2/v3, pnpm v9, Yarn Classic v1, and pinned Python `requirements.txt`, including nested projects. Python pins are positive evidence, not a complete installed dependency inventory. Kubernetes paths are declared, not observed traffic. Go, Java, and other package ecosystems, function-level reachability, runtime calls, and cloud firewall rules are not measured. KEV and EPSS are used when available; missing signals stay unknown.

## Verify and reproduce

```powershell
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
.\.venv\Scripts\python.exe -m eval.real
```

The [real-repository comparison](eval/online_boutique.md) uses npm and network access. It is a feature comparison, **not** an accuracy or exploitability benchmark.

AI coding assistance was used in implementation and review. Prototype work began before the October 15 event start for college selection; submission eligibility should be confirmed with the organizers. Only public repository data is imported.
