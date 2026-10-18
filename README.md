# LastHop

**Graph Hacks track:** Agents That Act on Connected Data.

A vulnerability scanner can tell you that a package is affected. It cannot, from that alert alone, tell you which of your services installs it, how the package enters each project, or whether a deployment manifest declares a route from a public entry point to that service. **LastHop joins those relationships in FalkorDB and gives an agent bounded tools to investigate them.** Every displayed path comes from the graph; missing deployment evidence stays unknown.

Give LastHop a **public GitHub repository** and a **CVE or GHSA ID**. It scans supported manifests at the latest default-branch commit and shows the affected projects, dependency paths, declared service routes, ownership when available, past decisions, and a fix plan for human review. The agent tab shows which tools were called and why. No GitHub sign-in is needed to scan a public repository.

The reproducible example is [Google Online Boutique](https://github.com/GoogleCloudPlatform/microservices-demo) with [CVE-2026-12143](https://github.com/advisories/GHSA-hmw2-7cc7-3qxx). At [the evaluated commit](eval/online_boutique.md), two Node projects install `form-data@2.5.5`; the repository's Kubernetes manifests declare a public `frontend-external` LoadBalancer and service-call paths to both workloads. This is evidence of **installed package and declared network paths**, not proof that the vulnerable function executes or can be exploited. A fresh scan may differ because the upstream repository changes.

## What to see in the demo

1. Open the app and select **Try Online Boutique**, or enter `GoogleCloudPlatform/microservices-demo` and `CVE-2026-12143`.
2. **Overview** shows each affected project's installed version, dependency chain, deployment evidence, and priority. Projects with no matching affected package are shown separately.
3. **Blast radius** runs one FalkorDB query across the ingested graph. It groups the affected projects, counts their dependency paths, and shows declared internet hop counts alongside past decisions.
4. **Agent run** shows the evidence tools selected by the model or the labeled deterministic fallback. The displayed answer is composed from tool facts; the model's proposed wording is checked against the known paths.
5. **History and action** let a person inspect prior decisions, trace an introducing npm commit when verifiable, and review a GitHub issue draft. Filing an issue requires explicit approval and write credentials.

## Run locally

**Fastest path — Docker Desktop:** from the repository root, run:

```powershell
docker compose up --build
```

This starts FalkorDB and the app. The app image includes Git for the source/provenance fallback. To run the app directly on your machine instead, use Python 3.11+ and Git alongside Docker Desktop:

```powershell
docker compose up -d falkordb
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. The FalkorDB Browser is at <http://127.0.0.1:3000>. Check <http://127.0.0.1:8000/api/health> for `{"database":"connected"}` before scanning. The first live scan needs network access to GitHub and advisory sources and may take longer than a cached scan. An empty database is expected before the first scan.

The application works without API keys. For higher GitHub API limits or a model-selected agent, run `Copy-Item .env.example .env` (PowerShell), edit `.env`, and restart the app. Set `GITHUB_TOKEN` for higher API limits; set `GROQ_API_KEY` or `OPENROUTER_API_KEY` for model-selected tool calls. With neither model key, the agent runs a labeled deterministic tool sequence. `GEMINI_API_KEY` is supported for the optional summary helper, not model-selected tool calls. When anonymous GitHub quota is exhausted, source ingestion tries a bounded GitHub archive, then a shallow filtered Git checkout if the archive is unavailable. Never commit `.env`; Git ignores it. The app binds to localhost by default; no public deployment is configured.

Launch the MCP server separately for an external MCP client:

```powershell
.\.venv\Scripts\python.exe -m app.mcp_server
```

It uses stdio and exposes `scan_public_repo`, `graph_blast_radius`, `advisory_fanout`, `exposure_evidence`, `cut_points`, `service_bridges`, `decision_memory`, `recall_investigations`, `graph_schema`, `query_graph`, and `introducing_commit`. `POST /api/agent` lets a configured model choose evidence tools within a call budget. The `query_graph` tool permits bounded **read-only** Cypher: write clauses are rejected, a trailing `LIMIT` is capped at 50, and the query runs through `GRAPH.RO_QUERY` with a 3-second timeout. The model receives no database credentials. A required scan and blast-radius query run as labeled guards if the model skips them. Its proposed wording is path-checked; the visible verdict is assembled from returned graph facts. If no model is available, a labeled fixed tool sequence still works.

The scanner discovers npm `package-lock.json` v2/v3, pnpm v9, Yarn Classic v1, and pinned Python `requirements.txt` entries in nested projects. Python requirements provide positive pin evidence only; they do not prove the installed or transitive set is complete. Kubernetes YAML in `kubernetes-manifests`, `k8s`, `kubernetes`, or `deploy` directories is parsed for Deployments, Services, Ingresses, LoadBalancers, and `*_ADDR`/`*_URL`/`*_HOST` service addresses. These are **declared** deployment paths, not observed runtime traffic.

Run checks with `.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider`. Reproduce the [real-repository comparison](eval/online_boutique.md) with `.\.venv\Scripts\python.exe -m eval.real` (requires npm and network access). The comparison records its source commit and compares features, not exploitability or detection accuracy.

For a second real ecosystem check, scan Online Boutique with [CVE-2026-97687](https://github.com/urllib3/urllib3/security/advisories/GHSA-8988-9cw3-xx77). Its Python requirements contain affected `urllib3` pins at the tested commit. The result distinguishes declared public paths from unavailable deployment evidence and marks actual installation as unverified.

## Why FalkorDB is central

LastHop stores package versions, **project-specific dependency instances**, deployment routes, decisions, and investigation history as connected data. A flat scanner result cannot answer the main question without rebuilding these joins: *for one advisory, which projects install an affected version, through how many dependency paths, and which of their services have a declared path from the internet?* The Blast radius tab answers that with one FalkorDB query; it returns the Cypher text and database runtime with the result.

### Graph data model

| Node / relationship | Meaning and source |
|---|---|
| `Repo` → `DEPENDS_ON` → `Dependency` → `DEPENDS_ON` → `Dependency` | One `Repo` per discovered lockfile or pinned requirements project. A `Dependency` is an installed/pinned instance scoped to that project; the edges preserve its parent chain. |
| `Dependency` → `INSTANCE_OF` → `PackageVersion` ← `AFFECTS_VERSION` ← `Advisory` | `PackageVersion` is shared by ecosystem, package name, and version. It joins the same affected release across projects and repositories. `AFFECTS` also links an advisory to specific matched instances. |
| `Repo` → `RUNS` → `Service`; `Internet` → `REACHES` → `Exposure` → `ROUTES_TO` → `Service` → `CALLS` → `Service` | Workloads, public entries, and calls parsed from Kubernetes manifests. `CALLS` stores the manifest and variable used as evidence. These are declared routes, not observed traffic. |
| `Repo` → `OWNED_BY` → `Owner`; `Repo` → `HAS_DECISION` → `Decision` | Ownership when source evidence exists. Decisions store the scan commit so an older decision can be marked stale after a commit change. |
| `Investigation` → `ABOUT` → `Advisory`; `Investigation` → `INVESTIGATED` → `Repo`; `Repo` → `HAS_ISSUE` → `IssueReport` | Prior agent investigations and human-approved issue records. They survive repository rescans. |
| `Person` → `AUTHORED` → `Commit` → `INTRODUCED_PIN` → `Dependency`; `PullRequest` → `CONTAINS` → `Commit`; `Person` → `APPROVED` → `PullRequest` | Verified npm pin provenance where the commit/PR/reviewer can be established. Person nodes use anonymous role IDs rather than storing names. |
| `Dependency` → `HAS_MODULE_ANALYSIS` → `ModuleAnalysis` → `MAIN_ENTRY` / `CLI_ENTRY` → `ModuleFile` → `IMPORTS_MODULE` / `IMPORTS_PACKAGE` | A bounded static trace through the immediate parent package. It distinguishes an observed main-entry import from a CLI-only import. |

For example, `GoogleCloudPlatform/microservices-demo::src/paymentservice` is a project node, while `npm:form-data@2.5.5` is a shared package-version node. This split matters: one repo's dependency edge must never leak into another repo's tree, yet a CVE should fan out to every project installing the same affected version. Ingestion replaces only the current project/deployment snapshot, uses `UNWIND … MERGE` for retry-safe batches, and retains decisions and investigations. A changed commit triggers decision review; it does not by itself prove the decision became invalid.

### Cypher that the product depends on

**1. Import project instances and join them to a shared release.** These are representative statements from [`app/graph.py`](app/graph.py); package version IDs include the ecosystem to keep npm and PyPI distinct.

```cypher
UNWIND $rows AS row
MERGE (d:Dependency {id:row.id})
SET d.repo_id=row.repo, d.path=row.path, d.name=row.name, d.version=row.version
```

```cypher
UNWIND $rows AS row
MATCH (d:Dependency {id:row.id})
MERGE (p:PackageVersion {id:$ecosystem + ':' + row.name + '@' + row.version})
SET p.ecosystem=$ecosystem, p.name=row.name, p.version=row.version
MERGE (d)-[:INSTANCE_OF]->(p)
```

**2. Compute cross-repository blast radius in one read.** The UI uses this exact bounded query. `paths` counts dependency paths to the matched instance; `internet_hops` is the shortest *declared* route to a service running the project. `null` means no such path was found in the ingested manifests, not proof of safety.

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

**3. Show the proof paths.** The first query returns the actual parent chain for one package; the second finds the shortest declared path from the internet through exposure and service-call edges. Both are capped at 12 edges.

```cypher
MATCH p=(r:Repo {id:$repo})-[:DEPENDS_ON*1..12]->(d:Dependency {name:$name})
RETURN p, d.version, d.id ORDER BY length(p) LIMIT 50
```

```cypher
MATCH (r:Repo {id:$repo})-[:RUNS]->(s:Service), (i:Internet {id:'internet'})
WITH s, shortestPath((i)-[:REACHES|ROUTES_TO|CALLS*1..12]->(s)) AS p
RETURN s.id, p LIMIT 20
```

**4. Find where dependency paths converge.** `cut_points` counts how many paths to a target dependency pass through each intermediate package. When `through = total`, every enumerated path crosses that package. This identifies where to investigate a fix; upgrading the cut point alone does not guarantee remediation.

```cypher
MATCH p=(r:Repo {id:$repo})-[:DEPENDS_ON*1..12]->(t:Dependency {id:$target})
WITH collect(p) AS paths
WITH paths, size(paths) AS total
UNWIND range(0, total - 1) AS k
WITH total, k, nodes(paths[k]) AS ns
UNWIND range(1, size(ns) - 2) AS i
WITH total, k, i, ns[i] AS n
RETURN n.name AS package, n.version AS version, count(DISTINCT k) AS through, total, min(i) AS depth
ORDER BY through DESC, depth ASC LIMIT 6
```

**5. Rank service-call bridges with a graph algorithm.** FalkorDB's `algo.betweenness` highlights services lying on many declared call paths. LastHop presents it as topology context, never as an exploitability score.

```cypher
CALL algo.betweenness({nodeLabels:['Service'], relationshipTypes:['CALLS']})
YIELD node, score
WITH node, score WHERE node.deployment_repo=$repo
RETURN node.name, score ORDER BY score DESC LIMIT 20
```

Fixed reads use FalkorDB `GRAPH.RO_QUERY`, bounded paths/results, and 3- or 5-second query timeouts. The agent's exploratory `query_graph` is additionally capped at 50 rows and 3 seconds. Matching affected versions happens in code before advisory edges are written: npm ranges use semver; Python pins and fix checks use Python version/specifier handling. The graph then owns the joins and path calculations.

## Risk, memory, provenance, and action

For CVEs, LastHop fetches the current [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS score](https://api.first.org/epss/). Missing lookups remain **unknown**. Priority uses public entry evidence, bounded module traces, KEV, and EPSS. CVSS remains advisory context. A public service path does not prove the vulnerable function can be exploited; a CLI-only static trace does not prove the app never invokes the CLI.

**Trace introducing commit** checks which lockfile commit changed the exact installed package key to its current vulnerable version. It uses GitHub's commit, associated PR, and review APIs. If anonymous API quota is exhausted, bounded shallow public Git history can verify the commit; a PR number parsed from its title is labeled inferred and reviewers remain unknown. `Commit`, `PullRequest`, and anonymous role-only `Person` nodes preserve graph relationships without storing author or reviewer names in FalkorDB. Public names are shown transiently from source evidence when available.

### GitHub issue (human-approved)

For npm direct or transitive dependencies, LastHop checks whether the first patched version fits the immediate parent's declared range. For pinned Python requirements, it checks that the patched release is available on PyPI and that declared parent requirements permit it. The issue draft carries the affected dependency path, declared internet path or its absence, advisory and exploit signals, and the verified fix plan or a manual-review reason. A person can edit the draft before entering `LASTHOP_ADMIN_KEY`; only then does the server use a write-capable `GITHUB_TOKEN` to create the issue. Filed issues are remembered in FalkorDB and shown on later investigations. The app does not change repository files.

To show a real transitive fix plan, scan `mercadopago/card-payment-bricks-sample-node` with `CVE-2021-44906`. Its tested lockfile has `hbs → handlebars → minimist@1.2.5`; the compatible 1.2.6 update fits the parent's declared range and can be included in a reviewed GitHub issue. The module trace finds the static minimist import in Handlebars' CLI, not its main entry. That is a bounded observation, not a proof that the CLI never runs.
