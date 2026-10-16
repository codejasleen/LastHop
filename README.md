# BlastRadius

**Track:** Agents That Act on Connected Data. The graph also retains human decisions for later review.

BlastRadius asks: when a CVE lands, which installed versions reach which services, how can a public request reach those services, what did the team decide before, and what fix can a human review? Its agent calls bounded MCP evidence tools backed by FalkorDB. The browser shows the tool trace, dependency path, declared network path, exploit signals, and a reviewable fix when one can be verified.

The live example uses [Google Online Boutique](https://github.com/GoogleCloudPlatform/microservices-demo) and [CVE-2026-12143](https://github.com/advisories/GHSA-hmw2-7cc7-3qxx). At the tested commit its two Node projects contain `form-data@2.5.5`. Kubernetes manifests declare a `frontend-external` LoadBalancer and service calls to both projects. [The comparison with npm audit](eval/online_boutique.md) records the exact tested commit. The latest commit can change; each UI scan refreshes it.

## Run locally

With Docker Desktop, Python 3.11+, and Git (for provenance):

```powershell
docker compose up -d falkordb
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. The FalkorDB Browser is at <http://127.0.0.1:3000>. **Try real example** scans Online Boutique. A public repo needs no sign-in. `GITHUB_TOKEN` is optional for higher API limits and required, with write permission to the target repo, for draft PR creation. When anonymous API quota is exhausted, source ingestion tries a bounded GitHub archive, then a shallow filtered Git checkout if the archive is unavailable.

For optional Groq summaries, set `GROQ_API_KEY` in a local `.env` file (see `.env.example`). The app reads it when an agent summary runs, and Git ignores the file.

`docker compose up --build` runs both the database and app in containers. The app image includes Git for the provenance fallback.

Launch the MCP server separately for an external MCP client:

```powershell
.\.venv\Scripts\python.exe -m app.mcp_server
```

It uses stdio and exposes `scan_public_repo`, `advisory_fanout`, `exposure_evidence`, `decision_memory`, `service_bridges`, and `introducing_commit`. `POST /api/agent` selects these tools based on the question, then returns its trace and evidence. With `GROQ_API_KEY`, `GEMINI_API_KEY`, or `OPENROUTER_API_KEY`, a model writes a short summary from bounded tool facts. If keys are absent or fail, the deterministic summary remains available. The model never receives database credentials or arbitrary Cypher/write access.

The scanner discovers npm `package-lock.json` v2/v3, pnpm v9, Yarn Classic v1, and pinned Python `requirements.txt` entries in nested projects. Python requirements provide positive pin evidence only; they do not prove the installed or transitive set is complete. Kubernetes YAML in `kubernetes-manifests`, `k8s`, `kubernetes`, or `deploy` directories is parsed for Deployments, Services, Ingresses, LoadBalancers, and `*_ADDR`/`*_URL`/`*_HOST` service addresses. These are **declared** deployment paths, not observed runtime traffic.

Run checks with `.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider`. Reproduce the real comparison with `.\.venv\Scripts\python.exe -m eval.real` (requires npm and network access).

For a second real ecosystem check, scan Online Boutique with [CVE-2026-97687](https://github.com/urllib3/urllib3/security/advisories/GHSA-8988-9cw3-xx77). Its Python requirements contain affected `urllib3` pins at the tested commit. The result distinguishes declared public paths from unavailable deployment evidence and marks actual installation as unverified.

## Graph model and queries

```text
(Advisory)-[:AFFECTS_VERSION]->(PackageVersion)<-[:INSTANCE_OF]-(Dependency)
(Advisory)-[:AFFECTS]->(Dependency)
(Repo)-[:DEPENDS_ON]->(Dependency)-[:DEPENDS_ON*]->(Dependency)
(Repo)-[:RUNS]->(Service)
(Internet)-[:REACHES]->(Exposure)-[:ROUTES_TO]->(Service)-[:CALLS*]->(Service)
(Repo)-[:OWNED_BY]->(Owner)
(Repo)-[:HAS_DECISION]->(Decision {snapshot_sha})
(Person)-[:AUTHORED]->(Commit)-[:INTRODUCED_PIN]->(Dependency)
(PullRequest)-[:CONTAINS]->(Commit)
(Person)-[:APPROVED]->(PullRequest)
(Dependency)-[:HAS_MODULE_ANALYSIS]->(ModuleAnalysis)-[:MAIN_ENTRY|CLI_ENTRY]->(ModuleFile)
(ModuleFile)-[:IMPORTS_MODULE]->(ModuleFile)-[:IMPORTS_PACKAGE]->(Dependency)
```

Each `Dependency` is a project-specific installed instance. `PackageVersion` is shared by npm name and version, allowing one advisory to fan out across projects without letting one repo's stale pin contaminate another. Ingestion uses `UNWIND … MERGE` batches and replaces each project's current snapshot. `Decision` nodes survive reingestion and carry the commit SHA at which they were recorded; the agent flags a decision as stale when the repository SHA changes. An unrelated commit can also trigger review.

The central bounded FalkorDB read queries are:

```cypher
MATCH p=(r:Repo {id:$repo})-[:DEPENDS_ON*1..12]->(d:Dependency {name:$name})
RETURN p, d.version, d.id ORDER BY length(p) LIMIT 50
```

```cypher
MATCH (a:Advisory {id:$id})-[:AFFECTS_VERSION]->(p:PackageVersion)
      <-[:INSTANCE_OF]-(d:Dependency)
MATCH path=(r:Repo)-[:DEPENDS_ON*1..12]->(d)
RETURN r.id, p.name, p.version, length(path), r.sha
ORDER BY r.id, length(path) LIMIT 100
```

```cypher
MATCH (r:Repo {id:$repo})-[:RUNS]->(s:Service), (i:Internet {id:'internet'})
WITH s, shortestPath((i)-[:REACHES|ROUTES_TO|CALLS*1..12]->(s)) AS p
RETURN s.id, p LIMIT 20
```

```cypher
CALL algo.betweenness({nodeLabels:['Service'], relationshipTypes:['CALLS']})
YIELD node, score
WITH node, score WHERE node.deployment_repo=$repo
RETURN node.name, score ORDER BY score DESC LIMIT 20
```

Reads use FalkorDB `GRAPH.RO_QUERY` with a 3-second timeout and caps. `algo.betweenness` ranks declared service-call bridges; it is context, not an exploitability score. Advisory ranges use npm semver. The bounded module trace records static imports in the immediate parent package's main and CLI entries as graph edges. Dynamic imports and app execution are outside its proof scope.

## Risk, memory, provenance, and action

For CVEs, BlastRadius fetches the current [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS score](https://api.first.org/epss/). Missing lookups remain **unknown**. Priority uses public entry evidence, bounded module traces, KEV, and EPSS. CVSS remains advisory context. A public service path does not prove the vulnerable function can be exploited; a CLI-only static trace does not prove the app never invokes the CLI.

**Trace introducing commit** checks which lockfile commit changed the exact installed package key to its current vulnerable version. It uses GitHub's commit, associated PR, and review APIs. If anonymous API quota is exhausted, bounded shallow public Git history can verify the commit; a PR number parsed from its title is labeled inferred and reviewers remain unknown. `Commit`, `PullRequest`, and anonymous role-only `Person` nodes preserve graph relationships without storing author or reviewer names in FalkorDB. Public names are shown transiently from source evidence when available.

For npm direct or transitive dependencies in root or nested projects, BlastRadius checks whether the first patched version fits the immediate parent's declared range. If it fits and package dependency metadata is unchanged, it builds a targeted lockfile diff using verified npm registry metadata. A human reviews the diff and enters `BLASTRADIUS_ADMIN_KEY`; with a write-capable `GITHUB_TOKEN`, the server opens a **draft** PR and never merges it. Out-of-range fixes, changed dependency metadata, multiple affected copies, and non-npm lockfiles require manual review. No PR is opened against public examples without write access.

To show a real reviewable transitive action, scan `mercadopago/card-payment-bricks-sample-node` with `CVE-2021-44906`. Its tested lockfile has `hbs → handlebars → minimist@1.2.5`; the compatible 1.2.6 update produces a targeted lockfile diff. The module trace finds the static minimist import in Handlebars' CLI, not its main entry. That is a bounded observation, not a proof that the CLI never runs.

## Limits and submission transparency

Only public repositories are imported. Python coverage is limited to pinned `requirements.txt` entries; Go, Java, and other ecosystems are not scanned for package vulnerabilities. Package-level and declared network reachability are checked; function-level reachability, runtime traffic, cloud firewalls, and actual exploitation are not measured. Manifest claims may be stale. The app binds to localhost by default and needs authentication/HTTPS before public deployment.

AI coding assistance was used for implementation and review. The owner must verify and be able to explain the graph model, queries, decisions, and demo. This repository has substantive pre-event prototype commits from October 11 and 14, 2026; [Graph Hacks rules](https://www.wemakedevs.org/hackathons/falkordb/rules) say main coding and design must begin after October 15. **Eligibility of this repo as a hackathon submission needs an organizer ruling.** October 15–16 work adds the module trace, MCP agent, real deployment graph, graph fan-out and algorithm, exploit signals, provenance, and real-repo evaluation.
