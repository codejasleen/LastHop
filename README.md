# BlastRadius

**Question:** A CVE just dropped. Which repositories actually contain the affected package, which declared services are public, who owns them, and what should be fixed first?

BlastRadius imports public npm repository evidence into **FalkorDB**, walks repository-specific dependency paths, joins declared service exposure and ownership, and returns a verdict with its proof path. For a bounded npm case it also traces static imports from the immediate parent package's main and CLI entries. A compatible direct or transitive dependency fix can be reviewed as a targeted lockfile diff and, with an approval key, submitted as a **draft pull request**. No LLM is needed for any verdict or action.

This is a working college-selection prototype. The included three-repo incident is explicitly **synthetic**; the same importer also reads real public GitHub repos. Its graph model, ingestion, queries, and UI are implemented here. Any later hackathon submission must be checked against the event's work-timing and disclosure rules.

## Run

With Docker Desktop running:

```powershell
docker compose up -d falkordb
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. Or run the whole stack with `docker compose up` (the app container installs Python requirements on startup). The FalkorDB Browser is at <http://127.0.0.1:3000>.

1. Paste a public GitHub repository URL (or `owner/repo`) and enter a CVE or GHSA, then click **Scan latest**. Each scan fetches the current default-branch commit, discovers supported projects, and rebuilds their separate graph snapshots.
2. For a tested affected real example, use `mercadopago/card-payment-bricks-sample-node` and `CVE-2021-44906`. The current committed lockfile traces `hbs → handlebars → minimist@1.2.5`; the Handlebars package main has no static import path to minimist, while `bin/handlebars:138` does. Review the targeted lockfile refresh to minimist 1.2.6. This is evidence about static imports in Handlebars, not proof that the application never executes its CLI.
3. Click **Run sample investigation** for a clearly synthetic affected case: a public storefront reached through `web-framework → render-kit`, an affected internal service, and a repo where the package is absent.

The scanner discovers **npm `package-lock.json` v2/v3**, **pnpm `pnpm-lock.yaml` v9**, and **Yarn Classic `yarn.lock` v1** at any directory, including nested pnpm importers. Each project has its own graph identity and result card. It refuses incomplete or unsupported paths instead of returning a false "not present" result. Private repos, npm/Yarn workspace lockfiles, Yarn Berry/Bun, pnpm workspace links and non-registry references, other ecosystems, and function-level call paths are not supported yet. A public GitHub repo needs no sign-in; optional `GITHUB_TOKEN` raises GitHub API limits and is required for draft PR creation.

Run the focused checks with `.\.venv\Scripts\python.exe -m pytest -q`.

For a reproducible package-only versus graph comparison, run `.\.venv\Scripts\python.exe -m eval.ablation`. This uses the synthetic three-repo case: package matching alerts on two repos, while graph plus declared exposure elevates one public service. It is a demonstration of decision differences, not a real-world accuracy measurement.

## Evidence and graph model

```text
(Advisory)-[:AFFECTS]->(Dependency)
(Repo)-[:DEPENDS_ON]->(Dependency)-[:DEPENDS_ON*]->(Dependency)
(Repo)-[:RUNS]->(Service)-[:EXPOSES]->(Exposure)
(Repo)-[:OWNED_BY]->(Owner)
(Repo)-[:HAS_DECISION]->(Decision)
(Dependency)-[:HAS_MODULE_ANALYSIS]->(ModuleAnalysis)-[:MAIN_ENTRY|CLI_ENTRY]->(ModuleFile)
(ModuleFile)-[:IMPORTS_MODULE]->(ModuleFile)-[:IMPORTS_PACKAGE]->(Dependency)
```

Each `Dependency` ID includes the project identity and exact installed package key. This prevents one repo or monorepo project pin from contaminating another result. The npm importer parses production and optional dependencies in lockfile v2/v3, resolves nested and hoisted packages, and refuses missing referenced packages. The pnpm v9 importer follows exact `importers` and `snapshots` keys, including peer suffixes. The Yarn Classic importer uses `package.json` production roots and exact selectors from `yarn.lock`. Workspace links and unresolved selectors currently stop the scan with an explicit unsupported-path error. Ingestion replaces one project snapshot at a time and uses `UNWIND … MERGE` batches for nodes and edges. There is no ordinary database standing behind the verdicts.

The core bounded read query is:

```cypher
MATCH p=(r:Repo {id:$repo})-[:DEPENDS_ON*1..12]->(d:Dependency {name:$name})
RETURN p, d.version, d.id ORDER BY length(p) LIMIT 50
```

It runs through `GRAPH.RO_QUERY` with a 3-second timeout. The path object returned by FalkorDB is displayed in the result card. Other read-only queries fetch `(Repo)-[:RUNS]->(Service)-[:EXPOSES]->(Exposure)`, ownership, and previous `Decision` nodes. Advisory ranges are checked with npm semver, never lexical string comparison. The LLM is absent from this prototype, and never receives graph credentials.

For a vulnerable npm dependency, BlastRadius downloads the immediate parent's bounded public npm tarball, verifies it against the committed lockfile integrity, and records static `require()`/`import` edges in FalkorDB. The module status is then read from graph traversals starting at the package `main` and `bin` entries:

```cypher
MATCH (a:ModuleAnalysis {id:$id})-[:MAIN_ENTRY]->(start:ModuleFile),
      (a)-[:ANALYZES]->(target:Dependency)
MATCH p=(start)-[:IMPORTS_MODULE*0..16]->(last:ModuleFile)-[imp:IMPORTS_PACKAGE]->(target)
RETURN last.file, imp.line ORDER BY length(p) LIMIT 1
```

The same bounded query from `CLI_ENTRY` distinguishes the Handlebars case. This is **static module-level evidence within the immediate parent package**. Dynamic imports, build transforms, app entry points, scripts, and CLI execution can make an absent path inconclusive. The P3 label on the Handlebars example is a provisional review priority, not a safety verdict.

The app reports **package not present**, **version unaffected**, **affected with declared public route**, **affected with declared internal service**, or **exposure unknown** separately. It checks package and declared network reachability. It does **not** establish function-level code reachability or observe runtime traffic. The `blast-radius.json` exposure claim is repository-supplied evidence, so production use should corroborate it with deployment and cloud inventory.

## Public repo evidence

The live scan reads the default branch SHA and Git tree, discovers supported lockfiles, and reads each project's `package.json`, optional root `CODEOWNERS`, and optional project `blast-radius.json`. If GitHub's anonymous API quota is exhausted, it reads a bounded public source archive from GitHub instead; the archive must identify the exact commit SHA. CVE lookup then falls back to OSV's public advisory API. It refuses private repos, truncated Git trees, archives over 30 MB, more than 20 lockfiles, or more than 30 projects. The UI shows the exact commit SHA and names any root manifests outside this scanner's scope (for example `go.mod`). A manifest can declare service exposure:

```json
{
  "services": [
    {"name": "storefront", "exposure": "public", "public_route": "https://store.example.org"},
    {"name": "worker", "exposure": "internal"}
  ]
}
```

Without this evidence, exposure is **unknown**. Pressing **Scan latest** always refreshes the repository. A signed GitHub `push` webhook sent to `/api/webhooks/github` can also refresh an already-scanned public repo when its default branch changes; set `GITHUB_WEBHOOK_SECRET` and expose a secured webhook URL before enabling it. The webhook does not create PRs.

## Draft PR gate

For a single affected **direct or transitive dependency in a root npm project**, BlastRadius checks the first patched version against the immediate parent's declared range. If it fits and the patched package has the same dependency metadata, BlastRadius obtains the exact tarball URL and integrity from the public npm registry and changes only that package's lockfile records. It checks the new version against the advisory, shows the diff, then waits for a human to enter `BLASTRADIUS_ADMIN_KEY`. With `GITHUB_TOKEN` configured for Contents and Pull requests write access **to that repository**, approval creates a branch and **draft PR**. It never merges. It rejects a stale graph snapshot if the default branch moved after review. Nested npm, pnpm, multiple affected installed copies, out-of-range upgrades, dependency-metadata changes, and synthetic repositories remain manual-review cases. No PR is created for the public Mercadopago example without repository write access.

Keep credentials in your local environment or an untracked `.env`; never commit them. The local Docker binding is `127.0.0.1` by default. Put authentication and HTTPS in front of the app before exposing it to other users. GitHub App installation and production authorization are future work; this MVP uses selected public repos and an optional GitHub token for writing a PR.

## Demo script (2 minutes)

1. **The problem (15s):** A package advisory alone cannot answer whether a vulnerable version reaches a public service.
2. **Live graph (45s):** Run the synthetic incident and follow the storefront's dependency path and public route. Compare its result to the internal service and absent package.
3. **Real input (35s):** Scan `mercadopago/card-payment-bricks-sample-node` with `CVE-2021-44906`. Show the real dependency path, the package-main versus CLI module evidence, and the provisional review priority.
4. **Action (25s):** Open the 28-line targeted transitive lockfile diff. Explain that draft PR creation requires repository write access and human approval; do not claim a PR was opened for Mercadopago.

The result is strongest when the judge sees the same advisory lead to different evidence-backed actions. The demo never presents synthetic data as a live incident.
