# BlastRadius

**Question:** A CVE just dropped. Which repositories actually contain the affected package, which declared services are public, who owns them, and what should be fixed first?

BlastRadius imports public npm repository evidence into **FalkorDB**, walks repository-specific dependency paths, joins declared service exposure and ownership, and returns a verdict with its proof path. A direct dependency fix can be reviewed as a lockfile diff and, with an approval key, submitted as a **draft pull request**. No LLM is needed for any verdict or action.

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
2. For a tested real example, use `axios/axios` and `CVE-2022-24999`. The result correctly reports that the affected `qs` package is absent from that repo's production dependency snapshot.
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
```

Each `Dependency` ID includes the project identity and exact installed package key. This prevents one repo or monorepo project pin from contaminating another result. The npm importer parses production and optional dependencies in lockfile v2/v3, resolves nested and hoisted packages, and refuses missing referenced packages. The pnpm v9 importer follows exact `importers` and `snapshots` keys, including peer suffixes. The Yarn Classic importer uses `package.json` production roots and exact selectors from `yarn.lock`. Workspace links and unresolved selectors currently stop the scan with an explicit unsupported-path error. Ingestion replaces one project snapshot at a time and uses `UNWIND … MERGE` batches for nodes and edges. There is no ordinary database standing behind the verdicts.

The core bounded read query is:

```cypher
MATCH p=(r:Repo {id:$repo})-[:DEPENDS_ON*1..12]->(d:Dependency {name:$name})
RETURN p, d.version, d.id ORDER BY length(p) LIMIT 50
```

It runs through `GRAPH.RO_QUERY` with a 3-second timeout. The path object returned by FalkorDB is displayed in the result card. Other read-only queries fetch `(Repo)-[:RUNS]->(Service)-[:EXPOSES]->(Exposure)`, ownership, and previous `Decision` nodes. Advisory ranges are checked with npm semver, never lexical string comparison. The LLM is absent from this prototype, and never receives graph credentials.

The app reports **package not present**, **version unaffected**, **affected with declared public route**, **affected with declared internal service**, or **exposure unknown** separately. It checks package and declared network reachability. It does **not** establish function-level code reachability or observe runtime traffic. The `blast-radius.json` exposure claim is repository-supplied evidence, so production use should corroborate it with deployment and cloud inventory.

## Public repo evidence

The live scan reads the default branch SHA and Git tree, discovers supported lockfiles, and reads each project's `package.json`, optional root `CODEOWNERS`, and optional project `blast-radius.json` through the GitHub API. It refuses private repos, truncated Git trees, more than 20 lockfiles, or more than 30 projects. The UI shows the exact commit SHA it scanned. A manifest can declare service exposure:

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

For an affected **direct production dependency in a root npm project**, BlastRadius can prepare a lockfile-only update with `npm update --package-lock-only --ignore-scripts`. It checks the patched version against the root declared range and the advisory, shows the diff, then waits for a human to enter `BLASTRADIUS_ADMIN_KEY`. With `GITHUB_TOKEN` configured for Contents and Pull requests write access, approval creates a branch and **draft PR**. It never merges. It rejects a stale graph snapshot if the default branch moved after review. Nested npm, pnpm, transitive fixes, out-of-range upgrades, and synthetic repositories remain manual-review cases.

Keep credentials in your local environment or an untracked `.env`; never commit them. The local Docker binding is `127.0.0.1` by default. Put authentication and HTTPS in front of the app before exposing it to other users. GitHub App installation and production authorization are future work; this MVP uses selected public repos and an optional GitHub token for writing a PR.

## Demo script (2 minutes)

1. **The problem (15s):** A package advisory alone cannot answer whether a vulnerable version reaches a public service.
2. **Live graph (45s):** Run the synthetic incident and follow the storefront's dependency path and public route. Compare its result to the internal service and absent package.
3. **Real input (35s):** Paste `https://github.com/axios/axios` and real `CVE-2022-24999`, scan the latest commit, and show the graph reports the package is not present in its production dependency snapshot.
4. **Action (25s):** Explain the reviewable direct-dependency lockfile diff and approval-gated draft PR. Show a configured test repo if GitHub write credentials are available; otherwise state that the write gate requires them.

The result is strongest when the judge sees the same advisory lead to different evidence-backed actions. The demo never presents synthetic data as a live incident.
