# Real-repository comparison

Generated 2026-10-16T10:29:21.362748+00:00 from [GoogleCloudPlatform/microservices-demo](https://github.com/GoogleCloudPlatform/microservices-demo)
at commit `38e7348eb289eb5b87c0c6e8cb19ced0449dc389`. Advisory: [CVE-2026-12143](https://github.com/advisories/GHSA-hmw2-7cc7-3qxx).

Both tools read the same committed npm lockfiles. `npm audit` identifies an affected package; BlastRadius adds cross-service graph paths, declared Kubernetes reachability, and review priority. This is a feature comparison, not an exploitability or accuracy benchmark.

| Project | npm audit: advisory | BlastRadius: affected path | Public entry path | Priority |
|---|---|---|---|---|
| `src/currencyservice` | yes | GoogleCloudPlatform/microservices-demo::src/currencyservice → @google-cloud/trace-agent → @google-cloud/common → retry-request → @types/request → form-data | Internet → LoadBalancer → frontend → currencyservice | Review |
| `src/paymentservice` | no | GoogleCloudPlatform/microservices-demo::src/paymentservice → @google-cloud/profiler → @google-cloud/logging-min → @google-cloud/common → retry-request → @types/request → form-data | Internet → LoadBalancer → frontend → checkoutservice → paymentservice | Review |

FalkorDB shared-package fan-out: **2 affected projects**.
Kubernetes import: **12 workloads**, **16 service calls**, **1 public entry**.

The package and declared network paths do not establish function-level reachability or exploitability.
