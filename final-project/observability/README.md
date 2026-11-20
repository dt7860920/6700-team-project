# Observability: Prometheus + Grafana (opt-in)

Plan §8.6, layer 2 — *"is it healthy now."* The app exposes Prometheus metrics at
`GET /metrics` on its one published port; this directory holds an **optional**
Prometheus + Grafana stack that scrapes it from inside the Compose network and ships a
pre-provisioned dashboard.

Nothing here changes the deployment's published surface: the `prometheus` and `grafana`
services live behind the `observability` Compose profile, are **off by default**, and
bind their UIs to the host's **loopback only** (`127.0.0.1:9090`, `127.0.0.1:3000`).
Port 8080 remains the only port reachable from outside the box.

## Run it

```bash
cd final-project
docker compose --profile observability up -d --build     # app + executor + prometheus + grafana
make observability-up                                     # the same thing

open http://127.0.0.1:3000        # Grafana (admin / admin unless GRAFANA_ADMIN_PASSWORD is set in .env)
open http://127.0.0.1:9090        # Prometheus (targets page: /targets)
curl -s localhost:8080/metrics | grep ^ono_

docker compose --profile observability down               # stop everything (volumes keep history)
```

On Jetstream2 the two UIs are not reachable from your laptop by design; tunnel them:
`ssh -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 <user>@<FLOATING-IP>`.

Grafana finds the Prometheus datasource and the **ONO - Operation: Negative One**
dashboard through file provisioning (`grafana/provisioning/`, `grafana/dashboards/ono.json`);
edits made in the UI can be exported as JSON and committed to make them permanent.

Without Docker: `uv run ono` then `curl localhost:8080/metrics` — the endpoint needs
nothing from this directory.

## Turning it off

`METRICS_ENABLED=false` removes the `/metrics` route (404) and collects nothing; scans run
exactly as before. The default is `true`. The endpoint is unauthenticated and outside the
OpenAPI schema: it is meant to be scraped in-box, and it never carries scan ids, file
paths, code or prompts — only counts and timings (plan §10, logging hygiene).

## What each metric means

Label values are closed sets (the allowlist's `target_id`, enums), so cardinality stays
in the tens.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `ono_build_info` | Info | `version`, `model_backend` | Which build and analyzer backend this process runs |
| `ono_scans_total` | Counter | `target`, `status` (`done` \| `failed`) | Scans that ended, by allowlisted target and outcome |
| `ono_scan_duration_seconds` | Histogram | — | Worker pick-up to end of scan (buckets 0.1 s … 1 h). A scan failed at shutdown never started and is not timed |
| `ono_findings_total` | Counter | `severity`, `rung` (1–5), `verified` (`true` \| `false`) | Findings persisted by completed scans |
| `ono_verifier_results_total` | Counter | `result` (`pass` \| `fail` \| `skip`) | Raw findings seen by the verify stage: verdict true, dropped, or passed through without a verdict (the service backend's verifier is a pass-through until step 3b-2, so its findings count as `skip`) |
| `ono_active_scans` | Gauge | — | Scans running on a worker right now (≤ `MAX_ACTIVE_SCANS`) |
| `ono_queued_scans` | Gauge | — | Scans waiting for a worker (≤ `MAX_QUEUED_SCANS`; beyond that `POST /scans` answers 429) |
| `ono_model_requests_total` | Counter | `outcome` (`ok` \| `error`) | `/chat/completions` requests made by the shared model client |
| `ono_model_latency_seconds` | Histogram | — | Wall-clock latency of one model request, success or failure (buckets 50 ms … 120 s) |
| `ono_model_tokens_total` | Counter | `kind` (`prompt` \| `completion`) | Tokens from the reply's `usage` block; nothing is counted when the server omits it |
| `process_*`, `python_*` | — | — | Standard process / interpreter collectors (RSS, CPU, GC; `process_*` on Linux only) |

The `mock` backend makes no model calls, so the `ono_model_*` series stay at zero there;
they move under `MODEL_BACKEND=service`.

**Not (yet) exposed — time to first token.** `ono_model_ttft_seconds` needs a streaming
model call; the client posts `stream: false` and gets one body back, so there is no
first-token instant to measure and the metric is deliberately absent rather than faked.
Until the client streams, take TTFT from the model server itself: vLLM's `/metrics`
has `vllm:time_to_first_token_seconds` (a commented scrape job is in `prometheus.yml`).
The **shadow-cost** counter from plan §8.6 is derived data (`tokens × rate`); compute it
in Grafana from `ono_model_tokens_total` or in the JSONL/DuckDB layer rather than as a
second source of truth.

## Dashboard panels

Top row: active / queued scans, scans done and failed in range, verifier pass rate
(`pass / (pass + fail)`), model error rate. Then: scan completions per minute by status,
scan duration p50/p95; findings per hour by severity (fixed status colors), findings by
rung, verifier results per hour; model latency p50/p95, requests per minute by outcome,
tokens per second by kind.

## Files

```
observability/
├── prometheus.yml                                 scrape config (app:8080 every 15 s)
├── grafana/provisioning/datasources/prometheus.yml the in-stack Prometheus datasource
├── grafana/provisioning/dashboards/dashboard.yml   loads grafana/dashboards/*.json
└── grafana/dashboards/ono.json                     the ONO dashboard
```
