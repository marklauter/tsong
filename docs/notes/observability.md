---
title: Tsong reports health, metrics and an audit line per exchange
type: note
summary: Liveness and readiness on their own listener, Prometheus metrics on the admin listener, one JSON audit line per token exchange, and every request correlated by X-Request-Id and W3C traceparent.
status: evolving
created: 2026-11-16
---

# Tsong reports health, metrics and an audit line per exchange

Tsong reports four things about itself:

- whether it is alive and ready
- Prometheus metrics
- one audit line per token exchange
- a request ID and trace context on every gateway request

This is item 9 of the [roadmap](../../ROADMAP.md); config loads are audited as described in [[config-source]].

## Health

`GET /health/live` answers 200 while the process runs. `GET /health/ready` answers 200 once the config is loaded and every listener is bound, and 503 from the moment shutdown begins, so a load balancer stops sending before the listeners close ([[shutdown-and-draining]]). A failed first load stops Tsong from starting. A failed reload doesn't make Tsong unready: the last good config keeps serving. A JWKS outage doesn't either, because the gateway answers 503 for the affected requests already. The config is read only at start until roadmap item 32 adds a poll ([[config-source]]).

The health checks have their own listener, for the load balancer in front of Tsong, set in the bootstrap file:

```toml
[health]
listen = "0.0.0.0:8447"
allow = ["10.20.0.0/16"]   # the load balancer's subnets
```

The list is deployed in the bootstrap file, never loaded from the config, and checked against each connection's own address.

## Metrics

`GET /metrics` on the admin listener serves the Prometheus text format, behind `gateway.allow`. The registry lives for the process, so a reload keeps counting into the same series.

| Metric | Labels | What it counts |
| --- | --- | --- |
| `tsong_cache_hits_total` | | Requests whose exchanged token came from the cache, or from an exchange another request had already started |
| `tsong_cache_misses_total` | | Requests that exchanged their token |
| `tsong_cache_entries` | | Exchanged tokens in the cache. A reload starts a new, empty cache |
| `tsong_gateway_requests_total` | `route`, `status` | Gateway answers. `route` is `-` when no route matched |
| `tsong_downstream_seconds` | `route` | Time to a downstream's response headers, 1ms to about 16s |
| `tsong_exchanges_total` | `outcome` | Token exchanges: `issued`, or the OAuth error code |
| `tsong_jwks_fetch_failures_total` | `issuer` | Failed JWKS fetches, by the trusted issuer's `iss` |
| `tsong_jwks_age_seconds` | `issuer` | Seconds since the trusted issuer's keys were fetched, for the config being served. Past its `jwks_max_age`, its tokens are refused. An issuer whose keys were never fetched has no series |
| `tsong_config_reloads_total` | `outcome` | Reloads that found a new revision: `applied`, `fetch_failed`, `invalid_config` or `build_failed` |
| `tsong_config_last_fetch_timestamp_seconds` | | When the config store was last read, new revision or not. The config is read only at start until roadmap item 32, so the value stays fixed after start |
| `tsong_config_revision_info` | `revision` | The revision being served, set to 1: the newest revision read whose config is in use. Across replicas, more than one `revision` means they haven't converged |
| `tsong_config_tip_rejected` | | 1 while the newest config read was invalid or failed to build, so an older one is still served |

Labelling by route costs one series per route and status, and one histogram per route. That cost grows with the route count.

## Audit

Each token exchange writes one JSON line to stdout. That covers every cache miss in the gateway and every call to the token endpoint. A cache hit isn't an exchange, so it writes nothing, and the metrics count it instead. Collecting stdout belongs to the platform.

```json
{"event":"token_exchange","at":1763251200,"outcome":"issued","request_id":"9f1c…","trace_id":"4bf92f35…",
 "audience":"orders.example.com","trusted_issuer":"okta","iss":"https://example.okta.com/oauth2/default",
 "sub":"00u1abcd","scope":"orders.read","error_description":null,"duration_ms":3.2}
```

`iss` and `sub` are the subject token's, which identify the caller together. A refusal carries the OAuth error code as its `outcome` and its `error_description`. `iss` and `sub` are null when the token never validated. Tokens are never written.

The issuer reports each exchange to an `ExchangeObserver` (`crates/tsong-issuer/src/context.rs`). `ExchangeAudit` in `crates/tsong/src/telemetry.rs` writes the line and counts the exchange.

Each failed JWKS fetch writes a line, and so does the first fetch that succeeds after a failure. While an issuer is down, a line appears every `jwks_retry`.

```json
{"event":"jwks_fetch","at":1763251200,"outcome":"failed","issuer":"https://example.okta.com/oauth2/default","error":"…"}
{"event":"jwks_fetch","at":1763251230,"outcome":"recovered","issuer":"https://example.okta.com/oauth2/default","error":null}
```

`ObservedFetcher` in `crates/tsong/src/telemetry.rs` writes these lines and counts the failures.

## Correlation

Every gateway request leaves with an `X-Request-Id` and a `traceparent`:

- A valid inbound `X-Request-Id`, 1 to 128 visible ASCII characters, is kept. Anything else is replaced with 32 random hex digits. The ID is sent downstream and returned to the caller on every response, refusals included.
- A valid version-00 `traceparent` keeps its trace ID and flags, with a new parent ID for the gateway's hop. Without one, a new trace starts with the sampled flag clear, and any `tracestate` is dropped, as the W3C Trace Context spec requires.

Both IDs are on every exchange audit line. The token endpoint reads them from its request without changing them.

## Deferred

- Exporting spans through OpenTelemetry. The gateway propagates trace context, but doesn't record spans of its own.
- A per-request access log. The request metrics cover most of what it would show.
