---
title: The gateway exchanges each bearer token once and forwards by host
type: note
summary: The gateway looks up a route by host, exchanges the bearer token through a read-through cache, swaps it in, and streams the request to the route's downstream.
status: evolving
created: 2026-11-15
---

# The gateway exchanges each bearer token once and forwards by host

The gateway authenticates callers. Downstreams own authorization. A request flows through these steps:

1. Look up the route by the request's host.
2. Check the client IP against the allow lists.
3. Read the bearer token.
4. Get the exchanged token from the cache, exchanging on a miss.
5. Replace the bearer token and stream the request to the route's downstream.

The gateway is item 5 of the [roadmap](../../ROADMAP.md), and its exchange cache is item 6.

## Routes

A route maps one host to one downstream. Matching uses the host alone. There is no path matching, so the path and query go to the downstream unchanged.

```toml
[[routes]]
name = "orders"
host = "orders.example.com"
downstream = "https://orders-lb.internal.example.com"
append_audience = "orders.example.com"
allowed_scopes = ["orders.read", "orders.write"]
allow = ["10.20.0.0/16"]

[routes.audiences]
allow = ["api://orders", "orders.example.com"]

[[routes]]
name = "builds"
host = "builds.example.com"
downstream = "https://builds-lb.internal.example.com"
append_audience = ""
allowed_scopes = []

[routes.audiences]
allow = ["*"]
deny = ["api://admin"]
```

- `host` is the key. It is compared lowercased, without its port. Two routes with the same host are a config error.
- `downstream` is an `https` origin with no path, query or fragment. It names the load balancer to forward to, by DNS name. IP addresses are not used, because load balancer addresses change.
- `append_audience` is added to the minted token's `aud`. When it is empty, nothing is added.
- `[routes.audiences]` holds the route's audience policy. The inbound token must carry at least one audience in `allow` and none outside it. Optional `require` lists audiences it must all carry, and optional `deny` audiences it may not carry. `"*"` must stand alone in `allow`, and then only `deny` narrows it. Each `require` and `deny` value must be one `allow` admits, and none may be in both.
- `allowed_scopes` lists the inbound scopes the route accepts. Every scope the inbound token carries must be in it.
- `required_scopes`, optional, lists scopes the inbound token must all carry. Each must be one `allowed_scopes` accepts, and a scope narrowed with the token endpoint's `scope` parameter must keep them all.
- `signing_algorithm`, optional, is the algorithm the route's minted tokens are signed with: RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384 or EdDSA, ES256 when unset. A key for it must be active in `issuer.signing.keys`.
- `allow` is optional, and adds a second IP check to the gateway-wide `gateway.allow`. A client must be in both lists, so a route can only narrow access. A route without `allow` takes `gateway.allow` alone.
- `read_timeout` is optional, and overrides `gateway.read_timeout`, the longest the gateway waits on a downstream between reads. That defaults to 60 seconds.

An empty `audiences.allow` or `allowed_scopes` denies every request. `"*"` accepts any value. IP lists follow the same rule: an empty `gateway.allow`, or an empty route `allow`, denies every client, and `["0.0.0.0/0", "::/0"]` allows every client. Validation stays mandatory: the config sets values, and no value switches a check off.

`[[routes]]` deserializes as `Vec<Route>`. `RouteTable` in `crates/tsong-config/src/lib.rs` indexes it as a `HashMap<String, Route>` keyed by lowercased host, and the issuer and the gateway each hold one. The allowed audience and scope lists stay `Vec<String>`: they hold a few entries, and scanning a few entries costs less than hashing. A config reload, roadmap item 7, will build a new table and swap it in.

## Exchange

The token endpoint stays reachable on its own, so the issuer enforces the route, not the gateway. Before an exchange it applies the same IP allow lists the gateway does, `gateway.allow` and the named route's `allow`, finding the client through the same trusted proxies, and refuses with `access_denied` (403). The gateway asks for an exchange with `audience` set to the request's host. The issuer then:

1. Looks up the route by that host, and fails with `invalid_target` when there is none.
2. Validates the subject token against the global trusted issuers. Every trusted issuer may exchange into every route.
3. Checks the inbound `aud` against `[routes.audiences]`, and the inbound scopes against `allowed_scopes` and `required_scopes`. A failure is `invalid_target` for the audience and `invalid_scope` for the scopes.
4. Mints a token whose `aud` is the inbound `aud` followed by `append_audience`, without duplicates.
5. Sets the minted `scope` to the inbound scopes. A `scope` parameter on the request narrows them. Asking for a scope the inbound token lacks, or narrowing away one the route requires, is `invalid_scope`.

The gateway calls the issuer through an `Exchanger` trait. The MVP implementation calls the `Issuer` in-process. An HTTP implementation can come later.

## Cache

The cache is read-through. A miss exchanges the token and stores the result, and concurrent misses on the same key share one exchange. It uses `moka`.

- The key is the SHA-256 of the inbound token plus the route host. The cache never holds an inbound token in the clear.
- An entry expires at the minted token's `exp` minus the clock skew. The gateway reads `exp` from the minted token's payload, because the downstream enforces `exp` and `expires_in` drifts with response latency. `expires_in` is the fallback for a token whose payload can't be read. A minted `exp` never exceeds the inbound `exp`, so the inbound lifetime caps the entry too.
- `gateway.cache.max_entries` bounds the entry count.
- A failed exchange is not cached.

## Request handling

- The client IP is the TCP peer, unless the peer is in `gateway.trusted_proxies`. In that case the gateway walks `X-Forwarded-For` from the right and stops at the first address outside `trusted_proxies`. A caller can forge `X-Forwarded-For`, so only trusted proxies are believed.
- The gateway-wide `allow` list applies first, then the route's `allow`.
- The token comes from `Authorization: Bearer`.
- The `Authorization` header is replaced with the minted token. The inbound token is never forwarded.
- Hop-by-hop headers are stripped, as RFC 9110 section 7.6.1 requires of an intermediary.
- The gateway sends `X-Forwarded-*`, which load balancers and downstream frameworks read by default. It strips any inbound `Forwarded` header (RFC 7239), so a downstream never trusts a value the gateway didn't check.
- `Host` is set to the downstream's host. `X-Forwarded-Host` carries the original host. `X-Forwarded-For` and `X-Forwarded-Proto` are set. A trusted proxy's `X-Forwarded-For` chain, `X-Forwarded-Proto` and `X-Forwarded-Host` are kept; anyone else's are replaced.
- Hops left of the client in `X-Forwarded-For` are never read, so an unparsable entry there doesn't fail the request.
- Request and response bodies stream through a `reqwest` client. A request body known to be empty is not sent. The client follows no redirects and uses no proxy.

The gateway fails closed:

| Condition | Status |
| --- | --- |
| No route for the host | 404 |
| A trusted proxy's `X-Forwarded-For` hop is not an IP address | 400 |
| Client IP not allowed | 403 |
| Missing or malformed bearer token | 401 with `WWW-Authenticate: Bearer` |
| Inbound token invalid | 401 with `WWW-Authenticate: Bearer` |
| Audience or scope not allowed for the route | 403 |
| Issuer or inbound JWKS unavailable | 503, without the cause |
| Exchange failed inside the issuer, such as signing | 500, without the cause |
| Downstream unreachable | 502 |
| Downstream silent past its read timeout | 504 |

## Config lint

`tsong check <config.toml>` lints the config for CI.

- Errors exit 1. They are everything validation rejects, such as a repeated host or a `downstream` that is not an `https` origin.
- Warnings print and exit 0, unless `--deny-warnings` is set, which makes them exit 1.
- An empty `allowed_*` or IP `allow` list warns that every request will be denied, which looks like an omission.
- A `"*"` entry, or `0.0.0.0/0` or `::/0` in an IP `allow` list, warns that anything is accepted, which needs confirming.

Each message names the route and the field, such as `warning: route "builds": allowed_scopes is empty; every request will be denied`.

## Serve

`tsong serve` runs the gateway on `gateway.listen` and the issuer on `issuer.listen`, sharing one `Issuer`, one config and one shutdown signal.

## Tests

The gateway tests run an in-process fake downstream that echoes the request it receives. Most use a fake `Exchanger` that answers by token. One runs the real `Issuer` against the in-process fake inbound issuer. Like all tsong code, the tests never panic.

## Deferred

- Downstream TLS name verification when the downstream's DNS name differs from the certificate's name.
- Per-route audience and scope policy for the minted token. The MVP only filters the inbound token.
- Route files split across many files, so that one config file doesn't grow unbounded.
- An HTTP `Exchanger` for a gateway that runs apart from the issuer.
- WebSocket and other `Upgrade` requests.
- Reading and sending the RFC 7239 `Forwarded` header.
