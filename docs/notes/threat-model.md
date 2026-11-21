---
title: Each input to Tsong is trusted only as far as its source
type: note
summary: Callers and downstreams are untrusted, trusted issuers are trusted only for their own tokens, the config is trusted less than the host, and the host's environment, files and bootstrap file are trusted.
status: evolving
created: 2026-11-18
---

# Each input to Tsong is trusted only as far as its source

Tsong sits between callers and the services behind it, and takes input from five sources. Each is trusted only as far as the table says. The [assurance case](assurance-case.md) argues from this model that Tsong's security requirements hold. A review asks of each change whether it lets a source control more than its row allows.

| Source | Trust | What it may control |
| --- | --- | --- |
| Caller | None | The request: host, path, headers, body and bearer token. The token endpoint's form. Its peer address, but only through a trusted proxy's `X-Forwarded-For`. |
| Trusted issuer | Only for its own tokens | Its discovery document and JWKS, so which keys sign its tokens. Never another issuer's subjects. |
| Downstream | None | The response to a request Tsong forwarded: status, headers and body. |
| Config | Less than the host | Routes, trusted issuers, claim mapping, allow lists and secret references. Whoever can change the published config file controls these. |
| Host | Full | The bootstrap file, environment variables, files the config points to, and the signing keys. |

## Callers

Every check on a caller is mandatory, and config sets the values but never turns a check off.

- The token is validated in full: signature, `alg` against the issuer's allowed list, `kid`, `iss`, `aud`, `exp` and `nbf`. A failure is a 401, or `invalid_request` at the token endpoint.
- The route comes from the host header alone, and route policy bounds the audiences and scopes a minted token may carry.
- `gateway.allow`, narrowed per route, admits callers by address. `X-Forwarded-For` counts only from a peer in `trusted_proxies`.
- The original token never reaches a downstream, and hop-by-hop and `Forwarded` headers are stripped.
- The token endpoint has no client authentication. In its place are the subject token's validation, the allow lists and route policy.

## Trusted issuers

A trusted issuer's keys are fetched over https, expire after `jwks_max_age`, and are refetched at most every `jwks_refetch` on an unknown `kid`. An issuer can mint any subject it likes, but only under its own `sub_prefix`, so it can never speak for another issuer's subjects.

## Downstreams

A downstream is reached over https only. Its response passes back to the caller, but it never sees the caller's token, only the minted one, which is scoped to its route.

## The config

Whoever can change the published config file controls the config, so the pipeline that publishes it is part of Tsong's security. Tsong limits what such a change can do:

- It can't add a secret: secret fields hold only references, `{ env = "NAME" }` or `{ file = "path" }`, and a value written into one is refused without being quoted.
- It can't change the admin and health listeners, which the bootstrap file sets. It does set the gateway and issuer listen addresses.
- A config that fails validation never replaces the one being served.

What it can still do is point a reference at any environment variable or file the process can read. Today that only loads a signing key or a client secret Tsong doesn't send anywhere. Introspection, [roadmap](../../ROADMAP.md) item 3, will send `client_secret` to the trusted issuer's `introspection_url`, which the same config chooses. Before it ships, introspection must not let a config alone send a secret it names to a host it names.

## The host

The bootstrap file, the environment and the filesystem are trusted. They hold the signing keys and decide where the config comes from. Anyone who controls them controls Tsong.

## Errors and logs

Errors and audit lines name references, kids, routes and addresses, never a secret or a token. A secret written into a config by mistake is refused without being quoted, and `Secret`'s `Debug` hides its bytes.
