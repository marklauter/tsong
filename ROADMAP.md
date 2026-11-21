# Roadmap

What Tsong has built and what comes next. The open items are the plan for the next year, in order of priority. Done means built, tested above the 95% line-coverage floor, and merged. Until something is merged it stays on the list. The [threat model](docs/notes/threat-model.md) names what each input to Tsong may control.

1. Skeleton: the config model and its validation, the `SigningKey` trait with the file provider, and `tsong check` (done).
2. Issuer: the RFC 8693 token endpoint, JWT validation of subject tokens against each trusted issuer's JWKS, minting, the JWKS and the discovery document, and `tsong serve` (done).
3. Introspection: validate opaque tokens, such as GitLab personal access tokens, by posting them to the issuer's RFC 7662 introspection endpoint. Until then, opaque tokens fail with "introspection is not supported yet" (`ValidateError::Unsupported` in `crates/tsong-validate/src/lib.rs`). So do JWTs from an issuer configured for introspection. A config may point `client_secret` at any file or environment variable on the host, so introspection must not let a config send that secret to an endpoint it chooses alone.
4. Actor tokens: accept `actor_token` and `actor_token_type` on the token endpoint and record the actor in the minted token's `act` claim. A token gets an `act` claim only when an actor token is sent. Until then, either parameter fails with `invalid_request`.
5. Gateway: the reverse proxy, planned in [gateway-plan](docs/notes/gateway-plan.md). Look up the route by host, enforce the IP allow lists, exchange the bearer token, replace the `Authorization` header and stream the request to the route's downstream. Fail closed and never forward the original token. (done)
6. Exchange cache: a read-through cache keyed on a hash of the inbound token plus the route host, expiring at the minted token's `exp` minus the clock skew, bounded by `gateway.cache.max_entries`. Planned in [gateway-plan](docs/notes/gateway-plan.md) and built with item 5. (done)
7. Config from Git (removed): it depended on gix, which pulls in heapless 0.8, and `cargo audit` fails on heapless advisories that no gix release fixes. A pipeline can run `tsong check` and publish the config file instead; item 32 plans config stores, and [config-source](docs/notes/config-source.md) describes the file store.
8. Cloud signing keys: AWS KMS and HSM providers behind the `SigningKey` trait (`crates/tsong-keys/src/lib.rs`), alongside the file provider, which sign without the private key leaving them. The config refers to a key by a pointer, such as an ARN, never by its contents.
9. Observability: liveness and readiness on their own listener, Prometheus metrics, one audit line per token exchange, and request correlation by `X-Request-Id` and `traceparent`. Planned in [observability](docs/notes/observability.md) (done).
10. Hooks: pre-exchange and post-exchange plugins, sandboxed in WebAssembly.
11. Rauthy integration test: exchange a token from a real issuer, Rauthy in podman, in addition to the in-process fake issuer the tests use now.
12. Issuer behind a path: the router serves `/token`, `/jwks.json` and `/.well-known/openid-configuration` at the root. For an `issuer.url` with a path, such as `https://example.com/tsong`, the discovery document names endpoints under that path. The router doesn't serve them there yet.
13. Downstream TLS names: verify a downstream's certificate when its DNS name differs from the name the certificate covers.
14. Minted-token policy per route: audiences and scopes the minted token carries, beyond the filters on the inbound token.
15. Split route files: load routes from many files in the config folder, so one config file doesn't grow unbounded.
16. Remote exchanger: an HTTP `Exchanger` for a gateway that runs apart from the issuer.
17. Upgraded connections: WebSocket and other `Upgrade` requests through the gateway, which strips hop-by-hop headers until then.
18. `Forwarded`: read and send the RFC 7239 `Forwarded` header alongside `X-Forwarded-*`. Until then the gateway strips it.
19. Git over HTTPS (withdrawn with item 7): a Git store in its own repository, item 32, would decide its transports.
20. Git host file API (withdrawn with item 7): a store that reads a Git host's API is one of the stores item 32 allows.
21. Signed commits (withdrawn with item 7): a Git store in its own repository, item 32, would verify them.
22. Tracing export: record the gateway's and the issuer's spans and export them through OpenTelemetry. Until then trace context is propagated but no spans are recorded.
23. Subject identity: each trusted issuer has a required, unique `sub_prefix`, and the minted `sub` is `<sub_prefix>:<sub>`. The subject token's own `iss` and `sub` go in an RFC 9493 `sub_id` claim (`iss_sub` format), always present and reserved from claim mapping. A token with an empty `sub`, or without the claim a rename makes its subject, is refused. A subject token that fails validation gets `invalid_request`, as RFC 8693 section 2.2.2 requires (done).
24. Issuer key expiry: each trusted issuer's keys expire after `jwks_max_age`, and a background refresher renews them three quarters of the way through, retrying a failure every `jwks_retry`. Keys that expire before a renewal succeeds refuse the issuer's tokens with a 503, with an audit line for each failure and for the recovery. A token with an unknown key ID, or whose signature fails with a known key, refetches once, no more often than `jwks_refetch`. `discovery_url` and `jwks_url` are set per issuer, and `jwks_timeout` bounds each fetch (done).
25. Config staleness: `tsong_config_last_fetch_timestamp_seconds` and `fetched_at` in `/status` report when the config store was last read, `tsong_config_revision_info` reports the revision each replica serves, and `tsong_config_tip_rejected` flags a newest config that won't load, so a stuck replica or replicas that haven't converged can be alerted on (done). The config is read only at start until item 32, so these metrics stay fixed after start.
26. Container: `tsong serve` stops on SIGTERM, failing readiness for `health.drain` before the listeners close. A `Containerfile` builds a non-root Debian slim image that runs with a read-only root filesystem, and `deploy/podman/run.sh` runs it in local podman with stub files. Building and publishing the image in CI comes later (done).
27. Required scopes: a route's optional `required_scopes` must all be present in the inbound token, and a token minted for the route keeps them all. Each must be one `allowed_scopes` accepts. Scope names pass through unchanged (done).
28. Signing algorithms: each route's `signing_algorithm` picks how its tokens are signed, from the nine asymmetric algorithms inbound validation accepts, ES256 by default. Each signing key names its algorithm, one key per algorithm is active, and every algorithm a route uses needs an active key. Keys are PKCS#8 PEM, signed through `aws-lc-rs`, and a key of the wrong type, or an RSA key under 2048 bits, is refused (done).
29. Secret references: a secret field holds a table with one key, the scheme, such as `{ env = "NAME" }`, never the secret, and the `SecretSource` for the scheme reads it (`crates/tsong-secrets/src/lib.rs`). A string is a value and a table is a reference, so neither needs escaping. `env` and `file` are built (done). Next, `{ aws-sm = "arn" }` for AWS Secrets Manager, then other secret stores as they are needed. The introspection `client_secret` is parsed and required, but read only once introspection (item 3) uses it.
30. Inbound TLS, low priority: a listener speaks HTTPS when the config gives it a certificate chain and private key, both secret references, through rustls, which Tsong already uses outbound. TLS 1.2 and 1.3 only, HTTP/2 over ALPN, and a new certificate loaded on reload. Plain HTTP stays for listeners behind a TLS-terminating load balancer, which is how Tsong is meant to run until then.
31. Token policy: one block per route that states which audiences and scopes it allows, requires and denies, CEL rules over the subject token's claims, and maps from inbound to outbound audiences and scopes. An allow list admits a token that carries at least one of its values and nothing outside it. It replaces `allowed_audiences`, `allowed_scopes` and `required_scopes`, in four pull requests. Planned in [token-policy](docs/notes/token-policy.md).
32. Config stores: an optional `poll` on a file source, so a config file a pipeline publishes reloads without a restart. Stores such as Git, S3 or an HTTPS URL live in their own repositories and implement the `ConfigStore` trait (`crates/tsong-config/src/store.rs`). For that, the bootstrap file's source must be open to stores Tsong doesn't name, and the trait needs an optional change notification beside `load`.

## On request

Tsong would build these once someone needs them, but they aren't scheduled. If you need one, open an issue that describes your case.

- JWT-bearer grant: accept RFC 7523's `urn:ietf:params:oauth:grant-type:jwt-bearer` at the token endpoint, for clients written for that grant, such as Microsoft Entra's on-behalf-of flow, that can't send an RFC 8693 exchange. The `assertion` is validated as a subject token is and goes through the same exchange path. The grant has no `audience` parameter, so part of the work is deciding how a request names the minted token's audience.

## Not planned

Tsong will not do these, this year or later:

- Authenticate users itself. Tsong trusts identity providers to log users in; it has no login page, sessions, consent screens or user store, and stores no passwords.
- Turn a check off. Config sets the values a check uses, such as audiences, scopes and allowed algorithms, but every check stays on.
- Sign or accept tokens with a shared secret. Tsong signs with asymmetric keys only, and refuses HS256 and its kin inbound.
- Run on platforms other than Linux.
