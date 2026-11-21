# Architecture

Tsong is one Linux binary that runs an API gateway and an RFC 8693 token exchange issuer in one process. The [README](README.md) describes the request flow and lists the crates, and the [threat model](docs/notes/threat-model.md) says what each input may control.

## Process and listeners

`tsong serve` reads a bootstrap file, deployed with Tsong, that says where the config comes from. It then serves up to four listeners, each a plain-HTTP socket behind a TLS-terminating load balancer:

- The gateway, for callers' requests to the routes' downstream services.
- The issuer: the token endpoint, the JWKS and the OIDC discovery document.
- The admin listener, optional: the config's status and Prometheus metrics.
- The health listener, optional: liveness and readiness for the load balancer.

The gateway and the issuer read their address and policy from the config. The admin and health listeners read theirs from the bootstrap file, each with its own allow list, so the config can't open or move them.

## State and reloads

Tsong builds one immutable `State` from each config. It holds the signing keys, the trusted issuers' key caches, the route table, the exchange cache and the HTTP clients. The listeners serve from whichever `State` is current when a request arrives, and a request keeps that state until it finishes.

The config is a file, read once at start, and a config that fails to parse, validate or build stops Tsong from starting. The reloader can fetch a config, validate it, and build a whole new `State` before swapping it in, so a config that fails never replaces the one being served, and nothing carries over between states. Nothing triggers a reload until roadmap item 32 adds a poll. [docs/notes/config-source.md](docs/notes/config-source.md) describes the store and the reloader.

## How a request is handled

The gateway looks up the route by host, checks the caller's address against the allow lists, and asks the exchanger for a token for the route. The exchanger is the issuer, called in process. It validates the caller's token against its trusted issuer, applies the route's audience and scope policy, and mints a token signed with the route's algorithm. The gateway caches the minted token per inbound token and route host until shortly before it expires. It forwards the request with the minted token in place of the original. [docs/notes/gateway-plan.md](docs/notes/gateway-plan.md) describes the gateway in detail.

## Crates and their dependencies

Each crate has one job, and dependencies point one way, from the command down to the config:

- `tsong` builds `State`, runs the listeners and the reloader, and depends on every other crate.
- `tsong-gateway` depends on `tsong-issuer` for the exchange.
- `tsong-issuer` depends on `tsong-validate` for inbound tokens and `tsong-keys` for signing.
- `tsong-keys` depends on `tsong-secrets` to read private keys.
- Every crate depends on `tsong-config`, the model and its validation, and none depends on `tsong`.

## Design decisions

- **Validation is mandatory.** Config sets the values a check uses, but no setting turns a check off.
- **Fail closed.** An empty allow list or scope list denies everything, expired issuer keys refuse their tokens, and a config that fails keeps the last good one serving.
- **Secrets are references.** A secret field names an environment variable or a file, so a config holds no secrets and can live in Git.
- **No panics.** Failures are values, `unsafe` code is forbidden, and lints deny `unwrap`, `expect`, `panic!` and indexing, tests included.
- **Injected time.** Every expiry and age comes from an injected `Clock`, so tests control time.
- **One immutable state per config.** Reloads swap whole states, never patch one.
