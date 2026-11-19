---
title: A route's token policy validates, then translates, in one block per route
type: note
summary: Each route states which audiences and scopes it allows, requires and denies, CEL rules over the claims, and maps from inbound to outbound audiences and scopes, applied in that order before minting.
status: evolving
created: 2026-11-19
---

# Token policy

A route decides which subject tokens it accepts and what the minted token carries. Today that decision is spread over a trusted issuer's `audiences`, a route's `[routes.audiences]`, `allowed_scopes`, `required_scopes` and `append_audience`, and the global `[claims]` copy and rename lists (`examples/tsong.toml`, `Issuer::exchange` in `crates/tsong-issuer/src/lib.rs`). The token policy gathers the route's part into one block per route, so an authorization modeller reads a route's whole policy in one place.

## Today

- A route's `[routes.audiences]`: the subject token must carry at least one audience in `allow` and none outside it, every one in `require` and none in `deny`. This is pull request 1 below.
- A route's `allowed_scopes`: any scope outside the list refuses the request. A token with no scopes passes.
- `required_scopes`: every one must be present.
- The minted token keeps the inbound audiences and scopes unchanged, plus `append_audience`.
- Claims are copied and renamed per trusted issuer, not per route. Nothing checks a claim's value.

## The policy

One rule for every allow list: the token must carry at least one allowed value, and nothing outside the list. `"*"` allows any value, and then only the deny list narrows it. A deny list may hold values only under `"*"`; under a named allow list, a value is denied by leaving it out.

```toml
[[routes]]
name = "orders"
host = "orders.example.com"
downstream = "https://orders-lb.internal.example.com"
append_audience = "orders.example.com"

[routes.audiences]
allow = ["api://default", "api://tsong"]
require = []
map = { "api://default" = "orders" }

[routes.scopes]
allow = ["*"]
require = ["orders.read"]
deny = ["orders.admin"]
map = { "orders.read" = "read", "orders.write" = "write" }

[routes.rules]
email-domain = 'claims.email.endsWith("@example.com")'
admins-only = '"orders-admins" in claims.groups'
```

Tsong applies it in this order:

0. Validation, as today (`Validator::validate` in `crates/tsong-validate/src/lib.rs`): the signature first, then `iss`, `exp`, `nbf` and the trusted issuer's `audiences`. The signature comes first so no claim is read from a token that may be forged, and a forgery is reported as one, never as expired.
1. Audiences: at least one allowed, none outside `allow`, every `require` present, no `deny` present.
2. Scopes: the same four checks. The request's `scope` parameter then narrows the scopes, in inbound names, as it does today.
3. Rules: every rule must evaluate to `true`.
4. Translate: each audience and scope in `map` becomes its outbound value, an unmapped value passes through unchanged, `append_audience` is added, and repeats are dropped.
5. Claims: copied and renamed as today, through `[claims]`.

Every check runs on inbound values. `map` changes only what the minted token carries.

### Loading

The config fails to load, and `tsong check` reports it, when:

- `allow` is missing. An empty `allow` denies every request, as empty lists do today.
- A value is empty, holds whitespace, or repeats within its list.
- `"*"` appears in `require` or `deny`, or alongside other values in `allow`.
- `deny` holds values and `allow` isn't `"*"`. Under a named `allow`, a denied value is one left out of `allow`.
- A value is in both `require` and `deny`, or `require` names a value `allow` doesn't admit.
- An audience `deny` lists is the route's `append_audience`, which the route adds to every token it mints.
- A `map` key is a value `allow` can't admit, or a scope's mapped value is empty or holds whitespace.
- A rule doesn't parse or type-check as CEL, or its result isn't a boolean.

`tsong check` warns when an audience `allow` is `"*"` with no `require` or `deny`, which accepts any audience, and when the audience policy admits no audience a trusted issuer that validates JWTs accepts, which refuses every token.

`allowed_audiences`, `allowed_scopes` and `required_scopes` are removed, not kept as aliases, and an old config is refused naming the new block. The release notes say how to move a config across.

### Rules

Rules are CEL, the Common Expression Language, through the `cel-interpreter` crate. CEL isn't Turing-complete, always terminates, and type-checks at load, so a broken rule fails `tsong check` and never reaches a request.

A rule sees:

- `claims`: the subject token's validated claims, as a map.
- `issuer`: the trusted issuer's name in the config, such as `"okta"`.
- `audiences` and `scopes`: the inbound lists.

A rule that is false refuses the exchange. So does a rule that fails to evaluate, such as one that reads a claim the token doesn't have. The error is `invalid_request`, which RFC 8693 section 2.2.2 gives for a subject token that fails validation, and it names the rule, as does the audit line. Errors and audit lines carry the rule's name, never its expression. A rule never sees the raw token. Rules are evaluated in name order, so every replica reports the same rule.

### Reloading

A reload builds a new `Gateway` with an empty exchange cache (`crates/tsong/src/state.rs`), so a policy change applies from the next request. No token minted under the old policy is served from the cache after a reload.

## Pull requests

Each goes through code review and security review, with a failing test pinned for every finding. Each updates the sample configs and the README, and the threat model and assurance case where it changes what a config may control.

1. Audience policy. Add `[routes.audiences]` with `allow`, `require` and `deny`, apply the allow rule, and remove `allowed_audiences`. Load checks, proptests over the four checks, and the fuzz seeds.
2. Scope policy. Add `[routes.scopes]` the same way, and remove `allowed_scopes` and `required_scopes`. A token with no scopes is now refused by every route.
3. Translation. Add `map` to both blocks, with load checks and proptests that every check runs on inbound values.
4. CEL rules. Add `[routes.rules]` and the `cel-interpreter` dependency, after `cargo deny` accepts it. Compile at load, fail closed on evaluation, and add a fuzz target that evaluates the sample rules against arbitrary claims. Tsong must not panic on any rule or claims, so the target runs with `--debug-assertions`.

Per-route claim mapping is not part of this work. Claims stay global and per trusted issuer until a route needs its own.

## Related

- [[gateway-plan]], which plans the exchange the token policy runs inside.
- [[threat-model]], which says what a config from Git may control.
- `ROADMAP.md` item 31.
