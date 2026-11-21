---
title: Tsong meets its security requirements because each is designed in and checked by tests and CI
type: note
summary: Tsong's security requirements, the threat model and trust boundaries they rest on, and the secure design and countermeasures to common weaknesses that make each hold, with the evidence for each.
status: evolving
created: 2026-11-19
---

# Tsong meets its security requirements because each is designed in and checked by tests and CI

Tsong's assurance case sets out what Tsong guarantees, the threats it guards against, and the evidence that each guarantee holds.

## Security requirements

1. A request reaches a downstream only with a token minted for its route, from a caller whose token a trusted issuer signed, whose address the allow lists admit, and whose audiences and scopes the route accepts.
2. The caller's own token never reaches a downstream.
3. A minted token carries only the scopes the route allows, the caller held and the request asked for, and always the scopes the route requires; it carries no claim the config doesn't map.
4. One trusted issuer can never mint a subject that belongs to another.
5. No check can be turned off by config, and a config that fails validation never replaces the one being served.
6. Secrets never sit in the config, and are never written to errors or logs.
7. Malformed input is refused, never a crash.

## Threat model and trust boundaries

The [threat model](threat-model.md) names the five sources of input, how far each is trusted, and what each may control: callers and downstreams are untrusted, trusted issuers are trusted only for their own tokens, the config is trusted less than the host, and the host is trusted. The trust boundaries are the gateway and issuer listeners, which face callers; the outbound connections to downstreams and trusted issuers; the config store; and the bootstrap file and environment, which belong to the host.

## Secure design

The design applies Saltzer and Schroeder's principles, and the requirements follow from them:

- **Fail-safe defaults** (requirements 1, 5): empty allow and scope lists deny everything, expired issuer keys refuse their tokens, and a config that fails keeps the last good one serving.
- **Complete mediation** (1, 3): every request passes the allow lists, full token validation and route policy. The token endpoint enforces the same policy as the gateway, so it offers no way around it.
- **Separation of privilege** (1): a request needs an admitted address, a valid signature from a trusted issuer, and an accepted audience and scope. Defeating one isn't enough.
- **Least privilege** (3): a minted token holds only what the route, the caller and the request all allow. The container runs as an unprivileged user on a read-only filesystem, and CI workflow tokens are read-only by default.
- **Least common mechanism** (4): each trusted issuer has its own key cache and subject prefix, so issuers share no trust.
- **Economy of mechanism** (5): one config file, one immutable state per config swapped whole, one crate per job.
- **Open design** (6): security rests on keys and secrets, never on secrecy of the code; secrets are references, never values.
- **Limited attack surface**: the admin and health listeners are separate, configured only by the host, each with its own allow list.
- **Allowlists for input** (7): algorithms, issuers, audiences, scopes, client ranges, hosts and secret schemes are all allowlists, and unknown config fields are errors.

## Common weaknesses and their countermeasures

| Weakness | Countermeasure | Evidence |
| --- | --- | --- |
| Broken JWT validation: `alg: none`, RS/HS key confusion, `kid`, `jku` and `x5u` tricks, cross-issuer keys | Per-issuer algorithm allowlists; keys only from the issuer's own JWKS; every claim checked | 43 hand-built attacks refused: `crates/tsong-validate/tests/attacks.rs` |
| Missing authentication or authorization (CWE-306, CWE-862) | Every request validated and checked against route policy and allow lists, at the gateway and the token endpoint alike | Gateway and issuer tests; scope and claim properties: `crates/tsong-issuer/tests/mint_properties.rs` |
| Client address spoofing | `X-Forwarded-For` believed only from trusted proxies, read from the right | Properties: `crates/tsong-config/tests/properties.rs`; the `forwarded` fuzz target |
| SSRF through discovery or JWKS URLs (CWE-918) | https only, the JWKS on the issuer's scheme, timeouts on every fetch | `crates/tsong-validate/tests/fetch.rs` |
| Secrets in config or logs (CWE-798, CWE-532) | Secret references only; a value written in by mistake refused without being quoted; redacted `Debug` | `crates/tsong-config/tests/config.rs`, `crates/tsong-secrets/tests/secrets.rs` |
| Memory corruption (CWE-787, CWE-416) | Safe Rust only: the workspace forbids `unsafe` | The workspace lints, and a CI check that every crate inherits them |
| Crashes on malformed input (CWE-20, CWE-248) | Panics denied by lint, tests included; checked arithmetic | Four fuzz targets with AddressSanitizer and overflow checks: `fuzz/` |
| Vulnerable or untrusted dependencies (CWE-1104) | cargo audit, cargo-deny, Dependabot, actions pinned by SHA | CI's `audit` and `deny` jobs |

## Evidence that this stays true

Every change reaches `main` through a pull request whose required checks run formatting, clippy with restriction lints, the tests in two profiles, 95% line coverage, mutation testing of the changed lines, cargo audit, cargo-deny, a fuzz run of every target, and CodeQL. A weekly workflow fuzzes each target for ten minutes and runs the property tests with 100,000 cases each. OpenSSF Scorecard checks the repository's practices weekly.
