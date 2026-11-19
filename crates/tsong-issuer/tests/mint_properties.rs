//! What a minted token carries, over generated subject tokens and
//! requests: its scopes against the `billing` route, which allows
//! orders.read, orders.write and billing.read and requires orders.read and
//! billing.read; its audiences against the `policy` route's audience
//! policy; and its claims against the config's claim mapping. Each
//! run tries `PROPTEST_CASES` cases, 256 unless set; the weekly workflow
//! sets more.

mod common;

use std::collections::BTreeSet;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::*;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use serde_json::{Map, Value, json};
use tsong_config::RESERVED_CLAIMS;

const HELD: [&str; 4] = ["orders.read", "orders.write", "billing.read", "admin"];
const ALLOWED: [&str; 3] = ["orders.read", "orders.write", "billing.read"];
const REQUIRED: [&str; 2] = ["orders.read", "billing.read"];

fn config() -> ProptestConfig {
    ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "tests/mint_properties.proptest-regressions",
        ))),
        ..ProptestConfig::default()
    }
}

fn scopes() -> impl Strategy<Value = Vec<&'static str>> {
    prop::collection::vec(prop::sample::select(&HELD[..]), 0..5)
}

/// The scopes the minted token must carry, or `None` when the exchange
/// must be refused.
fn expected(held: &BTreeSet<&str>, requested: Option<&[&str]>) -> Option<BTreeSet<String>> {
    if !held.iter().all(|scope| ALLOWED.contains(scope)) {
        return None;
    }
    let granted: BTreeSet<&str> = match requested {
        None => held.clone(),
        Some(requested) => {
            if !requested.iter().all(|scope| held.contains(scope)) {
                return None;
            }
            requested.iter().copied().collect()
        }
    };
    if !REQUIRED.iter().all(|scope| granted.contains(scope)) {
        return None;
    }
    Some(granted.into_iter().map(str::to_owned).collect())
}

proptest! {
    #![proptest_config(config())]

    /// A minted token holds exactly the scopes the route allows, the
    /// subject token holds and the request asks for, and always the ones
    /// the route requires; any other exchange is refused.
    #[test]
    fn a_minted_token_holds_only_scopes_it_may(
        held in scopes(),
        requested in prop::option::of(scopes()),
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        let h = harness().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let held_set: BTreeSet<&str> = held.iter().copied().collect();
        let scope = if held.is_empty() { json!(null) } else { json!(held.join(" ")) };
        let mut token = request(&h, "billing.test", subject(json!({ "scope": scope })))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        token.scope = requested.as_ref().map(|requested| requested.join(" "));
        let result = runtime.block_on(h.issuer.exchange(token));
        match (expected(&held_set, requested.as_deref()), result) {
            (Some(expected), Ok(response)) => {
                let minted: BTreeSet<String> = response
                    .scope
                    .unwrap_or_default()
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect();
                prop_assert_eq!(minted, expected);
            }
            (None, Err(_)) => {}
            (expected, result) => {
                prop_assert!(false, "expected {expected:?}, got {result:?}");
            }
        }
    }
}

/// Claims a subject token might carry beyond the ones it needs: reserved
/// claims an attacker would like to set, claims the config copies or
/// renames, and claims it doesn't mention.
const EXTRA: [&str; 10] = [
    "act", "cnf", "sub_id", "jti", "iat", "email", "groups", "uid", "user", "secret",
];

/// The claims a token minted for the `orders` route may carry: the
/// reserved ones Tsong sets, `sub`, the copied `email` and `groups`, and
/// `uid` renamed to `user`.
fn may_carry(name: &str) -> bool {
    RESERVED_CLAIMS.contains(&name) || ["sub", "email", "groups", "user"].contains(&name)
}

/// The payload of a JWT, unverified: the signature is tested elsewhere.
fn payload(token: &str) -> Result<Map<String, Value>, TestCaseError> {
    let fail = |error: String| TestCaseError::fail(error);
    let body = token
        .split('.')
        .nth(1)
        .ok_or_else(|| fail("no payload".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|error| fail(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|error| fail(error.to_string()))
}

proptest! {
    #![proptest_config(config())]

    /// A minted token carries the copied and renamed claims with the
    /// subject token's values, and nothing else from it: no reserved claim
    /// and no claim the config doesn't name passes through.
    #[test]
    fn a_minted_token_carries_only_mapped_claims(
        extra in prop::collection::btree_map(prop::sample::select(&EXTRA[..]), "[a-z]{1,6}", 0..10),
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        let h = harness().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let mut changes = Map::new();
        for name in ["email", "groups", "uid", "secret"] {
            changes.insert(name.into(), Value::Null);
        }
        for (name, value) in &extra {
            changes.insert((*name).into(), json!(format!("in-{value}")));
        }
        let token = request(&h, "orders.test", subject(Value::Object(changes)))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let response = runtime
            .block_on(h.issuer.exchange(token))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let minted = payload(&response.access_token)?;
        for (name, value) in &minted {
            prop_assert!(may_carry(name), "minted {name}");
            let from_subject = value.as_str().is_some_and(|text| text.starts_with("in-"));
            let mapped = ["email", "groups", "user"].contains(&name.as_str());
            prop_assert!(!from_subject || mapped, "{name} = {value} came from the subject token");
        }
        for (copied, from) in [("email", "email"), ("groups", "groups"), ("user", "uid")] {
            let inbound = extra.get(from).map(|value| json!(format!("in-{value}")));
            prop_assert_eq!(minted.get(copied).cloned(), inbound);
        }
    }
}

/// Audiences a subject token might carry: the trusted issuer accepts
/// `tsong` and `api`, the `policy` route requires `tsong` and denies
/// `admin`.
const AUDIENCES: [&str; 4] = ["tsong", "api", "admin", "other"];

proptest! {
    #![proptest_config(config())]

    /// The `policy` route, which allows any audience, requires `tsong` and
    /// denies `admin`, accepts a subject token exactly when it carries
    /// `tsong` and not `admin`. A token it accepts is minted with the
    /// subject token's audiences, once each, and the route's
    /// `append_audience`; one it refuses is `invalid_target`, or a failed
    /// validation when no audience is one the trusted issuer accepts.
    #[test]
    fn a_route_s_audience_policy_decides_the_exchange(
        held in prop::collection::vec(prop::sample::select(&AUDIENCES[..]), 1..5),
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        let h = harness().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let token = request(&h, "policy.test", subject(json!({ "aud": held })))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let result = runtime.block_on(h.issuer.exchange(token));
        let accepted = held.contains(&"tsong") && !held.contains(&"admin");
        match result {
            Ok(response) => {
                prop_assert!(accepted, "accepted {held:?}");
                let minted = payload(&response.access_token)?;
                let mut expected: Vec<&str> = Vec::new();
                for aud in held.iter().copied().chain(["policy.test"]) {
                    if !expected.contains(&aud) {
                        expected.push(aud);
                    }
                }
                prop_assert_eq!(minted.get("aud").cloned(), Some(json!(expected)));
            }
            Err(error) => {
                prop_assert!(!accepted, "refused {held:?}: {error}");
                let validated = held.iter().any(|aud| ["tsong", "api"].contains(aud));
                let code = if validated { "invalid_target" } else { "invalid_request" };
                prop_assert_eq!(error.code(), code);
            }
        }
    }
}
