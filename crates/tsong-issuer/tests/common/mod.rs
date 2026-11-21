//! The issuer under test: a config, an inbound issuer and a fixed clock.
#![allow(dead_code)]

use std::error::Error;
use std::sync::Arc;

use serde_json::{Map, Value, json};
use tsong_clock::ManualClock;
use tsong_config::Config;
use tsong_issuer::{
    ACCESS_TOKEN, ExchangeEvent, ExchangeObserver, Issuer, TOKEN_EXCHANGE, TokenRequest,
};
use tsong_keys::{FileKey, KeySet, SigningAlgorithm};
use tsong_validate::Validator;
use tsong_validate::testkit::{FakeFetcher, TestKey, pem};

pub const NOW: u64 = 1_000_000;

pub const CONFIG: &str = r#"
[issuer]
url = "https://tsong.test"
listen = "127.0.0.1:0"
token_lifetime = "00:15:00"
clock_skew = "00:00:30"

[issuer.signing]
provider = "file"

[[issuer.signing.keys]]
kid = "tsong-1"
private_key = { file = "unused.pem" }
state = "active"

[gateway]
listen = "127.0.0.1:0"
trusted_proxies = ["10.0.0.0/24"]
allow = ["127.0.0.0/8", "10.0.0.0/8"]

[gateway.cache]
max_entries = 10

[trusted_issuers.test]
sub_prefix = "test"
issuer = "https://issuer.test"
audiences = ["tsong", "api"]
algorithms = ["ES256"]

[trusted_issuers.other]
sub_prefix = "other"
issuer = "https://other.test"
audiences = ["tsong"]
algorithms = ["ES256"]

[claims]
copy = ["email", "groups"]

[claims.rename.test]
uid = "user"

[claims.rename.other]
oid = "sub"

[[routes]]
name = "orders"
host = "orders.test"
downstream = "https://orders-lb.test"
append_audience = "orders.test"
audiences = { allow = ["tsong", "orders.test"] }
allowed_scopes = ["orders.read", "orders.write"]

[[routes]]
name = "open"
host = "open.test"
downstream = "https://open-lb.test"
append_audience = ""
audiences = { allow = ["*"] }
allowed_scopes = ["*"]
allow = ["10.1.0.0/16"]

[[routes]]
name = "billing"
host = "billing.test"
downstream = "https://billing-lb.test"
append_audience = ""
audiences = { allow = ["tsong"] }
allowed_scopes = ["orders.read", "orders.write", "billing.read"]
required_scopes = ["orders.read", "billing.read"]

[[routes]]
name = "policy"
host = "policy.test"
downstream = "https://policy-lb.test"
append_audience = "policy.test"
audiences = { allow = ["*"], require = ["tsong"], deny = ["admin"] }
allowed_scopes = ["*"]

[[routes]]
name = "closed"
host = "closed.test"
downstream = "https://closed-lb.test"
append_audience = "closed.test"
audiences = { allow = ["tsong"] }
allowed_scopes = []
"#;

/// Every exchange event the issuer reported.
#[derive(Default)]
pub struct Recording(std::sync::Mutex<Vec<ExchangeEvent>>);

impl Recording {
    pub fn events(&self) -> Vec<ExchangeEvent> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The last event, or a test failure when there is none.
    pub fn last(&self) -> TestResult<ExchangeEvent> {
        Ok(self.events().pop().ok_or("no exchange was observed")?)
    }
}

impl ExchangeObserver for Recording {
    fn exchanged(&self, event: &ExchangeEvent) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event.clone());
    }
}

pub struct Harness {
    pub events: Arc<Recording>,
    pub issuer: Arc<Issuer>,
    pub fetcher: Arc<FakeFetcher>,
    pub inbound: TestKey,
}

/// What a test returns: nothing, or why it failed.
pub type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

pub fn harness_with_keys(keys: KeySet) -> TestResult<Harness> {
    harness_with_config(CONFIG, keys)
}

/// The issuer for the config `text`, signing with `keys`.
pub fn harness_with_config(text: &str, keys: KeySet) -> TestResult<Harness> {
    let config = Arc::new(Config::from_toml(text)?);
    let inbound = TestKey::new("in-1", 1)?;
    let fetcher = Arc::new(FakeFetcher::with(vec![inbound.jwk()]));
    let clock = Arc::new(ManualClock::at(NOW));
    let validator = Validator::new(&config, fetcher.clone(), clock.clone());
    let events = Arc::new(Recording::default());
    let issuer =
        Arc::new(Issuer::new(config, keys, validator, clock).with_observer(events.clone()));
    Ok(Harness {
        issuer,
        fetcher,
        inbound,
        events,
    })
}

pub fn harness() -> TestResult<Harness> {
    let key = Arc::new(FileKey::from_pem(
        "tsong-1",
        SigningAlgorithm::ES256,
        &pem(5)?,
    )?);
    harness_with_keys(KeySet::new(vec![key], vec![])?)
}

/// The fields of a JSON object, or a test failure for anything else.
pub fn object(value: Value) -> TestResult<Map<String, Value>> {
    match value {
        Value::Object(fields) => Ok(fields),
        other => Err(format!("expected a JSON object, got {other}").into()),
    }
}

/// The subject token's claims with `changes` applied: a null removes the
/// claim.
pub fn subject(changes: Value) -> TestResult<Value> {
    let mut claims = object(json!({
        "iss": "https://issuer.test",
        "sub": "alice",
        "aud": "tsong",
        "exp": NOW + 3600,
        "scope": "orders.read orders.write",
        "email": "alice@example.test",
        "groups": ["admins"],
        "uid": "a-1",
        "secret": "not copied",
    }))?;
    for (name, value) in object(changes)? {
        if value.is_null() {
            claims.remove(&name);
        } else {
            claims.insert(name, value);
        }
    }
    Ok(Value::Object(claims))
}

/// An exchange of a subject token with `claims` for `audience`.
pub fn request(h: &Harness, audience: &str, claims: TestResult<Value>) -> TestResult<TokenRequest> {
    Ok(TokenRequest {
        grant_type: Some(TOKEN_EXCHANGE.into()),
        subject_token: Some(h.inbound.sign(&claims?)?),
        subject_token_type: Some(ACCESS_TOKEN.into()),
        audience: Some(audience.into()),
        ..TokenRequest::default()
    })
}
