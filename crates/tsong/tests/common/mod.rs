//! Configs, signing keys and stores for the reload tests.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use tsong::reload::Audit;
use tsong_config::{ConfigError, ConfigStore, Fetched, LoadFuture, Snapshot};
use tsong_validate::testkit::pem;

pub type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

pub const NOW: u64 = 1_000_000;

/// Writes a signing key to `dir` and returns its path.
pub fn write_key(dir: &Path) -> TestResult<PathBuf> {
    let path = dir.join("k1.pem");
    std::fs::write(&path, pem(7)?)?;
    Ok(path)
}

/// A port nothing listens on, at the moment it is chosen.
pub fn free_port() -> TestResult<u16> {
    let free = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(free.local_addr()?.port())
}

/// A route on `host` allowing `scopes`.
pub fn route(name: &str, host: &str, scopes: &str) -> String {
    format!(
        r#"
[[routes]]
name = "{name}"
host = "{host}"
downstream = "https://{name}-lb.example.com"
append_audience = ""
allowed_audiences = ["*"]
allowed_scopes = [{scopes}]
"#
    )
}

/// A config issuing as `issuer` on `port`, signing with the key at `key`,
/// with `routes`.
pub fn config_text(key: &Path, issuer: &str, port: u16, routes: &str) -> String {
    config_on(key, issuer, port, 0, routes)
}

/// `config_text` with the gateway on `gateway_port`.
pub fn config_on(key: &Path, issuer: &str, port: u16, gateway_port: u16, routes: &str) -> String {
    format!(
        r#"
[issuer]
url = "{issuer}"
listen = "127.0.0.1:{port}"
token_lifetime = "00:15:00"
clock_skew = "00:00:30"

[issuer.signing]
provider = "file"

[[issuer.signing.keys]]
kid = "k1"
private_key = {{ file = '{}' }}
state = "active"

[gateway]
listen = "127.0.0.1:{gateway_port}"
allow = ["127.0.0.0/8"]

[gateway.cache]
max_entries = 10
{routes}"#,
        key.display()
    )
}

/// A copy of the status `reloader` reports.
pub fn status(reloader: &tsong::reload::Reloader) -> tsong::reload::Status {
    reloader
        .status()
        .lock()
        .map(|status| status.clone())
        .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
}

/// `text` as a store fetches it at `revision`, with content of its own.
pub fn fetched(text: &str, revision: &str) -> TestResult<Fetched> {
    Ok(Fetched {
        text: text.into(),
        revision: revision.into(),
        content: format!("content of {revision}"),
        author: Some("Ada <ada@example.test>".into()),
        base_dir: None,
    })
}

/// `text` parsed and validated at `revision`.
pub fn snapshot(text: &str, revision: &str) -> TestResult<Snapshot> {
    Ok(fetched(text, revision)?.parse()?)
}

/// A store that answers each load with the next queued result, and with a
/// store error once the queue is empty.
#[derive(Default)]
pub struct QueueStore {
    queue: Mutex<VecDeque<Result<Fetched, ConfigError>>>,
}

impl QueueStore {
    pub fn push(&self, result: Result<Fetched, ConfigError>) {
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(result);
    }
}

/// A `QueueStore` the test keeps a handle on while the reloader owns it.
pub struct Shared(pub Arc<QueueStore>);

impl ConfigStore for Shared {
    fn load(&self) -> LoadFuture<'_> {
        let next = self
            .0
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
            .unwrap_or_else(|| Err(ConfigError::Store("nothing queued".into())));
        Box::pin(async move { next })
    }
}

/// Audit lines, kept for inspection.
#[derive(Default)]
pub struct Recorded(Mutex<Vec<String>>);

impl Recorded {
    /// The lines recorded so far, parsed as JSON.
    pub fn parsed(&self) -> TestResult<Vec<serde_json::Value>> {
        let lines = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        Ok(lines
            .iter()
            .map(|line| serde_json::from_str(line))
            .collect::<Result<_, _>>()?)
    }
}

impl Audit for Recorded {
    fn record(&self, line: &str) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line.to_owned());
    }
}
