//! Reloading: load the config from its store, build its state, and swap it
//! in, or keep the old state and say why. Every attempt that finds a new
//! revision, or fails, is audited and counted.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use serde::Serialize;
use serde_json::json;
use tokio::sync::watch;
use tsong_clock::Clock;
use tsong_config::{Config, ConfigStore, Route};
use tsong_secrets::Secrets;
use tsong_validate::{HttpFetcher, JwksFetcher};

/// A new revision was swapped in.
pub const APPLIED: &str = "applied";
/// The store couldn't produce the config, such as a failed fetch.
pub const FETCH_FAILED: &str = "fetch_failed";
/// The config didn't parse or validate.
pub const INVALID_CONFIG: &str = "invalid_config";
/// The config was valid, but its state didn't build, such as a missing key
/// file.
pub const BUILD_FAILED: &str = "build_failed";

use crate::state::{State, listen_addresses};
use crate::telemetry::{Metrics, OutcomeLabel, RevisionLabel};

/// Where audit lines go: stdout in production, collected by the platform.
pub trait Audit: Send + Sync {
    fn record(&self, line: &str);
}

/// Writes each audit line, and a newline, to a writer: stdout in
/// production. A line that can't be written is dropped; auditing never
/// stops a reload.
pub struct Lines<W>(Mutex<W>);

impl<W> Lines<W> {
    pub fn new(writer: W) -> Self {
        Self(Mutex::new(writer))
    }

    /// The writer, with everything written to it.
    pub fn into_inner(self) -> W {
        self.0.into_inner().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<W: Write + Send> Audit for Lines<W> {
    fn record(&self, line: &str) {
        let mut writer = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = writeln!(writer, "{line}").and_then(|()| writer.flush());
    }
}

/// What `GET /status` reports.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Status {
    /// The revision being served: the newest revision read whose config is
    /// the one in use.
    pub revision: String,
    /// When it was loaded, in Unix seconds.
    pub loaded_at: u64,
    /// When the store was last read successfully, in Unix seconds, whether
    /// or not it had a new revision. The config is read only at start, so
    /// this stays fixed after start until roadmap item 32 adds a poll.
    pub fetched_at: u64,
    /// Reloads that swapped in a new revision, the first load included.
    pub reloads: u64,
    /// Reloads that kept the old state. It stays 0 until roadmap item 32
    /// adds a poll.
    pub failed_reloads: u64,
    /// Why the last failed reload failed, in short: `fetch_failed`,
    /// `invalid_config` or `build_failed`. The audit log has the detail.
    /// It stays unset until roadmap item 32 adds a poll.
    pub last_failure: Option<String>,
    /// Whether the newest config read was rejected as invalid or failed to
    /// build, so an older one is still served. It stays false until
    /// roadmap item 32 adds a poll.
    pub tip_rejected: bool,
}

/// What a reload did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A new revision is being served.
    Applied,
    /// The store's revision is the one being served.
    Unchanged,
    /// The old state is still served, for this reason.
    Rejected(String),
}

/// Reloads the config from one store into one watch channel.
pub struct Reloader {
    store: Box<dyn ConfigStore>,
    state: watch::Sender<Arc<State>>,
    status: Arc<Mutex<Status>>,
    audit: Arc<dyn Audit>,
    clock: Arc<dyn Clock>,
    metrics: Arc<Metrics>,
    /// Fetches trusted issuers' keys for every state it builds.
    fetcher: Arc<dyn JwksFetcher>,
    /// Reads the secrets of every state it builds.
    secrets: Secrets,
    /// The content of the last config rejected as invalid. It can't become
    /// valid until it changes, so it is not rejected again.
    invalid: Mutex<Option<String>>,
    /// The revision last reported in `tsong_config_revision_info`.
    published: Mutex<Option<String>>,
}

impl Reloader {
    /// A reloader serving `first`, already built from `store`'s config.
    pub fn new(
        store: Box<dyn ConfigStore>,
        first: State,
        audit: Arc<dyn Audit>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let now = clock.unix_seconds();
        let status = Status {
            revision: first.revision.clone(),
            loaded_at: now,
            fetched_at: now,
            reloads: 1,
            ..Status::default()
        };
        audit.record(&applied(None, &first, &status));
        let (state, _) = watch::channel(Arc::new(first));
        Self {
            store,
            state,
            status: Arc::new(Mutex::new(status)),
            metrics: Arc::default(),
            fetcher: Arc::new(HttpFetcher::default()),
            secrets: Secrets::default(),
            invalid: Mutex::new(None),
            published: Mutex::new(None),
            audit,
            clock,
        }
    }

    /// This reloader, building each state with `metrics`, counting its
    /// reloads there, and reporting its status there.
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = metrics;
        self.publish();
        self
    }

    /// This reloader, fetching keys for each state it builds with `fetcher`
    /// instead of plain HTTP.
    pub fn with_fetcher(mut self, fetcher: Arc<dyn JwksFetcher>) -> Self {
        self.fetcher = fetcher;
        self
    }

    /// This reloader, reading each state's secrets through `secrets`
    /// instead of the default sources.
    pub fn with_secrets(mut self, secrets: Secrets) -> Self {
        self.secrets = secrets;
        self
    }

    /// A receiver of the current state and each state swapped in after it.
    pub fn subscribe(&self) -> watch::Receiver<Arc<State>> {
        self.state.subscribe()
    }

    /// The status the admin listener reports.
    pub fn status(&self) -> Arc<Mutex<Status>> {
        self.status.clone()
    }

    /// Fetches the store's config and, when its content is new and it
    /// parses, validates and builds, swaps it in. The metrics then report
    /// the status it leaves.
    pub async fn reload(&self) -> Outcome {
        let outcome = self.load().await;
        self.publish();
        outcome
    }

    async fn load(&self) -> Outcome {
        let current = self.state.borrow().clone();
        let fetched = match self.store.load().await {
            Ok(fetched) => fetched,
            Err(error) => return self.reject(&current, None, FETCH_FAILED, error.to_string()),
        };
        self.lock().fetched_at = self.clock.unix_seconds();
        let content = fetched.content.clone();
        if content == current.content {
            // A revision that leaves the config alone is still the one served,
            // and a rejected config that comes back is judged again.
            *self.rejected() = None;
            let mut status = self.lock();
            status.revision = fetched.revision;
            status.tip_rejected = false;
            return Outcome::Unchanged;
        }
        if self.rejected().as_ref() == Some(&content) {
            return Outcome::Unchanged;
        }
        let revision = fetched.revision.clone();
        let snapshot = match fetched.parse() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                *self.rejected() = Some(content);
                return self.reject(&current, Some(&revision), INVALID_CONFIG, error.to_string());
            }
        };
        let built = State::build_with(
            snapshot,
            self.clock.clone(),
            &self.metrics,
            self.audit.clone(),
            self.fetcher.clone(),
            &self.secrets,
        )
        .await;
        let next = match built {
            Ok(next) => next,
            Err(error) => {
                return self.reject(&current, Some(&revision), BUILD_FAILED, error.to_string());
            }
        };
        *self.rejected() = None;
        let line = {
            let mut status = self.lock();
            status.revision = next.revision.clone();
            status.loaded_at = self.clock.unix_seconds();
            status.reloads += 1;
            status.tip_rejected = false;
            self.count(APPLIED);
            applied(Some(&current.config), &next, &status)
        };
        self.audit.record(&line);
        self.state.send_replace(Arc::new(next));
        Outcome::Applied
    }

    fn reject(
        &self,
        current: &State,
        revision: Option<&str>,
        reason: &str,
        error: String,
    ) -> Outcome {
        {
            let mut status = self.lock();
            status.failed_reloads += 1;
            self.count(reason);
            status.last_failure = Some(reason.to_owned());
            if reason != FETCH_FAILED {
                status.tip_rejected = true;
            }
        }
        let line = json!({
            "event": "config_reload",
            "at": self.clock.unix_seconds(),
            "outcome": "rejected",
            "reason": reason,
            "revision": revision,
            "serving": current.revision,
            "error": error,
        });
        self.audit.record(&line.to_string());
        Outcome::Rejected(error)
    }

    /// Reports the status in the metrics: when the store was last read,
    /// whether its newest config was rejected, and the revision served. A
    /// new revision's series is set before the old one goes, so a scrape
    /// always sees one.
    fn publish(&self) {
        let status = self.lock().clone();
        let metrics = &self.metrics;
        metrics
            .config_fetched
            .set(i64::try_from(status.fetched_at).unwrap_or(i64::MAX));
        metrics
            .config_tip_rejected
            .set(i64::from(status.tip_rejected));
        let mut published = self
            .published
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if published.as_ref() == Some(&status.revision) {
            return;
        }
        metrics
            .config_revision
            .get_or_create(&RevisionLabel {
                revision: status.revision.clone(),
            })
            .set(1);
        if let Some(old) = published.replace(status.revision) {
            metrics
                .config_revision
                .remove(&RevisionLabel { revision: old });
        }
    }

    fn rejected(&self) -> std::sync::MutexGuard<'_, Option<String>> {
        self.invalid.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn count(&self, outcome: &str) {
        self.metrics
            .reloads
            .get_or_create(&OutcomeLabel {
                outcome: outcome.to_owned(),
            })
            .inc();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Status> {
        self.status.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The audit line for `next` replacing `previous`, or for the first load.
fn applied(previous: Option<&Config>, next: &State, status: &Status) -> String {
    let old = previous.map(routes_by_host).unwrap_or_default();
    let new = routes_by_host(&next.config);
    let added: Vec<&str> = new
        .keys()
        .filter(|host| !old.contains_key(*host))
        .map(String::as_str)
        .collect();
    let removed: Vec<&str> = old
        .keys()
        .filter(|host| !new.contains_key(*host))
        .map(String::as_str)
        .collect();
    let changed: Vec<&str> = old
        .iter()
        .filter(|(host, route)| new.get(*host).is_some_and(|next| next != *route))
        .map(|(host, _)| host.as_str())
        .collect();
    let restart: Vec<&str> = previous
        .map(|previous| {
            listen_addresses(previous)
                .into_iter()
                .zip(listen_addresses(&next.config))
                .filter(|(old, new)| old != new)
                .map(|((field, _), _)| field)
                .collect()
        })
        .unwrap_or_default();
    json!({
        "event": "config_reload",
        "at": status.loaded_at,
        "outcome": "applied",
        "revision": next.revision,
        "author": next.author,
        "routes_added": added,
        "routes_removed": removed,
        "routes_changed": changed,
        "restart_required": restart,
    })
    .to_string()
}

/// A config's routes keyed by lowercased host, the first route winning a
/// repeated host, as in `RouteTable`.
fn routes_by_host(config: &Config) -> BTreeMap<String, &Route> {
    let mut routes = BTreeMap::new();
    for route in &config.routes {
        routes
            .entry(route.host.to_ascii_lowercase())
            .or_insert(route);
    }
    routes
}
