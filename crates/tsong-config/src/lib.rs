//! Tsong's configuration: the issuer, the gateway, the trusted inbound
//! issuers, claim mapping and routes.
//!
//! [`Config::from_toml`] parses a document and validates it as a whole, so
//! a config either loads with every reference resolved or fails with every
//! problem listed. Unknown fields are errors: a misspelled security setting
//! must not fall back to its default.

mod bootstrap;
mod duration;
mod lint;
mod network;
mod parse;
mod secret;
mod store;
mod validate;

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;
use url::Url;

use crate::parse::{AllowedAudiences, Removed};

pub use bootstrap::{
    Admin, Bootstrap, BootstrapError, CONFIG_FILE, GitHost, GitSource, Health, Source, Webhook,
};
pub use lint::Warnings;
pub use network::{allowed, client_ip};
pub use parse::ParseError;
pub use secret::{Scheme, SecretRef, SecretRefError};
pub use store::{ConfigStore, Fetched, FileStore, LoadFuture, Snapshot, hex};
pub use validate::{Problems, RESERVED_CLAIMS};

/// A whole Tsong configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub issuer: Issuer,
    pub gateway: Gateway,
    #[serde(default)]
    pub trusted_issuers: BTreeMap<String, TrustedIssuer>,
    #[serde(default)]
    pub claims: Claims,
    #[serde(default)]
    pub routes: Vec<Route>,
}

/// The token exchange issuer Tsong hosts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    /// The `iss` of every token Tsong signs, exactly as written, and the
    /// base of its discovery document. An https URL.
    pub url: String,
    /// Where the issuer serves the token endpoint, JWKS and discovery.
    pub listen: SocketAddr,
    /// The longest lifetime of a token Tsong signs.
    #[serde(with = "duration")]
    pub token_lifetime: Duration,
    /// Allowance for clocks that disagree: added to inbound `exp` and taken
    /// off inbound `nbf`, and taken off every cache lifetime.
    #[serde(with = "duration")]
    pub clock_skew: Duration,
    pub signing: Signing,
}

/// Where the issuer's signing keys come from.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signing {
    pub provider: KeyProvider,
    pub keys: Vec<KeyEntry>,
}

/// A source of signing keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyProvider {
    /// A PKCS#8 PEM private key, read through its secret reference and
    /// signing in process.
    File,
}

/// An algorithm Tsong signs with: the asymmetric JWS algorithms, as
/// inbound validation accepts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
pub enum SigningAlgorithm {
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    #[default]
    ES256,
    ES384,
    EdDSA,
}

impl SigningAlgorithm {
    /// The JWS `alg` name.
    pub fn name(self) -> &'static str {
        match self {
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
            Self::PS256 => "PS256",
            Self::PS384 => "PS384",
            Self::PS512 => "PS512",
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::EdDSA => "EdDSA",
        }
    }
}

impl std::fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// One signing key.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    pub kid: String,
    /// The algorithm the key signs with. Unset, ES256.
    #[serde(default)]
    pub algorithm: SigningAlgorithm,
    pub state: KeyState,
    /// The PKCS#8 PEM private key, for the file provider.
    pub private_key: Option<SecretRef>,
}

/// Whether a key signs, or is only published.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyState {
    /// Signs new tokens. At most one key per algorithm is active.
    Active,
    /// Published in JWKS until the tokens it signed expire; never signs.
    Retiring,
}

/// The reverse proxy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gateway {
    pub listen: SocketAddr,
    /// Proxies whose `X-Forwarded-For` hops are believed.
    #[serde(default)]
    pub trusted_proxies: Vec<IpNet>,
    /// Client ranges allowed through. Empty denies every client;
    /// `["0.0.0.0/0", "::/0"]` allows every client.
    pub allow: Vec<IpNet>,
    /// The longest the gateway waits on a downstream between reads, before
    /// answering 504. A route may set its own.
    #[serde(default = "default_read_timeout", with = "duration")]
    pub read_timeout: Duration,
    pub cache: Cache,
}

fn default_read_timeout() -> Duration {
    Duration::from_secs(60)
}

/// The exchanged-token cache.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cache {
    pub max_entries: u64,
}

/// An issuer whose tokens Tsong accepts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedIssuer {
    /// The `iss` its tokens carry, compared exactly. An https URL.
    pub issuer: String,
    /// Put before its subjects in the tokens Tsong signs, as
    /// `<sub_prefix>:<sub>`, so two issuers' subjects never collide.
    /// Lowercase letters, digits and `-`, unique among trusted issuers.
    /// Changing it changes the identity of every subject from this issuer.
    pub sub_prefix: String,
    /// The `aud` values Tsong accepts from it.
    pub audiences: Vec<String>,
    #[serde(default)]
    pub validation: Validation,
    /// The algorithms its JWTs may be signed with.
    #[serde(default)]
    pub algorithms: Vec<InboundAlgorithm>,
    /// Where its OIDC discovery document is. Unset, it is
    /// `<issuer>/.well-known/openid-configuration`. The document must name
    /// this issuer exactly.
    pub discovery_url: Option<Url>,
    /// Where its JWKS is. Unset, it is the `jwks_uri` of the discovery
    /// document. Set, discovery is skipped, so `discovery_url` may not be
    /// set too.
    pub jwks_url: Option<Url>,
    /// How long fetched keys are trusted. Past this they expire and are
    /// refetched; until a refetch succeeds, the issuer's tokens are refused.
    #[serde(default = "default_jwks_max_age", with = "duration")]
    pub jwks_max_age: Duration,
    /// How often a failed refetch of expired keys is retried.
    #[serde(default = "default_jwks_retry", with = "duration")]
    pub jwks_retry: Duration,
    /// The shortest time between refetches a token triggers: one with an
    /// unknown key ID, or whose signature fails with a known key.
    #[serde(default = "default_jwks_refetch", with = "duration")]
    pub jwks_refetch: Duration,
    /// The longest a discovery or JWKS request may take.
    #[serde(default = "default_jwks_timeout", with = "duration")]
    pub jwks_timeout: Duration,
    pub introspection_url: Option<Url>,
    pub client_id: Option<String>,
    /// The introspection client secret.
    pub client_secret: Option<SecretRef>,
}

fn default_jwks_max_age() -> Duration {
    Duration::from_secs(60 * 60)
}

fn default_jwks_retry() -> Duration {
    Duration::from_secs(10)
}

fn default_jwks_refetch() -> Duration {
    Duration::from_secs(30)
}

fn default_jwks_timeout() -> Duration {
    Duration::from_secs(10)
}

/// How an inbound token is validated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Validation {
    /// Locally, against the issuer's JWKS.
    #[default]
    Jwt,
    /// By asking the issuer (RFC 7662), for opaque tokens.
    Introspection,
}

/// An algorithm an inbound JWT may be signed with. Asymmetric only: `none`
/// and the HMAC algorithms don't parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum InboundAlgorithm {
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    ES256,
    ES384,
    EdDSA,
}

/// Which inbound claims carry over into exchanged tokens.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    /// Claims copied from every issuer.
    #[serde(default)]
    pub copy: Vec<String>,
    /// Per trusted issuer, inbound claim name to outbound claim name.
    #[serde(default)]
    pub rename: BTreeMap<String, BTreeMap<String, String>>,
}

/// A host mapped to a downstream service. The upstream is the caller; the
/// downstream is where the request goes.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub name: String,
    /// The host requests for this route arrive on, without a port.
    /// Compared without regard to case.
    pub host: String,
    /// The https origin requests are forwarded to. The request's path and
    /// query are kept.
    pub downstream: Url,
    /// Added to the `aud` of tokens minted for this route. Empty adds
    /// nothing.
    pub append_audience: String,
    /// Which inbound `aud` values the route accepts, requires and denies.
    pub audiences: AudiencePolicy,
    /// The inbound scopes the route accepts: every scope the inbound token
    /// carries must be one. Empty denies every token; `"*"` accepts any.
    pub allowed_scopes: Vec<String>,
    /// The scopes the inbound token must all carry, which a token minted
    /// for the route always keeps. Each must be one `allowed_scopes`
    /// accepts. Empty or unset requires none.
    #[serde(default)]
    pub required_scopes: Vec<String>,
    /// The algorithm tokens minted for the route are signed with. A key
    /// for it must be active. Unset, ES256.
    #[serde(default)]
    pub signing_algorithm: SigningAlgorithm,
    /// Client ranges allowed to this route, checked after the gateway's
    /// `allow`. Unset, the gateway's list alone applies. Empty denies
    /// every client.
    pub allow: Option<Vec<IpNet>>,
    /// Overrides `gateway.read_timeout` for this route.
    #[serde(default, with = "duration::option")]
    pub read_timeout: Option<Duration>,
    /// Refused, naming `audiences.allow` as its replacement.
    #[serde(default, rename = "allowed_audiences")]
    _allowed_audiences: Option<Removed<AllowedAudiences>>,
}

/// A route's audience policy, checked against the subject token's `aud`
/// values once the token is validated. The token must pass every check; the
/// first that fails refuses it. The minted token's audiences are not
/// affected.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AudiencePolicy {
    /// The audiences the token may carry: at least one of them, and none
    /// outside them. Empty denies every token; `"*"`, alone, allows any
    /// audience, and then only `deny` narrows it.
    pub allow: Vec<String>,
    /// The audiences the token must all carry. Each must be one `allow`
    /// admits. Empty or unset requires none.
    #[serde(default)]
    pub require: Vec<String>,
    /// The audiences the token may not carry. Holds values only when
    /// `allow` is `"*"`; under a named `allow`, leave the audience out of
    /// `allow` instead. Empty or unset denies none.
    #[serde(default)]
    pub deny: Vec<String>,
}

impl AudiencePolicy {
    /// Whether `allow` admits `audience`.
    pub fn allows(&self, audience: &str) -> bool {
        self.allow
            .iter()
            .any(|value| value == ANY || value == audience)
    }
}

/// Why a route refuses a subject token's audiences: the first of its
/// checks that failed, in the order they run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudienceRefusal<'a> {
    /// The token carries no audience.
    NoAudience,
    /// The token carries audiences, but none `allow` admits.
    NotAllowed,
    /// The token carries this audience, which is outside `allow`.
    Outside(&'a str),
    /// The token lacks this audience, which `require` lists.
    Missing(&'a str),
    /// The token carries this audience, which `deny` lists.
    Denied(&'a str),
}

impl Route {
    /// The longest the gateway waits on this route's downstream between
    /// reads.
    pub fn read_timeout(&self, gateway: &Gateway) -> Duration {
        self.read_timeout.unwrap_or(gateway.read_timeout)
    }
}

/// The entry in `audiences.allow` or `allowed_scopes` that accepts any
/// value.
pub const ANY: &str = "*";

impl Route {
    /// Why the route refuses a token with these audiences, or `None` when
    /// it accepts them. The token must carry at least one audience `allow`
    /// admits, none outside it, every one `require` lists and none `deny`
    /// lists.
    pub fn audience_refusal<'a>(&'a self, audiences: &[&'a str]) -> Option<AudienceRefusal<'a>> {
        let policy = &self.audiences;
        if audiences.is_empty() {
            return Some(AudienceRefusal::NoAudience);
        }
        if !audiences.iter().any(|aud| policy.allows(aud)) {
            return Some(AudienceRefusal::NotAllowed);
        }
        if let Some(outside) = audiences.iter().find(|aud| !policy.allows(aud)) {
            return Some(AudienceRefusal::Outside(outside));
        }
        if let Some(missing) = policy
            .require
            .iter()
            .find(|required| !audiences.contains(&required.as_str()))
        {
            return Some(AudienceRefusal::Missing(missing));
        }
        audiences
            .iter()
            .find(|aud| policy.deny.iter().any(|denied| denied == *aud))
            .map(|denied| AudienceRefusal::Denied(denied))
    }

    /// The first of the route's required scopes that `holds` says is
    /// missing.
    pub fn missing_scope(&self, holds: impl Fn(&str) -> bool) -> Option<&str> {
        self.required_scopes
            .iter()
            .map(String::as_str)
            .find(|scope| !holds(scope))
    }

    /// The first of these scopes the route doesn't accept. An empty
    /// `allowed_scopes` accepts nothing, so even a token without scopes is
    /// refused, reported as `None` in `Err`.
    pub fn refused_scope<'a>(
        &self,
        mut scopes: impl Iterator<Item = &'a str>,
    ) -> Result<(), Option<&'a str>> {
        let allowed = &self.allowed_scopes;
        if allowed.is_empty() {
            return Err(None);
        }
        if allowed.iter().any(|value| value == ANY) {
            return Ok(());
        }
        match scopes.find(|scope| !allowed.iter().any(|value| value == scope)) {
            Some(refused) => Err(Some(refused)),
            None => Ok(()),
        }
    }
}

/// The routes keyed by host, for lookup in constant time.
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    routes: HashMap<String, Route>,
}

impl RouteTable {
    /// Indexes `routes` by lowercased host. A validated config has no
    /// repeated host; were one repeated, the first route would win.
    pub fn new(routes: &[Route]) -> Self {
        let mut table = HashMap::with_capacity(routes.len());
        for route in routes {
            table
                .entry(route.host.to_ascii_lowercase())
                .or_insert_with(|| route.clone());
        }
        Self { routes: table }
    }

    /// The route for `host`, compared without regard to case. The host
    /// carries no port.
    pub fn get(&self, host: &str) -> Option<&Route> {
        self.routes.get(&host.to_ascii_lowercase())
    }
}

/// Why a config didn't load.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing: {0}")]
    Parse(#[from] ParseError),
    #[error("invalid config:\n{0}")]
    Invalid(Problems),
    /// The store couldn't produce the config, such as a failed fetch.
    #[error("{0}")]
    Store(String),
}

impl Config {
    /// Parses and validates a TOML document.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config: Self = parse::from_str(text)?;
        config.validate().map_err(ConfigError::Invalid)?;
        Ok(config)
    }

    /// Reads, parses and validates a TOML file. Relative `file` secret
    /// references are taken from the file's directory.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::from_text(&store::read(path)?, Some(&store::directory(path)))
    }

    /// Parses and validates a TOML document, taking relative `file` secret
    /// references from `base_dir`. Without one, as for a config from Git, a
    /// relative path is a problem: it has nothing to be relative to.
    pub fn from_text(text: &str, base_dir: Option<&Path>) -> Result<Self, ConfigError> {
        let mut config = Self::from_toml(text)?;
        let mut problems = Vec::new();
        let keys = config.issuer.signing.keys.iter_mut().filter_map(|key| {
            let field = format!("issuer.signing.keys {:?} private_key", key.kid);
            key.private_key.as_mut().map(|secret| (field, secret))
        });
        let clients = config
            .trusted_issuers
            .iter_mut()
            .filter_map(|(name, trusted)| {
                let field = format!("trusted_issuers.{name}.client_secret");
                trusted.client_secret.as_mut().map(|secret| (field, secret))
            });
        for (field, secret) in keys.chain(clients) {
            match base_dir {
                Some(dir) => {
                    if secret.rebase(dir).is_err() {
                        problems.push(format!(
                            "{field} is relative to a directory whose name isn't UTF-8"
                        ));
                    }
                }
                None if secret.is_relative_file() => problems.push(format!(
                    "{field} must be an absolute path, since the config has no directory"
                )),
                None => {}
            }
        }
        if problems.is_empty() {
            Ok(config)
        } else {
            Err(ConfigError::Invalid(Problems(problems)))
        }
    }

    /// The active signing key for `algorithm`: at most one, in a
    /// validated config.
    pub fn active_key(&self, algorithm: SigningAlgorithm) -> Option<&KeyEntry> {
        self.issuer
            .signing
            .keys
            .iter()
            .find(|key| key.state == KeyState::Active && key.algorithm == algorithm)
    }
}
