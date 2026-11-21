//! The bootstrap file: where the config comes from, and the admin and health
//! listeners.
//! It is deployed with Tsong, because the settings that say where the
//! config lives can't live in that config.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;

use crate::{ParseError, Problems, duration};

/// A whole bootstrap file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub source: Source,
    /// The admin listener, which serves the status endpoint. Unset, there
    /// is none.
    pub admin: Option<Admin>,
    /// The liveness and readiness checks, on their own listener. Unset,
    /// there is none.
    pub health: Option<Health>,
}

/// The health-check listener, for the load balancer in front of Tsong.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    pub listen: SocketAddr,
    /// The addresses health checks come from. Each connection's peer
    /// address must be in it; no `X-Forwarded-For` is read.
    pub allow: Vec<IpNet>,
    /// How long, on shutdown, readiness reports not ready before the
    /// listeners close, so the load balancer stops sending requests first.
    #[serde(default = "default_drain", with = "duration")]
    pub drain: Duration,
}

fn default_drain() -> Duration {
    Duration::from_secs(5)
}

/// Where the config comes from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "store", rename_all = "lowercase", deny_unknown_fields)]
pub enum Source {
    /// A TOML file on disk, relative to the bootstrap file. It is read once.
    File { path: PathBuf },
}

/// The admin listener. It admits the clients in the served config's
/// `gateway.allow`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admin {
    pub listen: SocketAddr,
}

/// Why a bootstrap file didn't load.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing the bootstrap file: {0}")]
    Parse(#[from] ParseError),
    #[error("invalid bootstrap file:\n{0}")]
    Invalid(Problems),
}

impl Bootstrap {
    /// Parses and validates a bootstrap document.
    pub fn from_toml(text: &str) -> Result<Self, BootstrapError> {
        let bootstrap: Self = crate::parse::from_str(text)?;
        bootstrap.validate().map_err(BootstrapError::Invalid)?;
        Ok(bootstrap)
    }

    /// Reads a bootstrap file. A relative source path is taken from the
    /// bootstrap file's directory.
    pub fn load(path: &Path) -> Result<Self, BootstrapError> {
        let text = std::fs::read_to_string(path).map_err(|source| BootstrapError::Read {
            path: path.to_owned(),
            source,
        })?;
        let mut bootstrap = Self::from_toml(&text)?;
        let dir = path.parent().unwrap_or(Path::new(""));
        let Source::File { path: file } = &mut bootstrap.source;
        *file = dir.join(&*file);
        Ok(bootstrap)
    }

    fn validate(&self) -> Result<(), Problems> {
        let mut problems = Vec::new();
        if self
            .health
            .as_ref()
            .is_some_and(|health| health.allow.is_empty())
        {
            problems.push("health.allow is empty, so no health check can arrive".into());
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(Problems(problems))
        }
    }
}
