//! Where a config comes from, behind one trait. Tsong has one store, a file.
//! A store only fetches the config's text; parsing and validating it is
//! the caller's, through [`Fetched::parse`].

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use sha2::{Digest, Sha256};

use crate::{Config, ConfigError};

/// A config's text, and where it was read.
#[derive(Debug, Clone)]
pub struct Fetched {
    pub text: String,
    /// What identifies the version read: a version the store assigns, or a
    /// hash of the text.
    pub revision: String,
    /// What identifies the config's text: a hash of the text. Equal contents
    /// hold equal configs, even at different revisions.
    pub content: String,
    /// Who made this revision, when the store knows.
    pub author: Option<String>,
    /// The directory relative key paths are taken from. A config from a
    /// store with no directory gives its key paths in full.
    pub base_dir: Option<PathBuf>,
}

/// A validated config and the revision it was read at.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub config: Config,
    pub revision: String,
    pub content: String,
    pub author: Option<String>,
}

impl Fetched {
    /// Parses and validates the text.
    pub fn parse(self) -> Result<Snapshot, ConfigError> {
        Ok(Snapshot {
            config: Config::from_text(&self.text, self.base_dir.as_deref())?,
            revision: self.revision,
            content: self.content,
            author: self.author,
        })
    }
}

/// What [`ConfigStore::load`] returns.
pub type LoadFuture<'a> = Pin<Box<dyn Future<Output = Result<Fetched, ConfigError>> + Send + 'a>>;

/// A source of config text.
pub trait ConfigStore: Send + Sync {
    /// Fetches the current config's text. The only errors are fetching
    /// errors: [`ConfigError::Read`] or [`ConfigError::Store`].
    fn load(&self) -> LoadFuture<'_>;
}

/// A TOML file on disk.
#[derive(Debug, Clone)]
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl ConfigStore for FileStore {
    fn load(&self) -> LoadFuture<'_> {
        let result = read(&self.path).map(|text| {
            let hash = hex(&Sha256::digest(text.as_bytes()));
            Fetched {
                text,
                revision: hash.clone(),
                content: hash,
                author: None,
                base_dir: Some(directory(&self.path)),
            }
        });
        Box::pin(async move { result })
    }
}

/// The text of the file at `path`.
pub(crate) fn read(path: &Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_owned(),
        source,
    })
}

/// The directory holding the file at `path`.
pub(crate) fn directory(path: &Path) -> PathBuf {
    path.parent().unwrap_or(Path::new("")).to_owned()
}

/// Bytes as lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}
