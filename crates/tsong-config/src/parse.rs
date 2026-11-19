//! TOML parse errors that name where the problem is, without quoting the
//! line, which may hold a secret written in by mistake.

use std::fmt;
use std::marker::PhantomData;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

/// Why a document didn't parse, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(String);

impl ParseError {
    /// The error `toml` reported for `text`, without its quoted source.
    pub(crate) fn new(text: &str, error: &toml::de::Error) -> Self {
        let message = error.message().trim_end();
        let Some(before) = error.span().and_then(|span| text.get(..span.start)) else {
            return Self(message.to_owned());
        };
        let line = before.matches('\n').count() + 1;
        let column = before
            .rsplit('\n')
            .next()
            .map_or(0, |start| start.chars().count())
            + 1;
        Self(format!("line {line}, column {column}: {message}"))
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

/// A key an earlier Tsong took and this one refuses, saying what took its
/// place. A table that held the key keeps a field for it, typed
/// `Option<Removed<K>>`: any value fails to parse with `K::INSTEAD`, at
/// the value's line and column. To retire another key, add a marker type
/// and its [`Replaced`] impl.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Removed<K>(PhantomData<K>);

/// What took the place of a removed key.
pub(crate) trait Replaced {
    /// The message a config that still sets the key fails with.
    const INSTEAD: &'static str;
}

impl<'de, K: Replaced> Deserialize<'de> for Removed<K> {
    fn deserialize<D: Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        Err(D::Error::custom(K::INSTEAD))
    }
}

/// A route's `allowed_audiences`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum AllowedAudiences {}

impl Replaced for AllowedAudiences {
    const INSTEAD: &'static str =
        "allowed_audiences is replaced by [routes.audiences]; move its values to audiences.allow";
}

/// Parses `text` as `T`, with any error as a [`ParseError`].
pub(crate) fn from_str<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, ParseError> {
    toml::from_str(text).map_err(|error| ParseError::new(text, &error))
}
