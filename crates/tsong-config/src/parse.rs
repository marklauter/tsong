//! TOML parse errors that name where the problem is, without quoting the
//! line, which may hold a secret written in by mistake.

use std::fmt;

use serde::Deserializer;
use serde::de::{Error as _, IgnoredAny};

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

/// Refuses a route's `allowed_audiences`, at its value's line and column,
/// naming what took its place.
pub(crate) fn refuse_allowed_audiences<'de, D: Deserializer<'de>>(
    _: D,
) -> Result<Option<IgnoredAny>, D::Error> {
    Err(D::Error::custom(
        "allowed_audiences is replaced by [routes.audiences]; move its values to audiences.allow, which also refuses a token carrying any audience outside it",
    ))
}

/// Parses `text` as `T`, with any error as a [`ParseError`].
pub(crate) fn from_str<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, ParseError> {
    toml::from_str(text).map_err(|error| ParseError::new(text, &error))
}
