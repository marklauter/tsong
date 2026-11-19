//! TOML parse errors that name where the problem is, without quoting the
//! line, which may hold a secret written in by mistake.

use std::fmt;

/// Why a document didn't parse, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(String);

impl ParseError {
    /// The error `toml` reported for `text`, without its quoted source.
    pub(crate) fn new(text: &str, error: &toml::de::Error) -> Self {
        let message = replaced(error.message()).unwrap_or_else(|| error.message().trim_end());
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

/// Keys an earlier Tsong took and this one refuses, each with what took
/// its place.
const REPLACED: [(&str, &str); 1] = [(
    "allowed_audiences",
    "allowed_audiences is replaced by [routes.audiences]; move its values to allow",
)];

/// What to say instead of `message` when it reports an unknown key that
/// [`REPLACED`] names.
fn replaced(message: &str) -> Option<&'static str> {
    REPLACED
        .iter()
        .find(|(key, _)| message.starts_with(&format!("unknown field `{key}`")))
        .map(|(_, instead)| *instead)
}

/// Parses `text` as `T`, with any error as a [`ParseError`].
pub(crate) fn from_str<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, ParseError> {
    toml::from_str(text).map_err(|error| ParseError::new(text, &error))
}
