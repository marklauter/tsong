//! Warnings: settings that are valid but look like a mistake. An empty
//! allow list denies everything, which looks like an omission; an entry
//! that accepts anything looks like a decision worth confirming. A route
//! whose audience policy admits no audience a trusted issuer accepts
//! refuses every token.
//! Keys trusted for more than a day leave a key an issuer has withdrawn in
//! use for that long.

use std::fmt;
use std::time::Duration;

use ipnet::IpNet;

use crate::{ANY, Config, Validation};

/// The longest `jwks_max_age` that doesn't warn.
const LONGEST_JWKS_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Every warning a config has, one per line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Warnings(pub Vec<String>);

impl fmt::Display for Warnings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for warning in &self.0 {
            writeln!(f, "warning: {warning}")?;
        }
        Ok(())
    }
}

impl Config {
    /// The config's warnings, in config order.
    pub fn warnings(&self) -> Warnings {
        let mut warnings = Vec::new();
        ip_list(&mut warnings, "gateway.allow", &self.gateway.allow);
        for (name, trusted) in &self.trusted_issuers {
            if trusted.validation == Validation::Jwt && trusted.jwks_max_age > LONGEST_JWKS_MAX_AGE
            {
                warnings.push(format!(
                    "trusted_issuers.{name}.jwks_max_age is over a day, 1.00:00:00; a key the issuer withdraws stays trusted that long"
                ));
            }
        }
        // Introspected tokens are refused as unsupported, so only issuers
        // that validate JWTs can serve a route.
        let jwt = || {
            self.trusted_issuers
                .values()
                .filter(|trusted| trusted.validation == Validation::Jwt)
        };
        let jwt_issuers = jwt().next().is_some();
        let jwt_audiences = jwt().flat_map(|trusted| &trusted.audiences);
        for route in &self.routes {
            let name = &route.name;
            let policy = &route.audiences;
            // A "*" that `require` or `deny` narrows is a decision already.
            let narrowed = !policy.require.is_empty() || !policy.deny.is_empty();
            for (field, values, star_warns, accepted) in [
                (
                    "audiences.allow",
                    &policy.allow,
                    !narrowed,
                    "any audience is accepted",
                ),
                (
                    "allowed_scopes",
                    &route.allowed_scopes,
                    true,
                    "any value is accepted",
                ),
            ] {
                if values.is_empty() {
                    warnings.push(format!(
                        "route {name:?}: {field} is empty; every request will be denied"
                    ));
                } else if star_warns && values.iter().any(|value| value == ANY) {
                    warnings.push(format!("route {name:?}: {field} has \"*\"; {accepted}"));
                }
            }
            if !policy.allow.is_empty()
                && jwt_issuers
                && !jwt_audiences
                    .clone()
                    .any(|aud| policy.allows(aud) && !policy.deny.contains(aud))
            {
                warnings.push(format!(
                    "route {name:?}: audiences admits no audience a trusted issuer accepts; every token will be refused"
                ));
            }
            if let Some(allow) = &route.allow {
                ip_list(&mut warnings, &format!("route {name:?}: allow"), allow);
            }
        }
        Warnings(warnings)
    }
}

/// Warns on an IP allow list that denies every client or allows every
/// address of a family.
fn ip_list(warnings: &mut Vec<String>, field: &str, list: &[IpNet]) {
    if list.is_empty() {
        warnings.push(format!("{field} is empty; every client will be denied"));
    }
    for net in list.iter().filter(|net| net.prefix_len() == 0) {
        warnings.push(format!("{field} has {net}; every address is allowed"));
    }
}
