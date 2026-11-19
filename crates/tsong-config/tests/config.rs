use std::error::Error;
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tsong_config::{
    ANY, AudienceRefusal, Config, ConfigError, ConfigStore, FileStore, InboundAlgorithm,
    KeyProvider, KeyState, Route, RouteTable, Scheme, SecretRef, SecretRefError, SigningAlgorithm,
    TrustedIssuer, Validation, Warnings, hex,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SAMPLE: &str = include_str!("../../../examples/tsong.toml");

const ISSUER: &str = r#"
[issuer]
url = "https://tsong.example.com"
listen = "127.0.0.1:8444"
token_lifetime = "00:15:00"
clock_skew = "00:00:30"

[issuer.signing]
provider = "file"
"#;

const ACTIVE_KEY: &str = r#"
[[issuer.signing.keys]]
kid = "k1"
private_key = { file = "k1.pem" }
state = "active"
"#;

const GATEWAY: &str = r#"
[gateway]
listen = "127.0.0.1:8443"
allow = ["10.0.0.0/8"]

[gateway.cache]
max_entries = 10
"#;

const OKTA: &str = r#"
[trusted_issuers.okta]
sub_prefix = "okta"
issuer = "https://okta.example.com"
audiences = ["api"]
algorithms = ["RS256"]
"#;

fn minimal() -> String {
    format!("{ISSUER}{ACTIVE_KEY}{GATEWAY}")
}

/// The problems validation finds in `text`, or a test failure when it
/// loads or fails some other way.
fn problems(text: &str) -> TestResult<Vec<String>> {
    match Config::from_toml(text) {
        Err(ConfigError::Invalid(problems)) => Ok(problems.0),
        other => Err(format!("expected an invalid config, got {other:?}").into()),
    }
}

/// The parse error for `text`, or a test failure when it parses.
fn parse_error(text: &str) -> TestResult<String> {
    match Config::from_toml(text) {
        Err(ConfigError::Parse(error)) => Ok(error.to_string()),
        other => Err(format!("expected a parse error, got {other:?}").into()),
    }
}

fn trusted<'a>(config: &'a Config, name: &str) -> TestResult<&'a TrustedIssuer> {
    Ok(config
        .trusted_issuers
        .get(name)
        .ok_or(format!("no trusted issuer {name}"))?)
}

fn route(config: &Config, index: usize) -> TestResult<&Route> {
    Ok(config
        .routes
        .get(index)
        .ok_or(format!("no route {index}"))?)
}

#[test]
fn sample_loads() -> TestResult {
    let config = Config::from_toml(SAMPLE)?;
    assert_eq!(config.issuer.token_lifetime, Duration::from_secs(15 * 60));
    assert_eq!(config.issuer.clock_skew, Duration::from_secs(30));
    assert_eq!(config.issuer.signing.provider, KeyProvider::File);
    assert_eq!(
        config
            .active_key(SigningAlgorithm::ES256)
            .map(|key| key.kid.as_str()),
        Some("2026-11")
    );
    let states: Vec<_> = config.issuer.signing.keys.iter().map(|k| k.state).collect();
    assert_eq!(
        states,
        [KeyState::Active, KeyState::Active, KeyState::Retiring]
    );
    assert_eq!(
        config
            .active_key(SigningAlgorithm::RS256)
            .map(|key| key.kid.as_str()),
        Some("2026-11-rsa")
    );
    assert_eq!(config.gateway.cache.max_entries, 100_000);
    assert_eq!(config.gateway.trusted_proxies.len(), 1);
    assert_eq!(config.trusted_issuers.len(), 3);
    let okta = trusted(&config, "okta")?;
    assert_eq!(okta.validation, Validation::Jwt);
    assert_eq!(okta.algorithms, [InboundAlgorithm::RS256]);
    assert_eq!(okta.jwks_refetch, Duration::from_secs(30));
    assert!(okta.jwks_url.is_none());
    assert_eq!(
        trusted(&config, "gitlab")?.validation,
        Validation::Introspection
    );
    assert_eq!(
        config
            .claims
            .rename
            .get("entra")
            .and_then(|renames| renames.get("oid"))
            .map(String::as_str),
        Some("sub")
    );
    assert_eq!(config.routes.len(), 2);
    let orders = route(&config, 0)?;
    assert_eq!(orders.host, "orders.example.com");
    assert_eq!(orders.append_audience, "orders.example.com");
    assert_eq!(orders.audiences.allow, ["api://default", "api://tsong"]);
    assert_eq!(orders.allowed_scopes, ["orders.read", "orders.write"]);
    assert!(orders.allow.is_none());
    assert_eq!(route(&config, 1)?.allow.as_ref().map(Vec::len), Some(1));
    assert_eq!(config.warnings(), Warnings::default());
    Ok(())
}

#[test]
fn minimal_loads() -> TestResult {
    let config = Config::from_toml(&minimal())?;
    assert!(config.trusted_issuers.is_empty());
    assert!(config.routes.is_empty());
    assert_eq!(config.gateway.allow.len(), 1);
    Ok(())
}

#[test]
fn load_reads_a_file() -> TestResult {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/tsong.toml");
    assert_eq!(Config::load(&path)?.routes.len(), 2);
    Ok(())
}

#[test]
fn load_takes_relative_key_paths_from_the_config_directory() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("tsong.toml");
    std::fs::write(&path, minimal())?;
    let config = Config::load(&path)?;
    assert_eq!(
        private_key(&config),
        Some(file_ref(&dir.path().join("k1.pem"))?)
    );
    Ok(())
}

/// The active ES256 key's private_key reference, as written.
fn private_key(config: &Config) -> Option<String> {
    config
        .active_key(SigningAlgorithm::ES256)
        .and_then(|key| key.private_key.as_ref())
        .map(ToString::to_string)
}

/// The error for a secret field that holds anything but a reference.
const NOT_A_REFERENCE: &str = r#"a secret must be a reference, such as { env = "NAME" } or { file = "path" }, never the secret"#;

/// A `file` reference to `path`, as a config writes it.
fn file_ref(path: &Path) -> TestResult<String> {
    Ok(SecretRef::new(Scheme::File, path.display().to_string())?.to_string())
}

#[test]
fn a_reference_displays_as_toml_that_reads_back() -> TestResult {
    for id in [
        "NAME",
        r"C:\keys\k1.pem",
        r#"a "b" c"#,
        "tab\there",
        "e\u{301}",
        "esc\u{1b}",
    ] {
        let reference = SecretRef::new(Scheme::File, id)?;
        let text = format!("x = {reference}");
        let table: toml::Table = toml::from_str(&text)?;
        let read = table
            .get("x")
            .and_then(|x| x.get("file"))
            .and_then(toml::Value::as_str);
        assert_eq!(read, Some(id), "{text}");
    }
    assert_eq!(
        SecretRef::new(Scheme::Env, "A")?.to_string(),
        r#"{ env = "A" }"#
    );
    Ok(())
}

#[test]
fn load_reports_a_missing_file() {
    let result = Config::load(Path::new("no-such-file.toml"));
    assert!(matches!(result, Err(ConfigError::Read { .. })));
    assert!(
        result.is_err_and(|error| error.to_string().starts_with("reading no-such-file.toml: "))
    );
}

#[test]
fn unknown_fields_are_rejected() -> TestResult {
    let text = minimal().replace("clock_skew", "clock_skw");
    assert!(parse_error(&text)?.contains("unknown field `clock_skw`"));
    Ok(())
}

#[test]
fn durations_must_parse() -> TestResult {
    let text = minimal().replace("\"00:00:30\"", "\"soon\"");
    parse_error(&text)?;
    Ok(())
}

#[test]
fn none_and_hmac_are_not_inbound_algorithms() -> TestResult {
    for algorithm in ["none", "HS256"] {
        let text = format!("{}{}", minimal(), OKTA.replace("RS256", algorithm));
        parse_error(&text)?;
    }
    Ok(())
}

#[test]
fn issuer_url_must_be_https() -> TestResult {
    let text = minimal().replace("https://tsong", "http://tsong");
    assert_eq!(problems(&text)?, ["issuer.url must be https"]);
    Ok(())
}

#[test]
fn clock_skew_must_be_shorter_than_token_lifetime() -> TestResult {
    let text = minimal().replace("\"00:00:30\"", "\"00:15:00\"");
    assert_eq!(
        problems(&text)?,
        ["issuer.clock_skew must be shorter than issuer.token_lifetime"]
    );
    Ok(())
}

#[test]
fn one_key_per_algorithm_is_active() -> TestResult {
    let none = format!(
        "{ISSUER}{}{GATEWAY}",
        ACTIVE_KEY.replace("active", "retiring")
    );
    assert_eq!(problems(&none)?, ["issuer.signing.keys has no active key"]);
    let routed = format!(
        "{ISSUER}{}{GATEWAY}{OKTA}{ROUTE}",
        ACTIVE_KEY.replace("active", "retiring")
    );
    assert_eq!(
        problems(&routed)?,
        ["issuer.signing.keys has no active key"],
        "the routes add nothing to the missing key"
    );
    let two = format!(
        "{ISSUER}{ACTIVE_KEY}{}{GATEWAY}",
        ACTIVE_KEY.replace("k1", "k2")
    );
    assert_eq!(
        problems(&two)?,
        ["issuer.signing.keys has more than one active ES256 key"]
    );
    let three = format!(
        "{ISSUER}{ACTIVE_KEY}{}{}{GATEWAY}",
        ACTIVE_KEY.replace("k1", "k2"),
        ACTIVE_KEY.replace("k1", "k3")
    );
    assert_eq!(
        problems(&three)?,
        ["issuer.signing.keys has more than one active ES256 key"],
        "reported once per algorithm"
    );
    let rsa = ACTIVE_KEY
        .replace("k1", "k2")
        .replace("state", "algorithm = \"RS256\"\nstate");
    let config = Config::from_toml(&format!("{ISSUER}{ACTIVE_KEY}{rsa}{GATEWAY}"))?;
    let algorithms: Vec<_> = config
        .issuer
        .signing
        .keys
        .iter()
        .map(|key| key.algorithm)
        .collect();
    assert_eq!(
        algorithms,
        [SigningAlgorithm::ES256, SigningAlgorithm::RS256],
        "a key without an algorithm signs ES256"
    );
    assert_eq!(
        config
            .active_key(SigningAlgorithm::RS256)
            .map(|key| key.kid.as_str()),
        Some("k2")
    );
    assert!(config.active_key(SigningAlgorithm::PS256).is_none());
    Ok(())
}

#[test]
fn a_route_signs_es256_unless_it_names_an_algorithm() -> TestResult {
    let config = Config::from_toml(&with_route(ROUTE))?;
    assert_eq!(
        route(&config, 0)?.signing_algorithm,
        SigningAlgorithm::ES256
    );
    let rsa = ACTIVE_KEY
        .replace("k1", "k2")
        .replace("state", "algorithm = \"RS256\"\nstate");
    let text = format!(
        "{}{rsa}",
        route_with(
            "allowed_scopes",
            "signing_algorithm = \"RS256\"\nallowed_scopes"
        )
    );
    let config = Config::from_toml(&text)?;
    assert_eq!(
        route(&config, 0)?.signing_algorithm,
        SigningAlgorithm::RS256
    );
    Ok(())
}

#[test]
fn a_route_s_algorithm_needs_an_active_key() -> TestResult {
    let text = route_with(
        "allowed_scopes",
        "signing_algorithm = \"EdDSA\"\nallowed_scopes",
    );
    assert_eq!(
        problems(&text)?,
        [r#"route "orders" signs with EdDSA, which no active key in issuer.signing.keys does"#]
    );
    let retiring = format!(
        "{text}{}",
        ACTIVE_KEY
            .replace("k1", "k2")
            .replace("active", "retiring")
            .replace("state", "algorithm = \"EdDSA\"\nstate")
    );
    assert_eq!(
        problems(&retiring)?,
        [r#"route "orders" signs with EdDSA, which no active key in issuer.signing.keys does"#],
        "a retiring key doesn't sign"
    );
    Ok(())
}

#[test]
fn every_signing_algorithm_parses_by_its_jws_name() -> TestResult {
    for name in [
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA",
    ] {
        let key = ACTIVE_KEY.replace("state", &format!("algorithm = \"{name}\"\nstate"));
        let config = Config::from_toml(&format!("{ISSUER}{key}{GATEWAY}"))?;
        let parsed = config
            .issuer
            .signing
            .keys
            .first()
            .map(|key| key.algorithm)
            .ok_or("no key")?;
        assert_eq!(parsed.name(), name);
        assert_eq!(parsed.to_string(), name);
    }
    let none = ACTIVE_KEY.replace("state", "algorithm = \"none\"\nstate");
    assert!(Config::from_toml(&format!("{ISSUER}{none}{GATEWAY}")).is_err());
    let hmac = ACTIVE_KEY.replace("state", "algorithm = \"HS256\"\nstate");
    assert!(Config::from_toml(&format!("{ISSUER}{hmac}{GATEWAY}")).is_err());
    Ok(())
}

#[test]
fn the_retired_signing_algorithm_field_is_refused() {
    let old = ISSUER.replace(
        "provider = \"file\"",
        "provider = \"file\"\nalgorithm = \"ES256\"",
    );
    assert!(Config::from_toml(&format!("{old}{ACTIVE_KEY}{GATEWAY}")).is_err());
}

#[test]
fn kids_are_unique_and_not_empty() -> TestResult {
    let repeated = format!(
        "{ISSUER}{ACTIVE_KEY}{}{GATEWAY}",
        ACTIVE_KEY.replace("active", "retiring")
    );
    assert_eq!(
        problems(&repeated)?,
        [r#"issuer.signing.keys repeats kid "k1""#]
    );
    let empty = minimal().replace(r#"kid = "k1""#, r#"kid = """#);
    assert_eq!(
        problems(&empty)?,
        ["issuer.signing.keys has a key with an empty kid"]
    );
    Ok(())
}

#[test]
fn file_keys_need_a_private_key() -> TestResult {
    let text = minimal().replace("private_key = { file = \"k1.pem\" }\n", "");
    assert_eq!(
        problems(&text)?,
        [r#"issuer.signing.keys "k1" needs a private_key for the file provider"#]
    );
    Ok(())
}

#[test]
fn cache_needs_room() -> TestResult {
    let text = minimal().replace("max_entries = 10", "max_entries = 0");
    assert_eq!(
        problems(&text)?,
        ["gateway.cache.max_entries must be above zero"]
    );
    Ok(())
}

#[test]
fn trusted_issuers_are_https() -> TestResult {
    let text = format!(
        "{}{}",
        minimal(),
        OKTA.replace("https://okta", "http://okta")
    );
    assert_eq!(
        problems(&text)?,
        ["trusted_issuers.okta.issuer must be https"]
    );
    Ok(())
}

#[test]
fn introspection_urls_are_https() -> TestResult {
    let text = format!(
        "{}{}",
        minimal(),
        OKTA.replace(
            "algorithms",
            "validation = \"introspection\"
introspection_url = \"http://okta.example.com/introspect\"
client_id = \"tsong\"
client_secret = { env = \"SECRET\" }
algorithms"
        )
    );
    assert_eq!(
        problems(&text)?,
        ["trusted_issuers.okta.introspection_url must be https"]
    );
    Ok(())
}

#[test]
fn jwks_urls_are_https() -> TestResult {
    let text = format!(
        "{}{}",
        minimal(),
        OKTA.replace(
            "algorithms",
            "jwks_url = \"http://okta.example.com/keys\"
algorithms"
        )
    );
    assert_eq!(
        problems(&text)?,
        ["trusted_issuers.okta.jwks_url must be https"]
    );
    let https = text.replace(
        "http://okta.example.com/keys",
        "https://okta.example.com/keys",
    );
    let config = Config::from_toml(&https)?;
    assert_eq!(
        trusted(&config, "okta")?
            .jwks_url
            .as_ref()
            .map(|url| url.as_str()),
        Some("https://okta.example.com/keys")
    );
    Ok(())
}

#[test]
fn issuers_are_kept_exactly_as_written() -> TestResult {
    let text = format!("{}{OKTA}", minimal());
    let config = Config::from_toml(&text)?;
    assert_eq!(config.issuer.url, "https://tsong.example.com");
    assert_eq!(trusted(&config, "okta")?.issuer, "https://okta.example.com");
    Ok(())
}

#[test]
fn issuer_urls_must_parse() -> TestResult {
    let text = minimal().replace("https://tsong.example.com", "not a url");
    assert_eq!(problems(&text)?, ["issuer.url must be https"]);
    Ok(())
}

#[test]
fn jwks_refetch_is_configurable() -> TestResult {
    let text = format!(
        "{}{}",
        minimal(),
        OKTA.replace(
            "algorithms",
            "jwks_refetch = \"00:05:00\"
algorithms"
        )
    );
    let config = Config::from_toml(&text)?;
    assert_eq!(
        trusted(&config, "okta")?.jwks_refetch,
        Duration::from_secs(300)
    );
    Ok(())
}

/// The okta issuer with `lines` added.
fn okta_with(lines: &str) -> String {
    format!(
        "{}{}",
        minimal(),
        OKTA.replace("algorithms", &format!("{lines}\nalgorithms"))
    )
}

#[test]
fn key_timing_has_defaults_and_is_configurable() -> TestResult {
    let config = Config::from_toml(&okta_with(""))?;
    let okta = trusted(&config, "okta")?;
    assert_eq!(
        (
            okta.jwks_max_age,
            okta.jwks_retry,
            okta.jwks_refetch,
            okta.jwks_timeout
        ),
        (
            Duration::from_secs(3600),
            Duration::from_secs(10),
            Duration::from_secs(30),
            Duration::from_secs(10)
        )
    );
    let config = Config::from_toml(&okta_with(
        "jwks_max_age = \"02:00:00\"\njwks_retry = \"00:00:05\"\njwks_timeout = \"00:00:03\"",
    ))?;
    let okta = trusted(&config, "okta")?;
    assert_eq!(
        (okta.jwks_max_age, okta.jwks_retry, okta.jwks_timeout),
        (
            Duration::from_secs(7200),
            Duration::from_secs(5),
            Duration::from_secs(3)
        )
    );
    Ok(())
}

#[test]
fn key_timing_is_above_zero() -> TestResult {
    for field in ["jwks_max_age", "jwks_retry", "jwks_refetch", "jwks_timeout"] {
        assert_eq!(
            problems(&okta_with(&format!("{field} = \"00:00:00\"")))?,
            [format!("trusted_issuers.okta.{field} must be above zero")]
        );
    }
    Ok(())
}

#[test]
fn a_discovery_url_is_https() -> TestResult {
    let http = okta_with(
        "discovery_url = \"http://okta.example.com/tenant/.well-known/openid-configuration\"",
    );
    assert_eq!(
        problems(&http)?,
        ["trusted_issuers.okta.discovery_url must be https"]
    );
    let config = Config::from_toml(&http.replace("http://", "https://"))?;
    assert_eq!(
        trusted(&config, "okta")?
            .discovery_url
            .as_ref()
            .map(|url| url.as_str()),
        Some("https://okta.example.com/tenant/.well-known/openid-configuration")
    );
    Ok(())
}

#[test]
fn a_discovery_url_and_a_jwks_url_are_not_both_set() -> TestResult {
    let both = okta_with(
        "discovery_url = \"https://okta.example.com/d\"\njwks_url = \"https://okta.example.com/k\"",
    );
    assert_eq!(
        problems(&both)?,
        [
            "trusted_issuers.okta sets both discovery_url and jwks_url; jwks_url skips discovery, so set one"
        ]
    );
    Ok(())
}

#[test]
fn keys_trusted_for_more_than_a_day_warn() -> TestResult {
    let warning = "trusted_issuers.okta.jwks_max_age is over a day, 1.00:00:00; a key the issuer withdraws stays trusted that long".to_owned();
    let day = Config::from_toml(&okta_with("jwks_max_age = \"1.00:00:00\""))?;
    assert!(!day.warnings().0.contains(&warning), "{}", day.warnings());
    let longer = Config::from_toml(&okta_with("jwks_max_age = \"1.01:00:00\""))?;
    assert!(
        longer.warnings().0.contains(&warning),
        "{}",
        longer.warnings()
    );
    let introspected = Config::from_toml(&okta_with(
        "jwks_max_age = \"1.01:00:00\"\nvalidation = \"introspection\"\nintrospection_url = \"https://okta.example.com/introspect\"\nclient_id = \"tsong\"\nclient_secret = { env = \"SECRET\" }",
    ))?;
    assert!(
        !introspected.warnings().0.contains(&warning),
        "{}",
        introspected.warnings()
    );
    Ok(())
}

#[test]
fn claim_mapping_may_not_write_reserved_claims() -> TestResult {
    let text = format!(
        "{}{OKTA}[claims]
copy = [\"email\", \"aud\"]
[claims.rename.okta]
uid = \"sub\"
x = \"exp\"
y = \"sub_id\"
",
        minimal()
    );
    assert_eq!(
        problems(&text)?,
        [
            r#"claims.copy may not copy reserved claim "aud""#,
            r#"claims.rename.okta may not write reserved claim "exp""#,
            r#"claims.rename.okta may not write reserved claim "sub_id""#,
        ]
    );
    Ok(())
}

#[test]
fn a_rename_writes_each_claim_from_one_claim() -> TestResult {
    let text = format!(
        "{}{OKTA}[claims.rename.okta]
oid = \"sub\"
upn = \"sub\"
uid = \"user\"
",
        minimal()
    );
    assert_eq!(
        problems(&text)?,
        [r#"claims.rename.okta writes claim "sub" from more than one claim"#]
    );
    Ok(())
}

#[test]
fn a_sub_prefix_is_required() -> TestResult {
    let text = format!(
        "{}{}",
        minimal(),
        OKTA.replace("sub_prefix = \"okta\"\n", "")
    );
    assert!(parse_error(&text)?.contains("missing field `sub_prefix`"));
    Ok(())
}

#[test]
fn sub_prefixes_are_lowercase_letters_digits_and_dashes() -> TestResult {
    for good in ["okta", "okta-2", "0"] {
        let text = format!(
            "{}{}",
            minimal(),
            OKTA.replace("\"okta\"\n", &format!("{good:?}\n"))
        );
        Config::from_toml(&text)?;
    }
    for bad in [
        "", "Okta", "ok:ta", "ok ta", "ok_ta", "ok.ta", "okta/", "ökta",
    ] {
        let text = format!(
            "{}{}",
            minimal(),
            OKTA.replace("\"okta\"\n", &format!("{bad:?}\n"))
        );
        assert_eq!(
            problems(&text)?,
            [format!(
                "trusted_issuers.okta.sub_prefix must be lowercase letters, digits and -, not {bad:?}"
            )]
        );
    }
    Ok(())
}

#[test]
fn sub_prefixes_are_unique() -> TestResult {
    let other = OKTA
        .replace("trusted_issuers.okta", "trusted_issuers.other")
        .replace("okta.example.com", "other.example.com");
    let text = format!("{}{OKTA}{other}", minimal());
    assert_eq!(
        problems(&text)?,
        [r#"trusted_issuers.other.sub_prefix "okta" is used by another trusted issuer"#]
    );
    Ok(())
}

#[test]
fn trusted_issuers_need_audiences() -> TestResult {
    let text = format!("{}{}", minimal(), OKTA.replace(r#"["api"]"#, "[]"));
    assert_eq!(
        problems(&text)?,
        ["trusted_issuers.okta.audiences is empty"]
    );
    Ok(())
}

#[test]
fn jwt_validation_needs_algorithms() -> TestResult {
    let text = format!("{}{}", minimal(), OKTA.replace(r#"["RS256"]"#, "[]"));
    assert_eq!(
        problems(&text)?,
        ["trusted_issuers.okta.algorithms is empty, and jwt validation needs at least one"]
    );
    Ok(())
}

#[test]
fn introspection_needs_its_endpoint_and_credentials() -> TestResult {
    let text = format!(
        "{}{}",
        minimal(),
        OKTA.replace("algorithms", "validation = \"introspection\"\nalgorithms")
    );
    assert_eq!(
        problems(&text)?,
        [
            "trusted_issuers.okta.introspection_url is required for introspection",
            "trusted_issuers.okta.client_id is required for introspection",
            "trusted_issuers.okta.client_secret is required for introspection",
        ]
    );
    Ok(())
}

#[test]
fn claim_renames_name_trusted_issuers() -> TestResult {
    let text = format!("{}{OKTA}[claims.rename.entra]\noid = \"sub\"\n", minimal());
    assert_eq!(
        problems(&text)?,
        ["claims.rename.entra names no trusted issuer"]
    );
    Ok(())
}

const ROUTE: &str = r#"
[[routes]]
name = "orders"
host = "orders.example.com"
downstream = "https://orders-lb.example.com"
append_audience = "orders.example.com"
audiences = { allow = ["api"] }
allowed_scopes = ["orders.read"]
"#;

fn with_route(route: &str) -> String {
    format!("{}{OKTA}{route}", minimal())
}

/// The route with one line of `ROUTE` replaced.
fn route_with(from: &str, to: &str) -> String {
    with_route(&ROUTE.replace(from, to))
}

#[test]
fn a_valid_route_loads() -> TestResult {
    let config = Config::from_toml(&with_route(ROUTE))?;
    let orders = route(&config, 0)?;
    assert_eq!(orders.append_audience, "orders.example.com");
    assert_eq!(orders.audiences.allow, ["api"]);
    assert!(orders.audiences.require.is_empty());
    assert!(orders.audiences.deny.is_empty());
    assert!(orders.allow.is_none());
    Ok(())
}

#[test]
fn a_config_without_an_active_key_has_none() -> TestResult {
    let mut config = Config::from_toml(&minimal())?;
    config.issuer.signing.keys.clear();
    assert!(config.active_key(SigningAlgorithm::ES256).is_none());
    Ok(())
}

#[tokio::test]
async fn a_file_store_loads_its_file() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("tsong.toml");
    std::fs::write(&path, minimal())?;
    let store: Box<dyn ConfigStore> = Box::new(FileStore::new(&path));
    let fetched = store.load().await?;
    assert_eq!(fetched.text, minimal());
    assert_eq!(fetched.revision, hex(&Sha256::digest(minimal().as_bytes())));
    assert_eq!(fetched.content, fetched.revision);
    assert_eq!(fetched.revision.len(), 64);
    assert_eq!(fetched.author, None);
    assert_eq!(fetched.base_dir.as_deref(), Some(dir.path()));
    let snapshot = fetched.parse()?;
    assert_eq!(snapshot.config.issuer.listen.port(), 8444);
    assert_eq!(snapshot.content, snapshot.revision);
    assert_eq!(snapshot.author, None);
    assert_eq!(
        private_key(&snapshot.config),
        Some(file_ref(&dir.path().join("k1.pem"))?)
    );
    std::fs::write(
        &path,
        minimal().replace("max_entries = 10", "max_entries = 11"),
    )?;
    assert_ne!(store.load().await?.revision, snapshot.revision);
    let missing = FileStore::new(dir.path().join("missing.toml"));
    assert!(matches!(
        missing.load().await,
        Err(ConfigError::Read { .. })
    ));
    Ok(())
}

#[test]
fn the_gateway_allow_list_is_required() -> TestResult {
    let text = minimal().replace("allow = [\"10.0.0.0/8\"]\n", "");
    assert!(parse_error(&text)?.contains("missing field `allow`"));
    Ok(())
}

#[test]
fn route_fields_are_required() -> TestResult {
    for field in [
        "host",
        "downstream",
        "append_audience",
        "audiences",
        "allowed_scopes",
    ] {
        let line = ROUTE
            .lines()
            .find(|line| line.starts_with(field))
            .ok_or(format!("no {field} line"))?;
        let text = route_with(line, "");
        assert!(
            parse_error(&text)?.contains(&format!("missing field `{field}`")),
            "{field}"
        );
    }
    Ok(())
}

#[test]
fn route_names_are_unique() -> TestResult {
    let second = ROUTE.replace(
        r#"host = "orders.example.com""#,
        r#"host = "other.example.com""#,
    );
    let text = with_route(&format!("{ROUTE}{second}"));
    assert_eq!(problems(&text)?, [r#"routes repeats name "orders""#]);
    Ok(())
}

#[test]
fn route_hosts_are_unique_without_regard_to_case() -> TestResult {
    let second = ROUTE
        .replace(r#"name = "orders""#, r#"name = "orders-2""#)
        .replace(
            r#"host = "orders.example.com""#,
            r#"host = "Orders.Example.COM""#,
        );
    let text = with_route(&format!("{ROUTE}{second}"));
    assert_eq!(
        problems(&text)?,
        [r#"routes repeats host "Orders.Example.COM""#]
    );
    Ok(())
}

#[test]
fn route_hosts_are_bare_host_names() -> TestResult {
    for host in [
        "",
        "orders.example.com:443",
        "orders.example.com/orders",
        "https://orders.example.com",
        "user@orders.example.com",
        "orders example.com",
    ] {
        let text = route_with(
            r#"host = "orders.example.com""#,
            &format!("host = {host:?}"),
        );
        assert_eq!(
            problems(&text)?,
            [r#"route "orders" host must be a host name, without a scheme, port or path"#],
            "{host}"
        );
    }
    for host in ["Orders.Example.com", "10.1.2.3", "[::1]", "localhost"] {
        let text = route_with(
            r#"host = "orders.example.com""#,
            &format!("host = {host:?}"),
        );
        Config::from_toml(&text).map_err(|error| format!("{host}: {error}"))?;
    }
    Ok(())
}

#[test]
fn downstreams_are_https_origins() -> TestResult {
    for downstream in [
        "http://orders-lb.example.com",
        "https://orders-lb.example.com/api",
        "https://orders-lb.example.com/?x=1",
        "https://orders-lb.example.com/#top",
        "https://user@orders-lb.example.com",
        "https://:pass@orders-lb.example.com",
        "unix:/run/orders.sock",
    ] {
        let text = route_with(
            r#"downstream = "https://orders-lb.example.com""#,
            &format!("downstream = {downstream:?}"),
        );
        assert_eq!(
            problems(&text)?,
            [
                r#"route "orders" downstream must be an https origin, without a path, query or credentials"#
            ],
            "{downstream}"
        );
    }
    for downstream in [
        "https://orders-lb.example.com/",
        "https://orders-lb.example.com:8443",
    ] {
        let text = route_with(
            r#"downstream = "https://orders-lb.example.com""#,
            &format!("downstream = {downstream:?}"),
        );
        Config::from_toml(&text).map_err(|error| format!("{downstream}: {error}"))?;
    }
    Ok(())
}

#[test]
fn the_route_table_finds_routes_by_host_without_regard_to_case() -> TestResult {
    let second = ROUTE
        .replace(r#"name = "orders""#, r#"name = "builds""#)
        .replace(
            r#"host = "orders.example.com""#,
            r#"host = "Builds.Example.com""#,
        );
    let config = Config::from_toml(&with_route(&format!("{ROUTE}{second}")))?;
    let table = RouteTable::new(&config.routes);
    let name = |host: &str| table.get(host).map(|route| route.name.clone());
    assert_eq!(name("orders.example.com").as_deref(), Some("orders"));
    assert_eq!(name("ORDERS.example.com").as_deref(), Some("orders"));
    assert_eq!(name("builds.example.com").as_deref(), Some("builds"));
    assert_eq!(name("example.com"), None);
    assert!(RouteTable::default().get("orders.example.com").is_none());
    Ok(())
}

#[test]
fn the_route_table_keeps_the_first_of_a_repeated_host() -> TestResult {
    let config = Config::from_toml(&with_route(ROUTE))?;
    let first = route(&config, 0)?.clone();
    let mut second = first.clone();
    second.name = "second".into();
    second.host = "ORDERS.example.com".into();
    let table = RouteTable::new(&[first, second]);
    let found = table
        .get("orders.example.com")
        .map(|route| route.name.as_str());
    assert_eq!(found, Some("orders"));
    Ok(())
}

fn names(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

/// The orders route with these allowed audiences and scopes.
fn orders(audiences: &[&str], scopes: &[&str]) -> TestResult<Route> {
    let config = Config::from_toml(&with_route(ROUTE))?;
    let mut route = route(&config, 0)?.clone();
    route.audiences.allow = names(audiences);
    route.allowed_scopes = names(scopes);
    Ok(route)
}

#[test]
fn a_route_needs_one_allowed_audience_and_none_outside() -> TestResult {
    let route = orders(&["a", "b"], &[])?;
    assert_eq!(route.audience_refusal(&["b"]), None);
    assert_eq!(route.audience_refusal(&["a", "b"]), None);
    assert_eq!(
        route.audience_refusal(&["x", "y"]),
        Some(AudienceRefusal::NotAllowed)
    );
    assert_eq!(
        route.audience_refusal(&[]),
        Some(AudienceRefusal::NoAudience)
    );
    assert_eq!(
        route.audience_refusal(&["b", "x", "y"]),
        Some(AudienceRefusal::Outside("x"))
    );
    Ok(())
}

#[test]
fn an_empty_allow_accepts_nothing_and_a_star_accepts_any_audience() -> TestResult {
    let empty = orders(&[], &[])?;
    assert_eq!(
        empty.audience_refusal(&["a"]),
        Some(AudienceRefusal::NotAllowed)
    );
    let any = orders(&[ANY], &[])?;
    assert_eq!(any.audience_refusal(&["a", "b"]), None);
    assert_eq!(
        any.audience_refusal(&[]),
        Some(AudienceRefusal::NoAudience),
        "a star still needs an audience"
    );
    Ok(())
}

#[test]
fn a_route_needs_every_required_audience() -> TestResult {
    let mut route = orders(&["a", "b", "c"], &[])?;
    route.audiences.require = names(&["b", "c"]);
    assert_eq!(route.audience_refusal(&["a", "b", "c"]), None);
    assert_eq!(
        route.audience_refusal(&["a", "b"]),
        Some(AudienceRefusal::Missing("c"))
    );
    assert_eq!(
        route.audience_refusal(&["a"]),
        Some(AudienceRefusal::Missing("b"))
    );
    Ok(())
}

#[test]
fn a_route_refuses_a_denied_audience() -> TestResult {
    let mut route = orders(&[ANY], &[])?;
    route.audiences.deny = names(&["admin", "root"]);
    assert_eq!(route.audience_refusal(&["a", "b"]), None);
    assert_eq!(
        route.audience_refusal(&["a", "root", "admin"]),
        Some(AudienceRefusal::Denied("root"))
    );
    Ok(())
}

#[test]
fn audience_checks_run_in_order() -> TestResult {
    let mut route = orders(&["a", "b", "c"], &[])?;
    route.audiences.require = names(&["b"]);
    route.audiences.deny = names(&["c"]);
    // Outside comes before missing, and missing before denied.
    assert_eq!(
        route.audience_refusal(&["c", "x"]),
        Some(AudienceRefusal::Outside("x"))
    );
    assert_eq!(
        route.audience_refusal(&["a", "c"]),
        Some(AudienceRefusal::Missing("b"))
    );
    assert_eq!(
        route.audience_refusal(&["b", "c"]),
        Some(AudienceRefusal::Denied("c"))
    );
    Ok(())
}

#[test]
fn an_audience_table_loads_with_require_and_deny() -> TestResult {
    let table = ROUTE.replace("audiences = { allow = [\"api\"] }\n", "")
        + "\n[routes.audiences]\nallow = [\"*\"]\nrequire = [\"api\"]\ndeny = [\"admin\"]\n";
    let config = Config::from_toml(&with_route(&table))?;
    let audiences = &route(&config, 0)?.audiences;
    assert_eq!(audiences.allow, [ANY]);
    assert_eq!(audiences.require, ["api"]);
    assert_eq!(audiences.deny, ["admin"]);
    Ok(())
}

#[test]
fn an_audience_table_refuses_unknown_keys() -> TestResult {
    let text = route_with(
        r#"audiences = { allow = ["api"] }"#,
        r#"audiences = { allow = ["api"], allowed = ["api"] }"#,
    );
    assert!(parse_error(&text)?.contains("unknown field `allowed`"));
    Ok(())
}

#[test]
fn allowed_audiences_is_refused_naming_its_replacement() -> TestResult {
    let text = route_with(
        r#"audiences = { allow = ["api"] }"#,
        r#"allowed_audiences = ["api"]"#,
    );
    let error = parse_error(&text)?;
    assert!(
        error.ends_with(
            "allowed_audiences is replaced by [routes.audiences]; move its values to audiences.allow, which also refuses a token carrying any audience outside it"
        ),
        "{error}"
    );
    assert!(error.starts_with("line "), "{error}");
    let line = text
        .lines()
        .position(|line| line.starts_with("allowed_audiences"))
        .ok_or("no allowed_audiences line")?
        + 1;
    assert_eq!(
        error,
        format!(
            "line {line}, column 21: allowed_audiences is replaced by [routes.audiences]; move its values to audiences.allow, which also refuses a token carrying any audience outside it"
        )
    );
    Ok(())
}

#[test]
fn a_route_shows_no_trace_of_allowed_audiences() -> TestResult {
    let config = Config::from_toml(&with_route(ROUTE))?;
    let shown = format!("{:?}", route(&config, 0)?);
    assert!(!shown.contains("allowed_audiences"), "{shown}");
    Ok(())
}

#[test]
fn allowed_audiences_outside_a_route_is_an_unknown_field() -> TestResult {
    let text = okta_with(r#"allowed_audiences = ["api"]"#);
    let error = parse_error(&text)?;
    assert!(
        error.contains("unknown field `allowed_audiences`, expected"),
        "{error}"
    );
    Ok(())
}

/// The problems the orders route has with this audience policy.
fn audience_problems(policy: &str) -> TestResult<Vec<String>> {
    problems(&route_with(
        r#"audiences = { allow = ["api"] }"#,
        &format!("audiences = {policy}"),
    ))
}

#[test]
fn audience_values_are_named() -> TestResult {
    assert_eq!(
        audience_problems(r#"{ allow = ["api", ""], require = [""] }"#)?,
        [
            r#"route "orders" audiences.allow has an empty value; name each audience"#,
            r#"route "orders" audiences.require has an empty value; name each audience"#,
        ]
    );
    assert_eq!(
        audience_problems(r#"{ allow = ["*"], deny = [""] }"#)?,
        [r#"route "orders" audiences.deny has an empty value; name each audience"#]
    );
    Ok(())
}

#[test]
fn a_star_stands_alone_in_allow_and_nowhere_else() -> TestResult {
    assert_eq!(
        audience_problems(r#"{ allow = ["api", "*"] }"#)?,
        [
            r#"route "orders" audiences.allow has "*" with other values; "*" allows any audience, so it stands alone"#
        ]
    );
    assert_eq!(
        audience_problems(r#"{ allow = ["*"], require = ["*"], deny = ["*"] }"#)?,
        [
            r#"route "orders" audiences.require may not hold "*"; name each audience"#,
            r#"route "orders" audiences.deny may not hold "*"; name each audience"#,
        ]
    );
    Ok(())
}

#[test]
fn an_audience_is_not_both_required_and_denied() -> TestResult {
    assert_eq!(
        audience_problems(r#"{ allow = ["*"], require = ["api"], deny = ["api"] }"#)?,
        [r#"route "orders" both requires and denies audience "api""#]
    );
    assert_eq!(
        audience_problems(r#"{ allow = ["*"], require = ["api", "api"], deny = ["api", "api"] }"#)?,
        [
            r#"route "orders" both requires and denies audience "api""#,
            r#"route "orders" audiences.require repeats audience "api""#,
            r#"route "orders" audiences.deny repeats audience "api""#,
        ],
        "reported once, however often it repeats"
    );
    Ok(())
}

#[test]
fn audience_lists_repeat_no_value() -> TestResult {
    assert_eq!(
        audience_problems(
            r#"{ allow = ["api", "other", "api", "other", "api"], require = ["api", "api"] }"#
        )?,
        [
            r#"route "orders" audiences.allow repeats audience "api""#,
            r#"route "orders" audiences.allow repeats audience "other""#,
            r#"route "orders" audiences.require repeats audience "api""#,
        ]
    );
    assert_eq!(
        audience_problems(r#"{ allow = ["*", "*"] }"#)?,
        [r#"route "orders" audiences.allow repeats audience "*""#]
    );
    Ok(())
}

#[test]
fn audience_values_hold_no_whitespace() -> TestResult {
    assert_eq!(
        audience_problems(r#"{ allow = ["api", "a b"], require = ["api\t"] }"#)?,
        [
            r#"route "orders" audiences.allow has "a b"; an audience holds no whitespace"#,
            r#"route "orders" audiences.require has "api\t"; an audience holds no whitespace"#,
        ]
    );
    assert_eq!(
        audience_problems(r#"{ allow = ["*"], deny = [" admin"] }"#)?,
        [r#"route "orders" audiences.deny has " admin"; an audience holds no whitespace"#]
    );
    Ok(())
}

#[test]
fn required_audiences_must_be_allowed() -> TestResult {
    assert_eq!(
        audience_problems(r#"{ allow = ["api"], require = ["api", "other"] }"#)?,
        [r#"route "orders" requires audience "other", which its audiences.allow doesn't admit"#]
    );
    Config::from_toml(&route_with(
        r#"audiences = { allow = ["api"] }"#,
        r#"audiences = { allow = ["*"], require = ["other"] }"#,
    ))?;
    Ok(())
}

#[test]
fn deny_applies_only_when_allow_is_a_star() -> TestResult {
    let refused = r#"route "orders" audiences.deny applies only when audiences.allow is "*"; remove the denied audiences from allow instead"#;
    for policy in [
        r#"{ allow = ["api", "other"], deny = ["other"] }"#,
        r#"{ allow = ["api"], deny = ["admin"] }"#,
        r#"{ allow = [], deny = ["admin"] }"#,
    ] {
        assert_eq!(audience_problems(policy)?, [refused], "{policy}");
    }
    assert_eq!(
        audience_problems(r#"{ allow = ["api"], require = ["api"], deny = ["api"] }"#)?,
        [refused]
    );
    Config::from_toml(&route_with(
        r#"audiences = { allow = ["api"] }"#,
        r#"audiences = { allow = ["api"], deny = [] }"#,
    ))?;
    Config::from_toml(&route_with(
        r#"audiences = { allow = ["api"] }"#,
        r#"audiences = { allow = ["*"], deny = ["admin"] }"#,
    ))?;
    Ok(())
}

#[test]
fn a_route_refuses_the_first_scope_it_does_not_allow() -> TestResult {
    let route = orders(&[], &["read", "write"])?;
    assert_eq!(route.refused_scope(["read", "write"].into_iter()), Ok(()));
    assert_eq!(route.refused_scope(std::iter::empty()), Ok(()));
    assert_eq!(
        route.refused_scope(["read", "admin", "root"].into_iter()),
        Err(Some("admin"))
    );
    Ok(())
}

#[test]
fn a_route_reports_the_first_required_scope_missing() -> TestResult {
    let mut route = orders(&[], &["read", "write"])?;
    assert_eq!(route.missing_scope(|_| false), None, "none required");
    route.required_scopes = vec!["read".into(), "write".into()];
    assert_eq!(route.missing_scope(|_| true), None);
    assert_eq!(route.missing_scope(|scope| scope == "read"), Some("write"));
    assert_eq!(route.missing_scope(|_| false), Some("read"));
    Ok(())
}

#[test]
fn required_scopes_default_to_none_and_load() -> TestResult {
    let config = Config::from_toml(&with_route(ROUTE))?;
    assert!(route(&config, 0)?.required_scopes.is_empty());
    let required = ROUTE.replace(
        "allowed_scopes",
        "required_scopes = [\"orders.read\"]\nallowed_scopes",
    );
    let config = Config::from_toml(&with_route(&required))?;
    assert_eq!(route(&config, 0)?.required_scopes, ["orders.read"]);
    Ok(())
}

#[test]
fn required_scopes_must_be_allowed_and_named() -> TestResult {
    let refused = ROUTE.replace(
        "allowed_scopes",
        "required_scopes = [\"orders.read\", \"admin\", \"*\"]\nallowed_scopes",
    );
    assert_eq!(
        problems(&with_route(&refused))?,
        [
            r#"route "orders" requires scope "admin", which its allowed_scopes refuses"#,
            r#"route "orders" required_scopes may not hold "*"; name each scope"#,
        ]
    );
    let open = refused.replace(", \"*\"]", "]").replace(
        r#"allowed_scopes = ["orders.read"]"#,
        r#"allowed_scopes = ["*"]"#,
    );
    Config::from_toml(&with_route(&open))?;
    Ok(())
}

#[test]
fn required_scopes_are_single_scopes_named_once() -> TestResult {
    // Under "*" every scope is allowed, so only the shape check stands
    // between these and a route that refuses every token.
    let malformed = ROUTE
        .replace(
            "allowed_scopes",
            "required_scopes = [\"\", \"orders.read billing.read\", \"a\", \"a\"]\nallowed_scopes",
        )
        .replace(
            r#"allowed_scopes = ["orders.read"]"#,
            r#"allowed_scopes = ["*"]"#,
        );
    assert_eq!(
        problems(&with_route(&malformed))?,
        [
            r#"route "orders" required scope "" must be one scope, without spaces"#,
            r#"route "orders" required scope "orders.read billing.read" must be one scope, without spaces"#,
            r#"route "orders" repeats required scope "a""#,
        ]
    );
    Ok(())
}

#[test]
fn an_empty_scope_list_refuses_everything_and_a_star_accepts_anything() -> TestResult {
    let empty = orders(&[], &[])?;
    assert_eq!(empty.refused_scope(std::iter::empty()), Err(None));
    assert_eq!(empty.refused_scope(["read"].into_iter()), Err(None));
    let any = orders(&[], &["read", ANY])?;
    assert_eq!(any.refused_scope(["admin"].into_iter()), Ok(()));
    Ok(())
}

#[test]
fn a_clean_config_has_no_warnings() -> TestResult {
    let config = Config::from_toml(&with_route(ROUTE))?;
    assert_eq!(config.warnings(), Warnings::default());
    assert_eq!(config.warnings().to_string(), "");
    Ok(())
}

#[test]
fn empty_lists_warn_as_omissions() -> TestResult {
    let route = ROUTE
        .replace(
            r#"audiences = { allow = ["api"] }"#,
            "audiences = { allow = [] }",
        )
        .replace(
            r#"allowed_scopes = ["orders.read"]"#,
            "allowed_scopes = []\nallow = []",
        );
    let text = with_route(&route).replace(r#"allow = ["10.0.0.0/8"]"#, "allow = []");
    let warnings = Config::from_toml(&text)?.warnings();
    assert_eq!(
        warnings.0,
        [
            "gateway.allow is empty; every client will be denied",
            r#"route "orders": audiences.allow is empty; every request will be denied"#,
            r#"route "orders": allowed_scopes is empty; every request will be denied"#,
            r#"route "orders": allow is empty; every client will be denied"#,
        ]
    );
    assert_eq!(
        warnings.to_string().lines().next(),
        Some("warning: gateway.allow is empty; every client will be denied")
    );
    Ok(())
}

#[test]
fn accept_anything_entries_warn_as_decisions() -> TestResult {
    let route = ROUTE
        .replace(
            r#"audiences = { allow = ["api"] }"#,
            r#"audiences = { allow = ["*"] }"#,
        )
        .replace(
            r#"allowed_scopes = ["orders.read"]"#,
            "allowed_scopes = [\"*\"]\nallow = [\"::/0\"]",
        );
    let text = with_route(&route).replace(
        r#"allow = ["10.0.0.0/8"]"#,
        r#"allow = ["0.0.0.0/0", "10.0.0.0/8", "::/0"]"#,
    );
    let warnings = Config::from_toml(&text)?.warnings();
    assert_eq!(
        warnings.0,
        [
            "gateway.allow has 0.0.0.0/0; every address is allowed",
            "gateway.allow has ::/0; every address is allowed",
            r#"route "orders": audiences.allow has "*"; any audience is accepted"#,
            r#"route "orders": allowed_scopes has "*"; any value is accepted"#,
            r#"route "orders": allow has ::/0; every address is allowed"#,
        ]
    );
    Ok(())
}

#[test]
fn a_star_audience_with_only_require_warns() -> TestResult {
    let text = route_with(
        r#"audiences = { allow = ["api"] }"#,
        r#"audiences = { allow = ["*"], require = ["api"] }"#,
    );
    assert_eq!(
        Config::from_toml(&text)?.warnings().0,
        [
            r#"route "orders": audiences.allow has "*"; any audience is accepted alongside the required ones"#
        ]
    );
    Ok(())
}

#[test]
fn a_star_audience_narrowed_by_deny_does_not_warn() -> TestResult {
    for policy in [
        r#"{ allow = ["*"], deny = ["admin"] }"#,
        r#"{ allow = ["*"], require = ["api"], deny = ["admin"] }"#,
    ] {
        let text = route_with(
            r#"audiences = { allow = ["api"] }"#,
            &format!("audiences = {policy}"),
        );
        assert_eq!(
            Config::from_toml(&text)?.warnings(),
            Warnings::default(),
            "{policy}"
        );
    }
    Ok(())
}

/// A second trusted issuer, validated by introspection, that accepts
/// `other`.
const INTROSPECTED: &str = r#"
[trusted_issuers.corp]
sub_prefix = "corp"
issuer = "https://corp.example.com"
audiences = ["other"]
validation = "introspection"
introspection_url = "https://corp.example.com/introspect"
client_id = "tsong"
client_secret = { env = "SECRET" }
"#;

const UNSERVED: &str = r#"route "orders": audiences admits no audience a trusted issuer accepts; every token will be refused"#;

#[test]
fn a_route_no_trusted_issuer_can_serve_warns() -> TestResult {
    for policy in [
        r#"{ allow = ["other"] }"#,
        r#"{ allow = ["a", "b"] }"#,
        r#"{ allow = ["*"], deny = ["api"] }"#,
    ] {
        let text = route_with(
            r#"audiences = { allow = ["api"] }"#,
            &format!("audiences = {policy}"),
        );
        assert_eq!(
            Config::from_toml(&text)?.warnings().0,
            [UNSERVED],
            "{policy}"
        );
    }
    for policy in [
        r#"{ allow = ["other", "api"] }"#,
        r#"{ allow = ["*"], deny = ["other"] }"#,
    ] {
        let text = route_with(
            r#"audiences = { allow = ["api"] }"#,
            &format!("audiences = {policy}"),
        );
        assert_eq!(
            Config::from_toml(&text)?.warnings(),
            Warnings::default(),
            "{policy}"
        );
    }
    Ok(())
}

#[test]
fn a_star_route_denying_every_issuer_audience_warns() -> TestResult {
    let text = route_with(
        r#"audiences = { allow = ["api"] }"#,
        r#"audiences = { allow = ["*"], deny = ["api", "web"] }"#,
    )
    .replace(r#"audiences = ["api"]"#, r#"audiences = ["api", "web"]"#);
    assert_eq!(Config::from_toml(&text)?.warnings().0, [UNSERVED]);
    let text = text.replace(r#"deny = ["api", "web"]"#, r#"deny = ["api"]"#);
    assert_eq!(Config::from_toml(&text)?.warnings(), Warnings::default());
    Ok(())
}

#[test]
fn audiences_only_an_introspected_issuer_accepts_do_not_serve_a_route() -> TestResult {
    let route = ROUTE.replace(
        r#"audiences = { allow = ["api"] }"#,
        r#"audiences = { allow = ["other"] }"#,
    );
    let text = format!("{}{OKTA}{INTROSPECTED}{route}", minimal());
    assert_eq!(Config::from_toml(&text)?.warnings().0, [UNSERVED]);
    Ok(())
}

#[test]
fn a_route_does_not_warn_when_no_trusted_issuer_validates_jwts() -> TestResult {
    for issuers in ["", INTROSPECTED] {
        let route = ROUTE.replace(
            r#"audiences = { allow = ["api"] }"#,
            r#"audiences = { allow = ["missing"] }"#,
        );
        let text = format!("{}{issuers}{route}", minimal());
        assert_eq!(
            Config::from_toml(&text)?.warnings(),
            Warnings::default(),
            "{issuers}"
        );
    }
    Ok(())
}

#[test]
fn a_route_may_deny_its_append_audience() -> TestResult {
    // deny refuses an inbound token already minted for the route;
    // append_audience adds to the minted one.
    let text = route_with(
        r#"audiences = { allow = ["api"] }"#,
        r#"audiences = { allow = ["*"], deny = ["orders.example.com"] }"#,
    );
    let config = Config::from_toml(&text)?;
    assert_eq!(route(&config, 0)?.audiences.deny, ["orders.example.com"]);
    assert_eq!(config.warnings(), Warnings::default());
    Ok(())
}

#[test]
fn the_read_timeout_defaults_to_a_minute_and_a_route_may_override_it() -> TestResult {
    let second = ROUTE
        .replace(r#"name = "orders""#, r#"name = "slow""#)
        .replace(
            r#"host = "orders.example.com""#,
            r#"host = "slow.example.com""#,
        )
        .replace(
            r#"allowed_scopes = ["orders.read"]"#,
            "allowed_scopes = [\"orders.read\"]\nread_timeout = \"00:05:00\"",
        );
    let config = Config::from_toml(&with_route(&format!("{ROUTE}{second}")))?;
    assert_eq!(config.gateway.read_timeout, Duration::from_secs(60));
    assert_eq!(
        route(&config, 0)?.read_timeout(&config.gateway),
        Duration::from_secs(60)
    );
    assert_eq!(
        route(&config, 1)?.read_timeout(&config.gateway),
        Duration::from_secs(300)
    );
    let text = with_route(ROUTE).replace(
        "[gateway.cache]",
        "read_timeout = \"00:01:30\"\n\n[gateway.cache]",
    );
    let config = Config::from_toml(&text)?;
    assert_eq!(
        route(&config, 0)?.read_timeout(&config.gateway),
        Duration::from_secs(90)
    );
    Ok(())
}

#[test]
fn read_timeouts_are_above_zero() -> TestResult {
    let text = route_with(
        r#"allowed_scopes = ["orders.read"]"#,
        "allowed_scopes = [\"orders.read\"]\nread_timeout = \"00:00:00\"",
    )
    .replace(
        "[gateway.cache]",
        "read_timeout = \"00:00:00\"\n\n[gateway.cache]",
    );
    assert_eq!(
        problems(&text)?,
        [
            r#"route "orders" read_timeout must be above zero"#,
            "gateway.read_timeout must be above zero",
        ]
    );
    let bad = route_with(
        r#"allowed_scopes = ["orders.read"]"#,
        "allowed_scopes = [\"orders.read\"]\nread_timeout = \"soon\"",
    );
    parse_error(&bad)?;
    Ok(())
}

#[test]
fn every_problem_is_reported() {
    let text = minimal()
        .replace("https://tsong", "http://tsong")
        .replace("max_entries = 10", "max_entries = 0");
    let message = Config::from_toml(&text).map_err(|error| error.to_string());
    assert_eq!(
        message.err().as_deref(),
        Some(
            "invalid config:\n- issuer.url must be https\n- gateway.cache.max_entries must be above zero\n"
        )
    );
}

#[test]
fn without_a_directory_key_paths_must_be_absolute() -> TestResult {
    match Config::from_text(&minimal(), None) {
        Err(ConfigError::Invalid(problems)) => assert_eq!(
            problems.0,
            [
                r#"issuer.signing.keys "k1" private_key must be an absolute path, since the config has no directory"#
            ]
        ),
        other => return Err(format!("expected invalid, got {other:?}").into()),
    }
    let absolute = std::env::temp_dir().join("k1.pem");
    let text = minimal().replace(
        r#"private_key = { file = "k1.pem" }"#,
        &format!("private_key = {}", file_ref(&absolute)?),
    );
    let config = Config::from_text(&text, None)?;
    assert_eq!(private_key(&config), Some(file_ref(&absolute)?));
    Ok(())
}

#[test]
fn a_directory_resolves_relative_key_paths() -> TestResult {
    let dir = std::env::temp_dir();
    let config = Config::from_text(&minimal(), Some(&dir))?;
    assert_eq!(private_key(&config), Some(file_ref(&dir.join("k1.pem"))?));
    Ok(())
}

#[test]
fn hex_is_lowercase_and_two_digits_a_byte() {
    assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    assert_eq!(hex(&[]), "");
}

#[test]
fn the_retired_secret_fields_are_refused() {
    let path = minimal().replace("private_key = { file = \"k1.pem\" }", "path = \"k1.pem\"");
    assert!(Config::from_toml(&path).is_err());
    let env = okta_with("client_secret_env = \"SECRET\"");
    assert!(Config::from_toml(&env).is_err());
}

#[test]
fn a_secret_field_takes_only_a_reference() -> TestResult {
    let not_a_table = NOT_A_REFERENCE;
    let not_one = "a secret reference must have exactly one key, env or file";
    for (written, expected) in [
        ("\"hunter2\"", not_a_table),
        ("\"env:SECRET\"", not_a_table),
        ("1234", not_a_table),
        ("true", not_a_table),
        ("[\"hunter2\"]", not_a_table),
        ("2026-11-18", not_a_table),
        ("2026-11-18T10:00:00Z", not_a_table),
        (
            "{ env = 2026-11-18 }",
            "a secret reference's id must be a string",
        ),
        ("{}", not_one),
        ("{ env = \"A\", file = \"b\" }", not_one),
        (
            "{ aws-sm = \"arn\" }",
            "a secret reference's key must be env or file",
        ),
        ("{ env = 1234 }", "a secret reference's id must be a string"),
        (
            "{ env = [\"x\"] }",
            "a secret reference's id must be a string",
        ),
        (
            "{ env = { a = \"x\" } }",
            "a secret reference's id must be a string",
        ),
        (
            "{ file = \"\" }",
            "a secret reference's id must not be empty",
        ),
    ] {
        let text = okta_with(&format!("client_secret = {written}"));
        let error = Config::from_toml(&text)
            .err()
            .ok_or("a bad reference was accepted")?
            .to_string();
        assert!(error.contains(expected), "{written}: {error}");
    }
    Ok(())
}

#[test]
fn a_client_secret_file_is_taken_from_the_config_directory() -> TestResult {
    let dir = std::env::temp_dir();
    let text = okta_with("client_secret = { file = \"okta.secret\" }");
    let config = Config::from_text(&text, Some(&dir))?;
    let secret = trusted(&config, "okta")?.client_secret.as_ref();
    assert_eq!(
        secret.map(ToString::to_string),
        Some(file_ref(&dir.join("okta.secret"))?)
    );
    match Config::from_text(&text, None) {
        Err(ConfigError::Invalid(problems)) => assert_eq!(
            problems.0,
            [
                r#"issuer.signing.keys "k1" private_key must be an absolute path, since the config has no directory"#,
                "trusted_issuers.okta.client_secret must be an absolute path, since the config has no directory",
            ]
        ),
        other => return Err(format!("expected invalid, got {other:?}").into()),
    }
    let env = okta_with("client_secret = { env = \"OKTA\" }");
    let config = Config::from_text(&env, Some(&dir))?;
    assert_eq!(
        trusted(&config, "okta")?
            .client_secret
            .as_ref()
            .map(ToString::to_string),
        Some(r#"{ env = "OKTA" }"#.to_owned())
    );
    Ok(())
}

#[test]
fn a_secret_written_in_by_mistake_is_never_quoted() -> TestResult {
    let text = okta_with("client_secret = \"hunter2\"");
    let error = Config::from_toml(&text)
        .err()
        .ok_or("a raw secret was accepted")?
        .to_string();
    assert!(!error.contains("hunter2"), "{error}");
    assert!(error.contains("a secret must be a reference"), "{error}");
    assert!(error.contains("line 27"), "{error}");
    Ok(())
}

#[test]
fn a_reference_is_its_scheme_and_id() -> TestResult {
    let text = okta_with(r#"client_secret = { file = 'C:\keys\k1.pem' }"#);
    let config = Config::from_toml(&text)?;
    let reference = trusted(&config, "okta")?
        .client_secret
        .as_ref()
        .ok_or("no client_secret")?;
    assert_eq!(reference.scheme(), Scheme::File);
    assert_eq!(reference.id(), r"C:\keys\k1.pem");
    assert_eq!(reference.to_string(), r#"{ file = "C:\\keys\\k1.pem" }"#);
    let reference = SecretRef::new(Scheme::Env, "A:B")?;
    assert_eq!(reference.scheme(), Scheme::Env);
    assert_eq!(reference.id(), "A:B");
    assert_eq!(reference.to_string(), r#"{ env = "A:B" }"#);
    assert_eq!(
        SecretRef::new(Scheme::Env, "").err(),
        Some(SecretRefError::NoId)
    );
    Ok(())
}

#[test]
fn a_reference_from_another_format_is_refused_by_shape() {
    use serde::Deserialize;
    use serde::de::value::{Error, MapDeserializer, UnitDeserializer};
    let unit = SecretRef::deserialize(UnitDeserializer::<Error>::new());
    assert_eq!(
        unit.err().map(|error| error.to_string()),
        Some(NOT_A_REFERENCE.into())
    );
    let map = MapDeserializer::<_, Error>::new([("env", ())].into_iter());
    assert_eq!(
        SecretRef::deserialize(map)
            .err()
            .map(|error| error.to_string()),
        Some(NOT_A_REFERENCE.into())
    );
}

#[test]
fn a_long_number_written_in_by_mistake_is_never_quoted() -> TestResult {
    for written in [
        "99999999999999999999",
        "-99999999999999999999",
        "{ env = 99999999999999999999 }",
        "{ env = -99999999999999999999 }",
    ] {
        let text = okta_with(&format!("client_secret = {written}"));
        let error = Config::from_toml(&text)
            .err()
            .ok_or("a raw secret was accepted")?
            .to_string();
        assert!(!error.contains("99999"), "{written}: {error}");
    }
    Ok(())
}

/// Every shape a secret written in by mistake might take. The secret is
/// `SEKRET`, and no error may quote it.
const MISTAKES: [&str; 16] = [
    r#"client_secret = "SEKRET""#,
    r#"client_secret = "SEK\qRET""#,
    "client_secret = SEKRET",
    "client_secret = -SEKRET",
    "client_secret = 0xSEKRET",
    "client_secret = '''SEKRET\nmore'''\nclient_secret = 1",
    r#"client_secret = [ "SEKRET" ]"#,
    r#"client_secret = { SEKRET = "x" }"#,
    r#"client_secret = { env = "x", env = "SEKRET" }"#,
    r#"client_secret = { env = "x", SEKRET }"#,
    r#"client_secret = { env = { SEKRET = 1 } }"#,
    r#"client_secret = { "$__toml_private_datetime" = "SEKRET" }"#,
    "client_secret = 9999999999999999999999SEKRET",
    "client_secret = 1.5e300",
    "client_secret = 1979-05-27T07:32:00Z",
    "client_secret = { env = 1979-05-27 }",
];

#[test]
fn no_mistaken_secret_reaches_an_error() -> TestResult {
    for mistake in MISTAKES {
        let text = okta_with(mistake);
        let error = Config::from_toml(&text)
            .err()
            .ok_or("a mistaken secret was accepted")?
            .to_string();
        assert!(!error.contains("SEKRET"), "{mistake}\n{error}");
        assert!(!error.contains("1979"), "{mistake}\n{error}");
        assert!(!error.contains("1.5e300"), "{mistake}\n{error}");
    }
    Ok(())
}
