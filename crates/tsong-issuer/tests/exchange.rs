mod common;

use std::sync::Arc;

use common::*;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, Header};
use serde_json::{Map, Value, json};
use tsong_issuer::{ACCESS_TOKEN, ExchangeError, JWT, TOKEN_EXCHANGE, TokenRequest, TokenResponse};
use tsong_keys::{FileKey, KeyError, KeySet, SignFuture, SigningAlgorithm, SigningKey};
use tsong_validate::ValidateError;

/// The header and claims of a token Tsong minted, after verifying it
/// against the key its header names in Tsong's own JWKS, with the
/// algorithm that key publishes.
fn verified(h: &Harness, token: &str) -> TestResult<(Header, Map<String, Value>)> {
    let kid = jsonwebtoken::decode_header(token)?.kid;
    let jwks = h.issuer.jwks();
    let named = jwks
        .get("keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|key| key.get("kid").and_then(Value::as_str) == kid.as_deref())
        .cloned()
        .ok_or("no key in Tsong's JWKS has the token's kid")?;
    let algorithm: Algorithm = named
        .get("alg")
        .and_then(Value::as_str)
        .ok_or("the JWK has no alg")?
        .parse()?;
    let jwk: Jwk = serde_json::from_value(named)?;
    let key = DecodingKey::from_jwk(&jwk)?;
    let mut validation = jsonwebtoken::Validation::new(algorithm);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let data = jsonwebtoken::decode::<Map<String, Value>>(token, &key, &validation)?;
    Ok((data.header, data.claims))
}

/// The response to an exchange that must succeed, and its token's claims.
async fn exchanged(
    h: &Harness,
    request: TestResult<TokenRequest>,
) -> TestResult<(TokenResponse, Map<String, Value>)> {
    let response = h.issuer.exchange(request?).await?;
    let (_, claims) = verified(h, &response.access_token)?;
    Ok((response, claims))
}

/// The error an exchange that must fail returns.
async fn failure(h: &Harness, request: TestResult<TokenRequest>) -> TestResult<ExchangeError> {
    match h.issuer.exchange(request?).await {
        Ok(response) => Err(format!("expected a refusal, got {response:?}").into()),
        Err(error) => Ok(error),
    }
}

/// The OAuth error code and description of an exchange that must fail.
async fn refused(
    h: &Harness,
    request: TestResult<TokenRequest>,
) -> TestResult<(&'static str, String)> {
    let error = failure(h, request).await?;
    Ok((error.code(), error.to_string()))
}

/// `request` with `change` applied.
fn changed(
    request: TestResult<TokenRequest>,
    change: impl FnOnce(&mut TokenRequest),
) -> TestResult<TokenRequest> {
    let mut request = request?;
    change(&mut request);
    Ok(request)
}

#[tokio::test]
async fn a_subject_token_is_exchanged_for_the_route() -> TestResult {
    let h = harness()?;
    let response = h
        .issuer
        .exchange(request(&h, "orders.test", subject(json!({})))?)
        .await?;
    assert_eq!(response.issued_token_type, ACCESS_TOKEN);
    assert_eq!(response.token_type, "Bearer");
    assert_eq!(response.expires_in, 900);
    assert_eq!(response.scope.as_deref(), Some("orders.read orders.write"));

    let (header, claims) = verified(&h, &response.access_token)?;
    assert_eq!(header.kid.as_deref(), Some("tsong-1"));
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    for (name, value) in [
        ("iss", json!("https://tsong.test")),
        ("sub", json!("test:alice")),
        (
            "sub_id",
            json!({ "format": "iss_sub", "iss": "https://issuer.test", "sub": "alice" }),
        ),
        ("aud", json!(["tsong", "orders.test"])),
        ("iat", json!(NOW)),
        ("exp", json!(NOW + 900)),
        ("scope", json!("orders.read orders.write")),
        ("email", json!("alice@example.test")),
        ("groups", json!(["admins"])),
        ("user", json!("a-1")),
    ] {
        assert_eq!(claims.get(name), Some(&value), "{name}");
    }
    for absent in ["secret", "uid", "act"] {
        assert!(!claims.contains_key(absent), "{absent}");
    }
    assert_eq!(
        claims.get("jti").and_then(Value::as_str).map(str::len),
        Some(22)
    );
    assert_eq!(claims.len(), 11);
    Ok(())
}

#[tokio::test]
async fn each_token_gets_its_own_id() -> TestResult {
    let h = harness()?;
    let (_, first) = exchanged(&h, request(&h, "orders.test", subject(json!({})))).await?;
    let (_, second) = exchanged(&h, request(&h, "orders.test", subject(json!({})))).await?;
    assert!(first.contains_key("jti"));
    assert_ne!(first.get("jti"), second.get("jti"));
    Ok(())
}

#[tokio::test]
async fn a_token_lives_no_longer_than_its_subject() -> TestResult {
    let h = harness()?;
    let (response, claims) = exchanged(
        &h,
        request(&h, "orders.test", subject(json!({ "exp": NOW + 60 }))),
    )
    .await?;
    assert_eq!(response.expires_in, 60);
    assert_eq!(claims.get("exp"), Some(&json!(NOW + 60)));
    let (response, _) = exchanged(
        &h,
        request(&h, "orders.test", subject(json!({ "exp": NOW + 1 }))),
    )
    .await?;
    assert_eq!(response.expires_in, 1);
    Ok(())
}

#[tokio::test]
async fn a_subject_inside_its_skew_but_expired_is_refused() -> TestResult {
    let h = harness()?;
    for exp in [NOW, NOW - 10] {
        assert_eq!(
            refused(
                &h,
                request(&h, "orders.test", subject(json!({ "exp": exp })))
            )
            .await?,
            ("invalid_request", "the subject token has expired".into())
        );
    }
    Ok(())
}

#[tokio::test]
async fn requested_scopes_narrow_the_subjects() -> TestResult {
    let h = harness()?;
    let narrowed = changed(request(&h, "orders.test", subject(json!({}))), |r| {
        r.scope = Some("orders.write orders.read orders.write".into());
    });
    let (response, claims) = exchanged(&h, narrowed).await?;
    assert_eq!(response.scope.as_deref(), Some("orders.read orders.write"));
    assert_eq!(
        claims.get("scope"),
        Some(&json!("orders.read orders.write"))
    );

    let one = changed(request(&h, "orders.test", subject(json!({}))), |r| {
        r.scope = Some("orders.write".into());
    });
    let (response, _) = exchanged(&h, one).await?;
    assert_eq!(response.scope.as_deref(), Some("orders.write"));

    let widened = changed(
        request(
            &h,
            "orders.test",
            subject(json!({ "scope": "orders.read" })),
        ),
        |r| r.scope = Some("orders.read orders.write".into()),
    );
    assert_eq!(
        refused(&h, widened).await?,
        (
            "invalid_scope",
            r#"the subject token lacks scope "orders.write""#.into()
        )
    );
    Ok(())
}

#[tokio::test]
async fn a_route_s_required_scopes_must_all_be_held() -> TestResult {
    let h = harness()?;
    let all = subject(json!({ "scope": "orders.read billing.read orders.write" }));
    let (response, _) = exchanged(&h, request(&h, "billing.test", all)).await?;
    assert_eq!(
        response.scope.as_deref(),
        Some("billing.read orders.read orders.write")
    );

    for (scope, missing) in [
        (json!("orders.read"), "billing.read"),
        (json!("billing.read orders.write"), "orders.read"),
        (Value::Null, "orders.read"),
    ] {
        let claims = subject(json!({ "scope": scope }));
        assert_eq!(
            refused(&h, request(&h, "billing.test", claims)).await?,
            (
                "invalid_scope",
                format!(r#"route "billing" requires scope "{missing}""#)
            )
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_requested_scope_keeps_the_required_scopes() -> TestResult {
    let h = harness()?;
    let all = || subject(json!({ "scope": "orders.read billing.read orders.write" }));
    let kept = changed(request(&h, "billing.test", all()), |r| {
        r.scope = Some("billing.read orders.read".into());
    });
    let (response, _) = exchanged(&h, kept).await?;
    assert_eq!(response.scope.as_deref(), Some("billing.read orders.read"));

    let dropped = changed(request(&h, "billing.test", all()), |r| {
        r.scope = Some("orders.read orders.write".into());
    });
    assert_eq!(
        refused(&h, dropped).await?,
        (
            "invalid_scope",
            r#"the requested scope drops "billing.read", which route "billing" requires"#.into()
        )
    );

    // A token that never held the scope is told so, narrowed or not.
    let lacking = changed(
        request(
            &h,
            "billing.test",
            subject(json!({ "scope": "billing.read" })),
        ),
        |r| r.scope = Some("billing.read".into()),
    );
    assert_eq!(
        refused(&h, lacking).await?,
        (
            "invalid_scope",
            r#"route "billing" requires scope "orders.read""#.into()
        )
    );
    Ok(())
}

#[tokio::test]
async fn a_subject_without_scopes_gets_none() -> TestResult {
    let h = harness()?;
    let claims = subject(json!({ "scope": null }));
    let (response, claims) = exchanged(&h, request(&h, "orders.test", claims)).await?;
    assert_eq!(response.scope, None);
    assert!(!claims.contains_key("scope"));
    Ok(())
}

#[tokio::test]
async fn the_route_refuses_scopes_it_does_not_allow() -> TestResult {
    let h = harness()?;
    let claims = subject(json!({ "scope": "orders.read admin" }));
    assert_eq!(
        refused(&h, request(&h, "orders.test", claims)).await?,
        (
            "invalid_scope",
            r#"scope "admin" is not allowed for route "orders""#.into()
        )
    );
    let entra = subject(json!({ "scope": null, "scp": ["orders.read"] }));
    let (response, _) = exchanged(&h, request(&h, "orders.test", entra)).await?;
    assert_eq!(response.scope.as_deref(), Some("orders.read"));
    Ok(())
}

#[tokio::test]
async fn an_scp_item_must_be_a_single_scope() -> TestResult {
    let h = harness()?;
    // A route that accepts any scope would otherwise mint "a b" as two.
    for item in ["orders.read billing.read", "", "orders.read\tadmin"] {
        let claims = subject(json!({ "scope": null, "scp": ["orders.read", item] }));
        assert_eq!(
            refused(&h, request(&h, "open.test", claims)).await?,
            (
                "invalid_request",
                format!("the subject token's scope {item:?} is not a single scope")
            )
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_route_with_no_allowed_scopes_refuses_every_subject() -> TestResult {
    let h = harness()?;
    for scope in [json!("orders.read"), json!(null)] {
        let claims = subject(json!({ "scope": scope }));
        assert_eq!(
            refused(&h, request(&h, "closed.test", claims)).await?,
            ("invalid_scope", r#"route "closed" allows no scopes"#.into())
        );
    }
    Ok(())
}

#[tokio::test]
async fn the_subject_must_carry_an_audience_the_route_allows() -> TestResult {
    let h = harness()?;
    let claims = subject(json!({ "aud": ["api", "other"] }));
    assert_eq!(
        refused(&h, request(&h, "orders.test", claims)).await?,
        (
            "invalid_target",
            r#"none of the subject token's audiences is allowed for "orders.test""#.into()
        )
    );
    let claims = subject(json!({ "aud": ["tsong"] }));
    let (_, claims) = exchanged(&h, request(&h, "orders.test", claims)).await?;
    assert_eq!(claims.get("aud"), Some(&json!(["tsong", "orders.test"])));
    Ok(())
}

#[tokio::test]
async fn the_subject_may_carry_no_audience_outside_the_allowed_ones() -> TestResult {
    let h = harness()?;
    let claims = subject(json!({ "aud": ["tsong", "api"] }));
    assert_eq!(
        refused(&h, request(&h, "orders.test", claims)).await?,
        (
            "invalid_target",
            r#"the subject token's audience "api" is outside the audiences allowed for "orders.test""#
                .into()
        )
    );
    Ok(())
}

#[tokio::test]
async fn the_subject_must_carry_every_required_audience() -> TestResult {
    let h = harness()?;
    let claims = subject(json!({ "aud": ["api", "other"] }));
    assert_eq!(
        refused(&h, request(&h, "policy.test", claims)).await?,
        (
            "invalid_target",
            r#"the subject token lacks audience "tsong", which "policy.test" requires"#.into()
        )
    );
    Ok(())
}

#[tokio::test]
async fn the_subject_may_carry_no_denied_audience() -> TestResult {
    let h = harness()?;
    let claims = subject(json!({ "aud": ["tsong", "admin"] }));
    assert_eq!(
        refused(&h, request(&h, "policy.test", claims)).await?,
        (
            "invalid_target",
            r#"the subject token's audience "admin" is denied for "policy.test""#.into()
        )
    );
    let claims = subject(json!({ "aud": ["api", "tsong", "other"] }));
    let (_, claims) = exchanged(&h, request(&h, "policy.test", claims)).await?;
    assert_eq!(
        claims.get("aud"),
        Some(&json!(["api", "tsong", "other", "policy.test"])),
        "the minted token keeps the inbound audiences"
    );
    Ok(())
}

#[tokio::test]
async fn the_appended_audience_is_not_repeated() -> TestResult {
    let h = harness()?;
    let claims = subject(json!({ "aud": ["orders.test", "tsong"] }));
    let (_, claims) = exchanged(&h, request(&h, "orders.test", claims)).await?;
    assert_eq!(claims.get("aud"), Some(&json!(["orders.test", "tsong"])));
    Ok(())
}

#[tokio::test]
async fn a_star_route_accepts_any_audience_and_scope_and_appends_nothing() -> TestResult {
    let h = harness()?;
    let claims = subject(json!({ "aud": "api", "scope": "admin root" }));
    let (response, claims) = exchanged(&h, request(&h, "open.test", claims)).await?;
    assert_eq!(response.scope.as_deref(), Some("admin root"));
    assert_eq!(claims.get("aud"), Some(&json!(["api"])));
    Ok(())
}

#[tokio::test]
async fn the_audience_names_a_route_host_without_regard_to_case() -> TestResult {
    let h = harness()?;
    exchanged(&h, request(&h, "ORDERS.test", subject(json!({})))).await?;
    assert_eq!(
        refused(&h, request(&h, "nowhere", subject(json!({})))).await?,
        ("invalid_target", r#"no route has host "nowhere""#.into())
    );
    Ok(())
}

#[tokio::test]
async fn every_trusted_issuer_may_exchange_for_every_route() -> TestResult {
    let h = harness()?;
    let other = subject(json!({ "iss": "https://other.test", "oid": "object-7" }));
    let (_, claims) = exchanged(&h, request(&h, "orders.test", other)).await?;
    assert_eq!(claims.get("aud"), Some(&json!(["tsong", "orders.test"])));
    Ok(())
}

#[tokio::test]
async fn each_issuer_prefixes_its_own_subjects() -> TestResult {
    let h = harness()?;
    let (_, claims) = exchanged(&h, request(&h, "orders.test", subject(json!({})))).await?;
    assert_eq!(claims.get("sub"), Some(&json!("test:alice")));
    let other = subject(json!({ "iss": "https://other.test", "oid": "object-7" }));
    let (_, claims) = exchanged(&h, request(&h, "orders.test", other)).await?;
    assert_eq!(claims.get("sub"), Some(&json!("other:object-7")));
    Ok(())
}

#[tokio::test]
async fn a_renamed_claim_supplies_the_subject_and_sub_id_keeps_the_original() -> TestResult {
    let h = harness()?;
    let other = subject(json!({ "iss": "https://other.test", "oid": "object-7" }));
    let (_, claims) = exchanged(&h, request(&h, "orders.test", other)).await?;
    assert_eq!(claims.get("sub"), Some(&json!("other:object-7")));
    assert_eq!(
        claims.get("sub_id"),
        Some(&json!({ "format": "iss_sub", "iss": "https://other.test", "sub": "alice" }))
    );
    Ok(())
}

#[tokio::test]
async fn a_token_without_its_renamed_subject_is_refused() -> TestResult {
    let h = harness()?;
    for oid in [Value::Null, json!(7), json!("")] {
        let other = subject(json!({ "iss": "https://other.test", "oid": oid }));
        assert_eq!(
            refused(&h, request(&h, "orders.test", other)).await?,
            (
                "invalid_request",
                "the subject token has no oid, which supplies its subject".into()
            )
        );
    }
    Ok(())
}

#[tokio::test]
async fn renames_apply_only_to_their_issuer() -> TestResult {
    let h = harness()?;
    let (_, claims) = exchanged(
        &h,
        request(&h, "orders.test", subject(json!({ "oid": "object-7" }))),
    )
    .await?;
    assert_eq!(claims.get("sub"), Some(&json!("test:alice")));
    let other = subject(json!({ "iss": "https://other.test", "oid": "object-7" }));
    let (_, claims) = exchanged(&h, request(&h, "orders.test", other)).await?;
    assert!(!claims.contains_key("user"));
    Ok(())
}

#[tokio::test]
async fn a_subject_is_required() -> TestResult {
    let h = harness()?;
    for changes in [
        json!({ "sub": null }),
        json!({ "sub": 7 }),
        json!({ "sub": "" }),
        json!({ "iss": "https://other.test", "oid": "object-7", "sub": null }),
    ] {
        assert_eq!(
            refused(&h, request(&h, "orders.test", subject(changes))).await?,
            ("invalid_request", "the subject token has no sub".into())
        );
    }
    Ok(())
}

#[tokio::test]
async fn the_request_must_be_a_token_exchange() -> TestResult {
    let h = harness()?;
    for grant_type in [None, Some("client_credentials".to_string())] {
        let request = changed(request(&h, "orders.test", subject(json!({}))), |r| {
            r.grant_type = grant_type;
        });
        assert_eq!(
            refused(&h, request).await?,
            (
                "unsupported_grant_type",
                "only token exchange is supported".into()
            )
        );
    }
    Ok(())
}

/// A change that makes a request malformed.
type Change = fn(&mut TokenRequest);

#[tokio::test]
async fn malformed_requests_are_invalid() -> TestResult {
    let h = harness()?;
    let cases: Vec<(Change, &str)> = vec![
        (
            |r| r.actor_token = Some("actor".into()),
            "actor tokens are not supported yet",
        ),
        (
            |r| r.actor_token_type = Some(JWT.into()),
            "actor tokens are not supported yet",
        ),
        (
            |r| r.resource = Some("https://orders.internal.test".into()),
            "resource is not supported; name the audience",
        ),
        (|r| r.subject_token = None, "subject_token is required"),
        (
            |r| r.subject_token_type = None,
            "subject_token_type is required",
        ),
        (
            |r| r.subject_token_type = Some("urn:ietf:params:oauth:token-type:id_token".into()),
            "subject_token_type must be an access token or a JWT",
        ),
        (
            |r| r.requested_token_type = Some("urn:ietf:params:oauth:token-type:saml2".into()),
            "requested_token_type must be an access token or a JWT",
        ),
        (|r| r.audience = None, "audience is required"),
    ];
    for (change, expected) in cases {
        let request = changed(request(&h, "orders.test", subject(json!({}))), change);
        assert_eq!(
            refused(&h, request).await?,
            ("invalid_request", expected.into())
        );
    }
    Ok(())
}

#[tokio::test]
async fn jwt_token_types_are_accepted() -> TestResult {
    let h = harness()?;
    let jwt = changed(request(&h, "orders.test", subject(json!({}))), |r| {
        r.subject_token_type = Some(JWT.into());
        r.requested_token_type = Some(JWT.into());
    });
    exchanged(&h, jwt).await?;
    let access = changed(request(&h, "orders.test", subject(json!({}))), |r| {
        r.requested_token_type = Some(ACCESS_TOKEN.into());
    });
    exchanged(&h, access).await?;
    Ok(())
}

#[tokio::test]
async fn validation_failures_map_to_oauth_errors() -> TestResult {
    let h = harness()?;
    let expired = subject(json!({ "exp": NOW - 3600 }));
    assert_eq!(
        refused(&h, request(&h, "orders.test", expired)).await?,
        ("invalid_request", "the token has expired".into())
    );

    let opaque = changed(request(&h, "orders.test", subject(json!({}))), |r| {
        r.subject_token = Some("opaque".into());
    });
    assert_eq!(refused(&h, opaque).await?.0, "invalid_request");

    // A fresh issuer, with no keys cached yet.
    let h = harness()?;
    h.fetcher.fail(true);
    let error = failure(&h, request(&h, "orders.test", subject(json!({})))).await?;
    assert_eq!(error.code(), "temporarily_unavailable");
    assert_eq!(error.status(), 503);
    Ok(())
}

/// A key whose signer is down.
struct BrokenKey;

impl SigningKey for BrokenKey {
    fn kid(&self) -> &str {
        "broken"
    }
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::ES256
    }
    fn public_jwk(&self) -> Value {
        json!({ "kid": "broken" })
    }
    fn sign<'a>(&'a self, _: &'a [u8]) -> SignFuture<'a> {
        Box::pin(async { Err(KeyError::NoActiveKey) })
    }
}

#[tokio::test]
async fn a_signing_failure_is_a_server_error() -> TestResult {
    let h = harness_with_keys(KeySet::new(vec![Arc::new(BrokenKey)], vec![])?)?;
    let error = failure(&h, request(&h, "orders.test", subject(json!({})))).await?;
    assert!(matches!(error, ExchangeError::Server(_)));
    assert_eq!(error.code(), "server_error");
    assert_eq!(error.status(), 500);
    assert_eq!(error.to_string(), "signing: no key is active");
    Ok(())
}

#[test]
fn unsupported_validation_is_an_invalid_request() {
    let error = ExchangeError::from(ValidateError::Unsupported("introspection"));
    assert_eq!(error.code(), "invalid_request");
    assert_eq!(error.to_string(), "introspection is not supported yet");
}

#[test]
fn error_codes_and_statuses() {
    for (error, code, status) in [
        (
            ExchangeError::UnsupportedGrantType,
            "unsupported_grant_type",
            400,
        ),
        (
            ExchangeError::InvalidRequest(String::new()),
            "invalid_request",
            400,
        ),
        (
            ExchangeError::InvalidTarget(String::new()),
            "invalid_target",
            400,
        ),
        (
            ExchangeError::InvalidScope(String::new()),
            "invalid_scope",
            400,
        ),
        (ExchangeError::AccessDenied, "access_denied", 403),
        (
            ExchangeError::Unavailable(String::new()),
            "temporarily_unavailable",
            503,
        ),
        (ExchangeError::Server(String::new()), "server_error", 500),
    ] {
        assert_eq!((error.code(), error.status()), (code, status));
    }
}

#[test]
fn discovery_names_the_endpoints() -> TestResult {
    let h = harness()?;
    assert_eq!(
        h.issuer.discovery(),
        json!({
            "issuer": "https://tsong.test",
            "jwks_uri": "https://tsong.test/jwks.json",
            "token_endpoint": "https://tsong.test/token",
            "grant_types_supported": [TOKEN_EXCHANGE],
        })
    );
    let kid = h
        .issuer
        .jwks()
        .get("keys")
        .and_then(|keys| keys.get(0))
        .and_then(|key| key.get("kid"))
        .cloned();
    assert_eq!(kid, Some(json!("tsong-1")));
    Ok(())
}

/// A route signing RS256, beside the harness's routes on the default.
const LEDGER: &str = r#"
[[routes]]
name = "ledger"
host = "ledger.test"
downstream = "https://ledger-lb.test"
append_audience = "ledger.test"
audiences = { allow = ["tsong"] }
allowed_scopes = ["*"]
signing_algorithm = "RS256"

[[issuer.signing.keys]]
kid = "tsong-rs"
algorithm = "RS256"
private_key = { file = "unused.pem" }
state = "active"
"#;

fn rsa_key(kid: &str) -> TestResult<Arc<dyn SigningKey>> {
    use aws_lc_rs::encoding::AsDer;
    let pair = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
        .map_err(|_| "generating an RSA key")?;
    let der = pair.as_der().map_err(|_| "encoding an RSA key")?;
    let pem = pem::encode(&pem::Pem::new("PRIVATE KEY", der.as_ref()));
    Ok(Arc::new(FileKey::from_pem(
        kid,
        SigningAlgorithm::RS256,
        &pem,
    )?))
}

fn es256_key() -> TestResult<Arc<dyn SigningKey>> {
    Ok(Arc::new(FileKey::from_pem(
        "tsong-1",
        SigningAlgorithm::ES256,
        &tsong_validate::testkit::pem(5)?,
    )?))
}

#[tokio::test]
async fn each_route_signs_with_its_algorithm() -> TestResult {
    let keys = KeySet::new(vec![es256_key()?, rsa_key("tsong-rs")?], vec![])?;
    let h = harness_with_config(&format!("{CONFIG}{LEDGER}"), keys)?;
    for (host, alg, kid) in [
        ("ledger.test", Algorithm::RS256, "tsong-rs"),
        ("orders.test", Algorithm::ES256, "tsong-1"),
    ] {
        let response = h
            .issuer
            .exchange(request(&h, host, subject(json!({})))?)
            .await?;
        let (header, claims) = verified(&h, &response.access_token)?;
        assert_eq!(header.alg, alg, "{host}");
        assert_eq!(header.kid.as_deref(), Some(kid), "{host}");
        assert_eq!(claims.get("aud"), Some(&json!(["tsong", host])), "{host}");
    }
    Ok(())
}

#[tokio::test]
async fn a_route_without_an_active_key_for_its_algorithm_is_a_server_error() -> TestResult {
    let keys = KeySet::new(vec![es256_key()?], vec![])?;
    let h = harness_with_config(&format!("{CONFIG}{LEDGER}"), keys)?;
    assert_eq!(
        refused(&h, request(&h, "ledger.test", subject(json!({})))).await?,
        (
            "server_error",
            r#"no active key signs RS256, which route "ledger" uses"#.into()
        )
    );
    Ok(())
}
