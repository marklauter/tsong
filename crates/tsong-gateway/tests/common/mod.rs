//! The gateway under test: a config, a fake exchanger, and a fake
//! downstream that echoes each request it receives.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, Request};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use tower::ServiceExt;
use tsong_clock::ManualClock;
use tsong_config::Config;
use tsong_gateway::{ExchangeFuture, Exchanger, Gateway, GatewayMetrics};
use tsong_issuer::{ExchangeContext, ExchangeError, TokenResponse};

/// What a test returns: nothing, or why it failed.
pub type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

pub const NOW: u64 = 1_000_000;

pub const CONFIG: &str = r#"
[issuer]
url = "https://tsong.test"
listen = "127.0.0.1:0"
token_lifetime = "00:15:00"
clock_skew = "00:00:30"

[issuer.signing]
provider = "file"

[[issuer.signing.keys]]
kid = "tsong-1"
private_key = { file = "unused.pem" }
state = "active"

[gateway]
listen = "127.0.0.1:0"
trusted_proxies = ["10.0.0.0/24"]
allow = ["10.0.0.0/8", "::1/128"]

[gateway.cache]
max_entries = 100

[trusted_issuers.test]
sub_prefix = "test"
issuer = "https://issuer.test"
audiences = ["tsong"]
algorithms = ["ES256"]

[[routes]]
name = "orders"
host = "orders.test"
downstream = "https://orders-lb.test"
append_audience = "orders.test"
audiences = { allow = ["tsong"] }
allowed_scopes = ["orders.read"]

[[routes]]
name = "builds"
host = "builds.test"
downstream = "https://builds-lb.test"
append_audience = "builds.test"
audiences = { allow = ["tsong"] }
allowed_scopes = ["*"]
allow = ["10.1.0.0/16"]
"#;

/// A client address the gateway allows on every route.
pub const CLIENT: &str = "10.1.2.3:50000";

/// A JWT-shaped token with `exp` in its payload. Its header and signature
/// are placeholders: the gateway reads `exp` without verifying.
pub fn minted(name: &str, exp: u64) -> TestResult<String> {
    let payload = serde_json::to_vec(&json!({ "exp": exp, "name": name }))?;
    Ok(format!("h.{}.s", URL_SAFE_NO_PAD.encode(payload)))
}

/// An exchanger that records its calls and answers by inbound token:
/// `invalid`, `untargeted`, `unscoped`, `unavailable` and `broken` fail;
/// `opaque` mints an opaque token; `expiring` mints a token expiring now;
/// anything else mints a token valid for 15 minutes.
#[derive(Default)]
pub struct FakeExchanger {
    calls: Mutex<Vec<(String, String)>>,
    contexts: Mutex<Vec<ExchangeContext>>,
}

impl FakeExchanger {
    pub fn calls(&self) -> Vec<(String, String)> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The request context of each exchange, in order.
    pub fn contexts(&self) -> Vec<ExchangeContext> {
        self.contexts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn answer(token: &str, audience: &str) -> Result<TokenResponse, ExchangeError> {
        let response = |access_token: String, expires_in| TokenResponse {
            access_token,
            issued_token_type: tsong_issuer::ACCESS_TOKEN.into(),
            token_type: "Bearer".into(),
            expires_in,
            scope: None,
        };
        let server = |error: Box<dyn Error + Send + Sync>| ExchangeError::Server(error.to_string());
        match token {
            "invalid" => Err(ExchangeError::InvalidRequest("bad signature".into())),
            "untargeted" => Err(ExchangeError::InvalidTarget("audience not allowed".into())),
            "unscoped" => Err(ExchangeError::InvalidScope("scope not allowed".into())),
            "unavailable" => Err(ExchangeError::Unavailable("jwks down".into())),
            "broken" => Err(ExchangeError::Server("signing failed".into())),
            "opaque" => Ok(response("opaque-minted".into(), 600)),
            "expiring" => Ok(response(minted("expiring", NOW).map_err(server)?, 0)),
            _ => Ok(response(
                minted(&format!("{token}@{audience}"), NOW + 900).map_err(server)?,
                900,
            )),
        }
    }
}

impl Exchanger for FakeExchanger {
    fn exchange<'a>(
        &'a self,
        token: &'a str,
        audience: &'a str,
        context: &'a ExchangeContext,
    ) -> ExchangeFuture<'a> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((token.into(), audience.into()));
        self.contexts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(context.clone());
        Box::pin(async move { Self::answer(token, audience) })
    }
}

/// The request a fake downstream received, as JSON: its method, path and
/// query, headers (each name to its values) and body.
async fn echo(request: Request) -> Response {
    let (parts, body) = request.into_parts();
    if parts.uri.path() == "/stall" {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    if parts.uri.path() == "/teapot" {
        return (
            StatusCode::IM_A_TEAPOT,
            [("x-kind", "teapot")],
            "short and stout",
        )
            .into_response();
    }
    let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in &parts.headers {
        headers
            .entry(name.as_str().to_owned())
            .or_default()
            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
    }
    let body = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    let echoed = json!({
        "method": parts.method.as_str(),
        "path": parts.uri.path_and_query().map(|path| path.as_str()),
        "headers": headers,
        "body": body,
    });
    (
        [("x-echo", "yes"), ("keep-alive", "timeout=5")],
        axum::Json(echoed),
    )
        .into_response()
}

/// Starts a fake downstream on a free port and returns its address.
pub async fn downstream() -> TestResult<SocketAddr> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move { axum::serve(listener, Router::new().fallback(echo)).await });
    Ok(address)
}

pub struct Harness {
    pub router: Router,
    pub exchanger: Arc<FakeExchanger>,
    pub downstream: SocketAddr,
    pub metrics: Arc<GatewayMetrics>,
}

/// The config with every route forwarding to `downstream` over plain
/// HTTP, which config validation refuses but a test downstream needs.
pub fn config_to(downstream: &str) -> TestResult<Config> {
    let mut config = Config::from_toml(CONFIG)?;
    for route in &mut config.routes {
        route.downstream = downstream.parse()?;
    }
    Ok(config)
}

pub async fn harness() -> TestResult<Harness> {
    let address = downstream().await?;
    let config = config_to(&format!("http://{address}"))?;
    let exchanger = Arc::new(FakeExchanger::default());
    harness_with(&config, exchanger, address)
}

pub fn harness_with(
    config: &Config,
    exchanger: Arc<FakeExchanger>,
    downstream: SocketAddr,
) -> TestResult<Harness> {
    let clock = Arc::new(ManualClock::at(NOW));
    let metrics = Arc::new(GatewayMetrics::default());
    let gateway = Gateway::new(config, exchanger.clone(), clock, metrics.clone())?;
    Ok(Harness {
        router: tsong_gateway::router(Arc::new(gateway)),
        exchanger,
        downstream,
        metrics,
    })
}

/// A request to `host` and `path`, from `CLIENT`, with `token` as its
/// bearer token when there is one.
pub fn get(host: &str, path: &str, token: Option<&str>) -> TestResult<Request> {
    let mut builder = Request::get(path).header("host", host);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    from(CLIENT, builder.body(Body::empty())?)
}

/// `request` arriving on a connection from `peer`.
pub fn from(peer: &str, mut request: Request) -> TestResult<Request> {
    let peer: SocketAddr = peer.parse()?;
    request.extensions_mut().insert(ConnectInfo(peer));
    Ok(request)
}

/// What the gateway answered: status, headers and body.
pub struct Answer {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Answer {
    /// The echoed request, when the downstream answered with one.
    pub fn echoed(&self) -> TestResult<Value> {
        Ok(serde_json::from_str(&self.body)?)
    }

    /// The values the downstream received for header `name`.
    pub fn received(&self, name: &str) -> TestResult<Vec<String>> {
        let echoed = self.echoed()?;
        let values = echoed
            .get("headers")
            .and_then(|headers| headers.get(name))
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Ok(values)
    }

    /// The one value the downstream received for header `name`.
    pub fn received_one(&self, name: &str) -> TestResult<String> {
        match self.received(name)?.as_slice() {
            [value] => Ok(value.clone()),
            other => Err(format!("expected one {name}, got {other:?}").into()),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

/// Sends `request` through the gateway.
pub async fn send(h: &Harness, request: Request) -> TestResult<Answer> {
    let response = h.router.clone().oneshot(request).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    Ok(Answer {
        status,
        headers,
        body: String::from_utf8(bytes.to_vec())?,
    })
}
