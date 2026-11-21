mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use common::*;
use tokio::sync::watch;
use tower::ServiceExt;
use tsong::allow::admit;
use tsong::state::State;
use tsong_clock::{Clock, ManualClock};

/// State for a config allowing `allow` through `trusted_proxies`.
async fn state(
    key: &std::path::Path,
    allow: &str,
    trusted_proxies: &str,
) -> TestResult<Arc<State>> {
    let text = config_text(key, "https://one.test", 8444, "").replace(
        r#"allow = ["127.0.0.0/8"]"#,
        &format!("allow = {allow}\ntrusted_proxies = {trusted_proxies}"),
    );
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::at(NOW));
    Ok(Arc::new(State::build(snapshot(&text, "r1")?, clock).await?))
}

fn guarded(state: watch::Receiver<Arc<State>>) -> Router {
    Router::new()
        .route("/", get(|| async { "inside" }))
        .layer(axum::middleware::from_fn_with_state(state, admit))
}

/// The status for a request from `peer` with an `X-Forwarded-For` value.
async fn status(
    router: &Router,
    peer: &str,
    forwarded_for: Option<&str>,
) -> TestResult<StatusCode> {
    let mut request = Request::get("/");
    if let Some(value) = forwarded_for {
        request = request.header("x-forwarded-for", value);
    }
    let mut request = request.body(Body::empty())?;
    let peer: SocketAddr = peer.parse()?;
    request.extensions_mut().insert(ConnectInfo(peer));
    Ok(router.clone().oneshot(request).await?.status())
}

#[tokio::test]
async fn only_clients_in_the_global_allow_list_get_through() -> TestResult {
    let dir = tempfile::tempdir()?;
    let key = write_key(dir.path())?;
    let (_sender, receiver) = watch::channel(state(&key, r#"["10.1.0.0/16"]"#, "[]").await?);
    let router = guarded(receiver);
    assert_eq!(status(&router, "10.1.2.3:1", None).await?, StatusCode::OK);
    assert_eq!(
        status(&router, "[::ffff:10.1.2.3]:1", None).await?,
        StatusCode::OK
    );
    assert_eq!(
        status(&router, "10.2.0.1:1", None).await?,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(&router, "10.2.0.1:1", Some("10.1.2.3")).await?,
        StatusCode::FORBIDDEN,
        "an untrusted peer's X-Forwarded-For is ignored"
    );
    Ok(())
}

#[tokio::test]
async fn a_trusted_proxy_forwards_the_client() -> TestResult {
    let dir = tempfile::tempdir()?;
    let key = write_key(dir.path())?;
    let (_sender, receiver) =
        watch::channel(state(&key, r#"["10.1.0.0/16"]"#, r#"["10.0.0.0/24"]"#).await?);
    let router = guarded(receiver);
    assert_eq!(
        status(&router, "10.0.0.5:1", Some("10.1.2.3")).await?,
        StatusCode::OK
    );
    assert_eq!(
        status(&router, "10.0.0.5:1", Some("10.2.0.1")).await?,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(&router, "10.0.0.5:1", Some("not-an-ip")).await?,
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[tokio::test]
async fn a_reload_changes_who_gets_through() -> TestResult {
    let dir = tempfile::tempdir()?;
    let key = write_key(dir.path())?;
    let (sender, receiver) = watch::channel(state(&key, r#"["10.1.0.0/16"]"#, "[]").await?);
    let router = guarded(receiver);
    assert_eq!(status(&router, "10.1.2.3:1", None).await?, StatusCode::OK);
    sender.send_replace(state(&key, r#"["10.9.0.0/16"]"#, "[]").await?);
    assert_eq!(
        status(&router, "10.1.2.3:1", None).await?,
        StatusCode::FORBIDDEN
    );
    assert_eq!(status(&router, "10.9.0.1:1", None).await?, StatusCode::OK);
    Ok(())
}

/// A router admitting only peers in `allow`.
fn peer_guarded(allow: &[&str]) -> TestResult<Router> {
    let allow: Vec<ipnet::IpNet> = allow
        .iter()
        .map(|net| net.parse())
        .collect::<Result<_, _>>()?;
    Ok(Router::new().route("/", get(|| async { "inside" })).layer(
        axum::middleware::from_fn_with_state(Arc::new(allow), tsong::allow::admit_peer),
    ))
}

#[tokio::test]
async fn a_peer_list_admits_only_its_own_peers() -> TestResult {
    let router = peer_guarded(&["192.30.252.0/22"])?;
    assert_eq!(
        status(&router, "192.30.252.10:1", None).await?,
        StatusCode::OK
    );
    assert_eq!(
        status(&router, "[::ffff:192.30.252.10]:1", None).await?,
        StatusCode::OK
    );
    assert_eq!(
        status(&router, "10.1.2.3:1", None).await?,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(&router, "10.1.2.3:1", Some("192.30.252.10")).await?,
        StatusCode::FORBIDDEN,
        "X-Forwarded-For is never read"
    );
    let closed = peer_guarded(&[])?;
    assert_eq!(
        status(&closed, "192.30.252.10:1", None).await?,
        StatusCode::FORBIDDEN
    );
    Ok(())
}
