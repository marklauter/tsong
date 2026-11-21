//! The global allow list as middleware, for listeners that have no route of
//! their own to check, such as the admin listener.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State as Extract};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ipnet::IpNet;
use tokio::sync::watch;
use tsong_config::{allowed, client_ip};

use crate::state::State;

/// Lets a request through only when its client, found through the trusted
/// proxies, is in `gateway.allow` of the config being served: 403 when it
/// isn't, 400 when a trusted proxy's `X-Forwarded-For` can't be read.
/// Serve the router with `into_make_service_with_connect_info::<SocketAddr>()`.
pub async fn admit(
    Extract(state): Extract<watch::Receiver<Arc<State>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let config = state.borrow().config.clone();
    let forwarded_for = request.headers().get_all("x-forwarded-for");
    let Some(client) = client_ip(
        peer.ip(),
        forwarded_for.iter().map(HeaderValue::as_bytes),
        &config.gateway.trusted_proxies,
    ) else {
        return (StatusCode::BAD_REQUEST, "malformed X-Forwarded-For\n").into_response();
    };
    if !allowed(client, &config.gateway.allow, None) {
        return (StatusCode::FORBIDDEN, "client address not allowed\n").into_response();
    }
    next.run(request).await
}

/// Lets a request through only when the connection's peer address is in
/// the list: 403 otherwise. No `X-Forwarded-For` is read, for a listener
/// whose callers connect directly, such as the health listener.
pub async fn admit_peer(
    Extract(allow): Extract<Arc<Vec<IpNet>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    if !allowed(peer.ip().to_canonical(), &allow, None) {
        return (StatusCode::FORBIDDEN, "client address not allowed\n").into_response();
    }
    next.run(request).await
}
