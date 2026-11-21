//! The admin listener's reload status and metrics, and the health
//! listener's checks. Each runs on its own listener with its own allow list.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use serde_json::json;

use crate::reload::Status;
use crate::telemetry::Metrics;

struct Admin {
    status: Arc<Mutex<Status>>,
    metrics: Arc<Metrics>,
}

/// `GET /status` and `GET /metrics`.
pub fn status_router(status: Arc<Mutex<Status>>, metrics: Arc<Metrics>) -> Router {
    Router::new()
        .route("/status", get(status_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(Arc::new(Admin { status, metrics }))
}

async fn status_handler(State(admin): State<Arc<Admin>>) -> Response {
    let status = admin
        .status
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    axum::Json(status).into_response()
}

/// The Prometheus text exposition format.
const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

async fn metrics_handler(State(admin): State<Arc<Admin>>) -> Response {
    match admin.metrics.encode() {
        Ok(text) => ([(header::CONTENT_TYPE, METRICS_CONTENT_TYPE)], text).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// `GET /health/live`, which answers 200 while the process runs, and
/// `GET /health/ready`, which answers 200 while `ready` is set: once the
/// listeners are bound, until shutdown begins. Otherwise it answers 503.
pub fn health_router(ready: Arc<AtomicBool>) -> Router {
    Router::new()
        .route(
            "/health/live",
            get(|| async { axum::Json(json!({ "live": true })) }),
        )
        .route("/health/ready", get(readiness))
        .with_state(ready)
}

async fn readiness(State(ready): State<Arc<AtomicBool>>) -> Response {
    if ready.load(Ordering::Acquire) {
        axum::Json(json!({ "ready": true })).into_response()
    } else {
        let body = json!({ "ready": false });
        (StatusCode::SERVICE_UNAVAILABLE, axum::Json(body)).into_response()
    }
}
