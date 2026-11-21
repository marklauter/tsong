mod common;

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::TestResult;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use tsong::admin::status_router;
use tsong::reload::Status;

#[tokio::test]
async fn status_reports_the_reloads() -> TestResult {
    let status = Arc::new(Mutex::new(Status {
        revision: "r7".into(),
        loaded_at: 42,
        fetched_at: 50,
        reloads: 3,
        failed_reloads: 1,
        last_failure: Some("fetch_failed".into()),
        tip_rejected: false,
    }));
    let response = status_router(status, Arc::default())
        .oneshot(Request::get("/status").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        body,
        json!({
            "revision": "r7",
            "loaded_at": 42,
            "fetched_at": 50,
            "reloads": 3,
            "failed_reloads": 1,
            "last_failure": "fetch_failed",
            "tip_rejected": false,
        })
    );
    Ok(())
}
