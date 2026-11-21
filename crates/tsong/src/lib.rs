//! The `tsong` command: `check` validates a config, loads its keys and
//! reports its warnings; `serve` reads a bootstrap file, then runs the
//! gateway and the token exchange issuer.

pub mod admin;
pub mod allow;
pub mod reload;
pub mod state;
pub mod telemetry;

use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::watch;
use tsong_clock::{Clock, SystemClock};
use tsong_config::{
    Bootstrap, BootstrapError, ConfigError, ConfigStore, FileStore, Source, Warnings,
};
use tsong_gateway::GatewayError;
use tsong_keys::{KeyError, KeySet};
use tsong_secrets::Secrets;
use tsong_validate::{HttpFetcher, JwksFetcher};

use crate::reload::{Audit, Lines, Reloader};
use crate::state::State;
use crate::telemetry::{Metrics, ObservedFetcher};

/// How to run the command.
pub const USAGE: &str =
    "usage: tsong check [--deny-warnings] <config.toml> | tsong serve <bootstrap.toml>";

/// The flag that makes `check` fail on warnings.
pub const DENY_WARNINGS: &str = "--deny-warnings";

/// Why the command failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{USAGE}")]
    Usage,
    #[error(transparent)]
    Bootstrap(#[from] BootstrapError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Gateway(#[from] GatewayError),
    #[error("{0}warnings are denied")]
    Warnings(Warnings),
    #[error("serving: {0}")]
    Io(#[from] std::io::Error),
}

/// Runs the command for its arguments, without the program name, and
/// returns what to print.
pub async fn run(args: impl IntoIterator<Item = String>) -> Result<String, Error> {
    let args: Vec<_> = args.into_iter().collect();
    match args.as_slice() {
        [command, path] if command == "check" => check(Path::new(path), false).await,
        [command, flag, path] if command == "check" && flag == DENY_WARNINGS => {
            check(Path::new(path), true).await
        }
        [command, path] if command == "serve" => {
            serve_until(Path::new(path), shutdown_signal()).await?;
            Ok("stopped".into())
        }
        _ => Err(Error::Usage),
    }
}

/// Loads the config at `path` and its signing keys, and reports its
/// warnings. With `deny_warnings`, a warning fails the check.
pub async fn check(path: &Path, deny_warnings: bool) -> Result<String, Error> {
    let config = FileStore::new(path).load().await?.parse()?.config;
    let keys = KeySet::from_config(&config.issuer.signing, &Secrets::default()).await?;
    let warnings = config.warnings();
    if deny_warnings && !warnings.0.is_empty() {
        return Err(Error::Warnings(warnings));
    }
    let signers: Vec<_> = keys
        .active_keys()
        .map(|key| format!("{} {}", key.algorithm(), key.kid()))
        .collect();
    Ok(format!(
        "{warnings}{}: ok, signing with {}",
        path.display(),
        signers.join(", "),
    ))
}

/// Serves Tsong for the bootstrap file at `path` until `shutdown`
/// completes: the issuer on `issuer.listen`, the gateway on
/// `gateway.listen`, and the admin and health listeners when the
/// bootstrap file has them. The config is read once.
pub async fn serve_until(
    path: &Path,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), Error> {
    let bootstrap = Bootstrap::load(path)?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let store = store(&bootstrap.source);
    let metrics = Arc::new(Metrics::default());
    let audit: Arc<dyn Audit> = Arc::new(Lines::new(std::io::stdout()));
    let fetcher: Arc<dyn JwksFetcher> = Arc::new(ObservedFetcher::new(
        HttpFetcher::default(),
        metrics.jwks_failures.clone(),
        audit.clone(),
        clock.clone(),
    ));
    let secrets = Secrets::default();
    let first = State::build_with(
        store.load().await?.parse()?,
        clock.clone(),
        &metrics,
        audit.clone(),
        fetcher.clone(),
        &secrets,
    )
    .await?;
    let issuer_address = first.config.issuer.listen;
    let gateway_address = first.config.gateway.listen;
    let reloader = Arc::new(
        Reloader::new(store, first, audit, clock)
            .with_metrics(metrics.clone())
            .with_fetcher(fetcher)
            .with_secrets(secrets.clone()),
    );
    let admin = match &bootstrap.admin {
        Some(admin) => {
            let router = admin::status_router(reloader.status(), metrics).layer(
                axum::middleware::from_fn_with_state(reloader.subscribe(), allow::admit),
            );
            Some((TcpListener::bind(admin.listen).await?, router))
        }
        None => None,
    };
    let ready = Arc::new(AtomicBool::new(false));
    let health = match &bootstrap.health {
        Some(health) => {
            let router =
                admin::health_router(ready.clone()).layer(axum::middleware::from_fn_with_state(
                    Arc::new(health.allow.clone()),
                    allow::admit_peer,
                ));
            Some((TcpListener::bind(health.listen).await?, router))
        }
        None => None,
    };
    let issuer_listener = TcpListener::bind(issuer_address).await?;
    let gateway_listener = TcpListener::bind(gateway_address).await?;
    // The config is loaded and every listener is bound.
    ready.store(true, Ordering::Release);

    // One shutdown, heard by every server.
    let (stop, stopping) = watch::channel(false);
    let stopped = |mut stopping: watch::Receiver<bool>| async move {
        let _ = stopping.wait_for(|stop| *stop).await;
    };
    // On shutdown, readiness goes first, so the load balancer drains
    // Tsong before its listeners close. A second Ctrl+C or SIGTERM ends
    // the drain at once.
    let drain = bootstrap
        .health
        .as_ref()
        .map_or(Duration::ZERO, |health| health.drain);
    let signal = async move {
        shutdown.await;
        ready.store(false, Ordering::Release);
        tokio::select! {
            () = tokio::time::sleep(drain) => {}
            () = shutdown_signal() => {}
        }
        let _ = stop.send(true);
        Ok::<(), std::io::Error>(())
    };
    let issuer_server = axum::serve(
        issuer_listener,
        state::current(reloader.subscribe(), |state| &state.issuer)
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(stopped(stopping.clone()));
    let gateway_server = axum::serve(
        gateway_listener,
        state::current(reloader.subscribe(), |state| &state.gateway)
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(stopped(stopping.clone()));
    let admin_server = optional(admin, stopped(stopping.clone()));
    let health_server = optional(health, stopped(stopping));
    tokio::try_join!(
        signal,
        async { issuer_server.await },
        async { gateway_server.await },
        admin_server,
        health_server,
    )?;
    Ok(())
}

/// The store for `source`.
fn store(source: &Source) -> Box<dyn ConfigStore> {
    match source {
        Source::File { path } => Box::new(FileStore::new(path)),
    }
}

/// Serves `router` on `listener`, when there is one, until `stopped`.
async fn optional(
    server: Option<(TcpListener, axum::Router)>,
    stopped: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    match server {
        Some((listener, router)) => {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(stopped)
            .await
        }
        None => Ok(()),
    }
}

/// Completes on Ctrl+C, or on SIGTERM, which container runtimes send to
/// stop a container. A signal that can't be watched never completes it.
async fn shutdown_signal() {
    let interrupt = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        () = interrupt => {}
        () = terminate() => {}
    }
}

/// Completes on SIGTERM. Where there is no SIGTERM, or it can't be
/// watched, it never completes.
async fn terminate() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            terminate.recv().await;
            return;
        }
    }
    std::future::pending::<()>().await;
}
