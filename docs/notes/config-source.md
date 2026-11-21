---
title: The config comes from a store and is swapped in whole
type: note
summary: A bootstrap file names the config source, a file read once at start; a store only fetches text, and the reloader validates it and builds whole state before serving it.
status: evolving
created: 2026-11-16
---

# The config comes from a store and is swapped in whole

Tsong reads its config through a store named in the bootstrap file. Today the only store is a file, read once at start. The reloader builds the whole runtime state from a config, validates it, and swaps it in at once. A config that fails validation never replaces the one being served.

To change the config, a pipeline runs `tsong check` and publishes the file, and Tsong reads it on its next start. [Roadmap](../../ROADMAP.md) item 32 plans a poll on file sources and stores in their own repositories.

## Bootstrap

Settings that say where the config lives can't live in that config. A bootstrap TOML file, deployed with the app, holds them, and `tsong serve <bootstrap.toml>` reads it.

```toml
[source]
store = "file"
path = "tsong.toml"                       # relative to this file

[admin]
listen = "0.0.0.0:8445"                   # GET /status and GET /metrics
```

A relative `path` is taken from the bootstrap file's directory. Unknown fields, tables and stores are errors.

## Fetching

A store implements the `ConfigStore` trait (`crates/tsong-config/src/store.rs`). `FileStore` is the only one. A store only fetches: it returns the config's text with a revision, a content ID, the author when known, and the directory relative `file` secret references resolve against, as `Fetched`. The reloader parses and validates it.

For a file store, the revision and the content ID are both a SHA-256 of the file, and the directory is the file's own. The revision is what `/status` and the audit log name. A reload compares the content ID, so a new revision with the same config rebuilds nothing. Because the reloader holds the revision and content ID before parsing, a config that fails is audited with both, and one content check covers both a config already served and one already rejected. A store with no directory makes a relative `file` reference fail validation.

Secrets never live in the config. A secret field holds a reference, a table naming one source: `{ env = "NAME" }` or `{ file = "path" }` today, and `{ aws-sm = "arn" }` once roadmap item 29 adds it.

## Reload

1. Fetch. If the content is the one being served, stop.
2. Parse and validate the config, load its signing keys, and build new state: route table, issuer, validator, gateway, downstream clients and an empty exchange cache.
3. On any failure, keep serving the old state and log why. A config rejected as invalid isn't rejected again until its content changes; a failed fetch or build is retried every time.
4. Otherwise send the new state on a `tokio::sync::watch` channel. Each request takes a snapshot of the state when it starts, so requests in flight finish on the old config.

`tsong serve` runs the first load before any listener is bound, and fails to start when it fails. The config is fetched only at start until roadmap item 32 adds a poll. Until then, the reload counts, the fetch time and `tip_rejected` stay fixed after start, and so do their metrics: `tsong_config_reloads_total`, `tsong_config_last_fetch_timestamp_seconds` and `tsong_config_tip_rejected`.

## Subscribers

Eight things react to a reload. Four are part of the state, so rebuilding it handles them: the exchange cache is cleared, cached JWKS are dropped, new signing keys are loaded, and clients for new read timeouts are built. The reloader (`crates/tsong/src/reload.rs`) handles the other four, because a failed reload produces no new state for a watcher to see:

- The audit log writes one JSON line to stdout for each load that swaps in a new revision and each failure: the time, revision, author, outcome, and the routes added, removed and changed, keyed by host. A fetch that finds the content being served writes nothing, though `/status` reports its revision. Collecting stdout belongs to the platform.
- `GET /status` on the admin listener reports the revision being served, when it loaded, when the store was last read, whether the newest config read was rejected, the count of reloads and failed reloads, and the last failure as a short reason: `fetch_failed`, `invalid_config` or `build_failed`. The detail stays in the audit log.
- The metrics are published from `/status` after each reload, so the two always agree. `tsong_config_last_fetch_timestamp_seconds` shows when the store was last read, `tsong_config_tip_rejected` shows a newest config that won't load, and `tsong_config_revision_info` shows which revision each replica serves. [[observability]] lists the metrics.
- A change to `issuer.listen` or `gateway.listen` is named in the audit line's `restart_required`. The old addresses stay bound until a restart.
