// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! HTTP entry point for the mirror worker.
//!
//! Serves the root status route; unmatched routes return 404.

use crate::CONFIG;
use axum::{
    Router,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use tower_service::Service as _;
#[allow(clippy::wildcard_imports)]
use worker::*;

/// Entry point: initialize logging.
#[event(start)]
fn start() {
    let level = match CONFIG.logging_level.as_deref().unwrap_or("info") {
        "trace" => log::Level::Trace,
        "debug" => log::Level::Debug,
        "warn" => log::Level::Warn,
        "error" => log::Level::Error,
        _ => log::Level::Info,
    };
    console_error_panic_hook::set_once();
    let _ = console_log::init_with_level(level);
}

/// Top-level `#[event(fetch)]` handler. Delegates to the axum router;
/// unmatched routes return 404.
#[event(fetch, respond_with_errors)]
async fn fetch(
    req: HttpRequest,
    _env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    // `Router`'s `Service::Error` is `Infallible`; `?` performs the
    // trivial conversion into `worker::Error`.
    Ok(Router::new().route("/", get(root)).call(req).await?)
}

/// `GET /` -- mirror identity string. Convenience only; not part of the
/// spec.
async fn root() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{} - c2sp.org/tlog-mirror mirror\n", CONFIG.mirror_name),
    )
}
