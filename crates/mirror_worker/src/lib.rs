// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! A transparency-log mirror implementing [c2sp.org/tlog-mirror][mirror] on
//! Cloudflare Workers, specialized for MTC issuance logs.
//!
//! The per-environment configuration is validated and embedded at build
//! time (see `build.rs` and the [`config`] sub-crate). The HTTP entry
//! point lives in [`frontend_worker`].
//!
//! [mirror]: https://c2sp.org/tlog-mirror

use config::AppConfig;
use std::sync::LazyLock;

mod frontend_worker;

/// The compile-time-embedded worker configuration.
///
/// `build.rs` validates `config.<DEPLOY_ENV>.json` against the schema and
/// [`AppConfig::validate`], then stages it under `OUT_DIR/config.json`, so
/// this parse is infallible in a crate that compiled.
pub(crate) static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| {
    serde_json::from_str(include_str!(concat!(env!("OUT_DIR"), "/config.json")))
        .expect("config.json must be valid at build time")
});
