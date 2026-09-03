// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Build script to include per-environment mirror configuration.

use config::AppConfig;

fn main() {
    let loaded = worker_build_config::load::<AppConfig>(include_str!("config.schema.json"));

    // Run the canonical validation defined in the config crate. Failures
    // surface as build errors with operator-readable messages.
    loaded.config.validate().unwrap_or_else(|e| {
        panic!("mirror worker config failed validation: {e}");
    });
    loaded.stage();
}
