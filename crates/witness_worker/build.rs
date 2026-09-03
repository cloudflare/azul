// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

// Build script to include per-environment witness configuration.

use config::AppConfig;

fn main() {
    let loaded = worker_build_config::load::<AppConfig>(include_str!("config.schema.json"));

    // Run the canonical validation defined in the config crate. This
    // covers signed-note key-name constraints on `witness_name` and
    // every log origin, plus Ed25519 SPKI parsing and `(name, key_id)`
    // collision detection on `log_public_keys`. Failures surface as
    // build errors with operator-readable messages.
    loaded.config.validate().unwrap_or_else(|e| {
        panic!("witness worker config failed validation: {e}");
    });
    loaded.stage();
}
