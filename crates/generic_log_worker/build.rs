// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

// Build script to include per-environment configuration and trusted roots.

fn main() {
    let env = std::env::var("DEPLOY_ENV").unwrap_or_else(|_| "dev".to_string());
    // Make DEPLOY_ENV available at compile time via env!()
    println!("cargo::rustc-env=DEPLOY_ENV={env}");
    println!("cargo::rerun-if-env-changed=DEPLOY_ENV");
}
