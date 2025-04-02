// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

// Build script to include per-environment configuration and trusted roots.

use serde_json::from_str;
use std::env;
use std::fs;

fn main() {
    let env = env::var("DEPLOY_ENV").unwrap_or_else(|_| "dev".to_string());

    // Get and validate config.
    // TODO move AppConfig to a separate crate so we can validate the config contents here (e.g. temporal interval).
    let config_file = &format!("config.{env}.json");
    let config_contents = &fs::read_to_string(config_file).unwrap_or_else(|e| {
        panic!("failed to read config file '{config_file}': {e}");
    });
    let json = from_str(config_contents).unwrap_or_else(|e| {
        panic!("failed to deserialize JSON config '{config_file}': {e}");
    });
    let schema = from_str(include_str!("config.schema.json")).unwrap_or_else(|e| {
        panic!("failed to deserialize JSON schema 'config.schema.json': {e}");
    });
    jsonschema::validate(&schema, &json).unwrap_or_else(|e| {
        panic!("config '{config_file}' does not match schema 'config.schema.json': {e}");
    });

    // Get and validate roots. Use 'default_roots.pem' if no environment-specific roots file is found.
    let mut roots_file: &str = &format!("roots.{env}.pem");
    if !fs::exists(roots_file).expect("Cannot check if file exists") {
        roots_file = "default_roots.pem";
    }
    let roots =
        static_ct_api::load_pem_chain(&fs::read(roots_file).expect("Failed to read roots file"))
            .expect("Unable to decode certificates");
    assert!(!roots.is_empty(), "Roots file is empty");

    // Copy to OUT_DIR.
    let out_dir = env::var("OUT_DIR").unwrap();
    fs::copy(config_file, format!("{out_dir}/config.json")).expect("Failed to copy config file");
    fs::copy(roots_file, format!("{out_dir}/roots.pem")).expect("Failed to copy roots file");

    println!("cargo::rerun-if-env-changed=DEPLOY_ENV");
    println!("cargo::rerun-if-changed={config_file}");
    println!("cargo::rerun-if-changed={roots_file}");
}
