// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

// Build script to include per-environment witness configuration.

use config::AppConfig;
use std::env;
use std::fs;

fn main() {
    let env = env::var("DEPLOY_ENV").unwrap_or_else(|_| "dev".to_string());
    let config_file = &format!("config.{env}.json");
    let config_contents = &fs::read_to_string(config_file).unwrap_or_else(|e| {
        panic!("failed to read config file '{config_file}': {e}");
    });

    // Validate the config JSON against the schema.
    let json = serde_json::from_str(config_contents).unwrap_or_else(|e| {
        panic!("failed to deserialize JSON config '{config_file}': {e}");
    });
    let schema = serde_json::from_str(include_str!("config.schema.json")).unwrap_or_else(|e| {
        panic!("failed to deserialize JSON schema 'config.schema.json': {e}");
    });
    jsonschema::validate(&schema, &json).unwrap_or_else(|e| {
        panic!("config '{config_file}' does not match schema 'config.schema.json': {e}");
    });

    // Deserialize to the strongly-typed config; this catches type/shape errors
    // that the JSON Schema may not.
    //
    // Note: there is no need for a separate "duplicate origin" check here.
    // Origins are the keys of `AppConfig.logs`, so duplicates are duplicate
    // JSON object keys, which `serde_json` rejects at deserialization time.
    let app_config: AppConfig = serde_json::from_str(config_contents).unwrap_or_else(|e| {
        panic!("failed to parse '{config_file}' as AppConfig: {e}");
    });

    // Run the canonical validation defined in the config crate. This
    // covers signed-note key-name constraints on `witness_name` and
    // every log origin, plus Ed25519 SPKI parsing and `(name, key_id)`
    // collision detection on `log_public_keys`. Failures surface as
    // build errors with operator-readable messages.
    app_config.validate().unwrap_or_else(|e| {
        panic!("config '{config_file}' failed validation: {e}");
    });

    // Copy to OUT_DIR for include_str! at compile time.
    let out_dir = env::var("OUT_DIR").unwrap();
    fs::copy(config_file, format!("{out_dir}/config.json")).expect("failed to copy config file");

    // Make DEPLOY_ENV available at compile time via env!()
    println!("cargo::rustc-env=DEPLOY_ENV={env}");

    println!("cargo::rerun-if-env-changed=DEPLOY_ENV");
    println!("cargo::rerun-if-changed=config.schema.json");
    println!("cargo::rerun-if-changed={config_file}");
}
