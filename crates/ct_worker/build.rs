// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

// Build script to include per-environment configuration and trusted roots.

use chrono::Months;
use config::AppConfig;
use serde_json::from_str;
use std::env;
use std::fs;
use url::Url;
use x509_cert::Certificate;

fn main() {
    let env = env::var("DEPLOY_ENV").unwrap_or_else(|_| "dev".to_string());
    let config_file = &format!("config.{env}.json");
    let config_contents = &fs::read_to_string(config_file).unwrap_or_else(|e| {
        panic!("failed to read config file '{config_file}': {e}");
    });

    // Validate the config json against the schema.
    let json = from_str(config_contents).unwrap_or_else(|e| {
        panic!("failed to deserialize JSON config '{config_file}': {e}");
    });
    let schema = from_str(include_str!("config.schema.json")).unwrap_or_else(|e| {
        panic!("failed to deserialize JSON schema 'config.schema.json': {e}");
    });
    jsonschema::validate(&schema, &json).unwrap_or_else(|e| {
        panic!("config '{config_file}' does not match schema 'config.schema.json': {e}");
    });

    // Validate the config parameters.
    let conf = serde_json::from_str::<AppConfig>(config_contents).unwrap_or_else(|e| {
        panic!("failed to deserialize JSON config '{config_file}': {e}");
    });
    for (name, params) in conf.logs {
        // Chrome's CT policy (https://googlechrome.github.io/CertificateTransparency/log_policy.html) states:
        // "The certificate expiry ranges for CT Logs must be no longer than one calendar year and should be no shorter than six months."
        assert!(
            (params.temporal_interval.start_inclusive + Months::new(6)
                ..=params.temporal_interval.start_inclusive + Months::new(12))
                .contains(&params.temporal_interval.end_exclusive),
            "{name} invalid temporal interval: [{}, {})",
            params.temporal_interval.start_inclusive,
            params.temporal_interval.end_exclusive
        );
        // Valid location hints: https://developers.cloudflare.com/durable-objects/reference/data-location/#supported-locations-1
        if let Some(location) = &params.location_hint {
            assert!(
                ["wnam", "enam", "sam", "weur", "eeur", "apac", "oc", "afr", "me",]
                    .contains(&location.as_str()),
                "{name} invalid location hint: {location}"
            );
        }

        check_url(&params.submission_url);
        if !params.monitoring_url.is_empty() {
            check_url(&params.monitoring_url);
        }
    }

    // Get and validate roots. Use 'default_roots.pem' if no environment-specific roots file is found.
    let mut roots_file: &str = &format!("roots.{env}.pem");
    if !fs::exists(roots_file).expect("failed to check if file exists") {
        roots_file = "default_roots.pem";
    }
    let roots =
        Certificate::load_pem_chain(&fs::read(roots_file).expect("failed to read roots file"))
            .expect("unable to decode certificates");
    assert!(roots.len() > 50, "Roots file has too few entries");

    // Copy to OUT_DIR.
    let out_dir = env::var("OUT_DIR").unwrap();
    fs::copy(config_file, format!("{out_dir}/config.json")).expect("failed to copy config file");
    fs::copy(roots_file, format!("{out_dir}/roots.pem")).expect("failed to copy roots file");

    println!("cargo::rerun-if-env-changed=DEPLOY_ENV");
    println!("cargo::rerun-if-changed=config.schema.json");
    println!("cargo::rerun-if-changed={config_file}");
    println!("cargo::rerun-if-changed={roots_file}");
}

// Validate the URL prefix according to https://datatracker.ietf.org/doc/html/rfc6962#section-4.
// "The <log server> prefix can include a path as well as a server name and a port."
fn check_url(s: &str) {
    let u = Url::parse(s).unwrap();
    assert!(["http", "https"].contains(&u.scheme()), "invalid scheme");
    assert!(u.domain().is_some(), "invalid domain");
    assert_eq!(
        u.as_str(),
        &format!("{}{}", u.origin().ascii_serialization(), u.path()),
        "invalid URL components"
    );
}
