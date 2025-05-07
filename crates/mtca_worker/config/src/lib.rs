// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

// MTCA configuration, in a separate crate to allow build.rs to use it.
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize, Debug)]
pub struct AppConfig {
    pub logging_level: Option<String>,
    pub cas: HashMap<String, CaParams>,
}

#[derive(Deserialize, Debug)]
pub struct CaParams {
    pub description: Option<String>,
    pub evidence_policy: Option<String>,
    #[serde(default)]
    pub monitoring_url: String,
    pub origin_url: String,
    pub location_hint: Option<String>,
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    #[serde(default = "default_sequence_interval_seconds")]
    pub sequence_interval: u64,
    #[serde(default = "default_cert_lifetime_seconds")]
    pub cert_lifetime: u64,
}

// Limit on the number of entries per batch. Tune this parameter to avoid running into various size limitations.
// For instance, unexpectedly large leaves (e.g., with PQ signatures) could cause us to exceed the 128MB Workers memory limit. Storing 4000 10KB certificates is 40MB.
fn default_pool_size() -> usize {
    4000
}

fn default_sequence_interval_seconds() -> u64 {
    1
}

fn default_cert_lifetime_seconds() -> u64 {
    1_209_600 // two weeks
}
