// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

// CT log configuration, in a separate crate to allow build.rs to use it.
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize, Debug)]
pub struct AppConfig {
    pub logging_level: Option<String>,
    pub logs: HashMap<String, LogParams>,
}

#[derive(Deserialize, Debug)]
pub struct LogParams {
    pub description: Option<String>,
    pub issuer_rdn: String,
    #[serde(default = "default_u64::<604_800>")]
    pub validity_interval_seconds: u64,
    #[serde(default)]
    pub monitoring_url: String,
    pub submission_url: String,
    pub location_hint: Option<String>,
    #[serde(default = "default_u64::<1000>")]
    pub sequence_interval_millis: u64,
    #[serde(default = "default_usize::<0>")]
    pub max_sequence_skips: usize,
    pub sequence_skip_threshold_millis: Option<u64>,
    #[serde(default = "default_u8::<8>")]
    pub num_batchers: u8,
    #[serde(default = "default_u64::<1000>")]
    pub batch_timeout_millis: u64,
    #[serde(default = "default_usize::<100>")]
    pub max_batch_entries: usize,
    #[serde(default = "default_bool::<true>")]
    pub enable_dedup: bool,
}

fn default_bool<const V: bool>() -> bool {
    V
}
fn default_u8<const V: u8>() -> u8 {
    V
}
fn default_u64<const V: u64>() -> u64 {
    V
}
fn default_usize<const V: usize>() -> usize {
    V
}
