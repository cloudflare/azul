// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

// CT log configuration, in a separate crate to allow build.rs to use it.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
pub struct TemporalInterval {
    pub start_inclusive: DateTime<Utc>,
    pub end_exclusive: DateTime<Utc>,
}

#[derive(Deserialize, Debug)]
pub struct AppConfig {
    pub logging_level: Option<String>,
    pub logs: HashMap<String, LogParams>,
}

#[derive(Deserialize, Debug)]
pub struct LogParams {
    pub description: Option<String>,
    pub log_type: Option<String>,
    #[serde(default)]
    pub monitoring_url: String,
    pub submission_url: String,
    pub temporal_interval: TemporalInterval,
    pub location_hint: Option<String>,
    #[serde(default = "default_u64::<1000>")]
    pub sequence_interval_millis: u64,
    #[serde(default = "default_usize::<0>")]
    pub max_sequence_skips: usize,
    pub sequence_skip_threshold_millis: Option<u64>,
    #[serde(default = "default_u8::<8>")]
    pub num_batchers: u8,
    #[serde(default = "default_u64::<100>")]
    pub batch_timeout_millis: u64,
    #[serde(default = "default_usize::<256>")]
    pub max_batch_entries: usize,
    #[serde(default = "default_bool::<true>")]
    pub enable_dedup: bool,
    #[serde(default = "default_bool::<true>")]
    pub enable_ccadb_roots: bool,
    #[serde(default = "default_u64::<60>")]
    pub clean_interval_secs: u64,
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
