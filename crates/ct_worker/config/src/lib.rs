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
    #[serde(default = "default_pool_size_seconds")]
    pub pool_size: usize,
    #[serde(default = "default_sequence_interval_seconds")]
    pub sequence_interval: u64,
}

// Limit on the number of entries per batch. Tune this parameter to avoid running into various size limitations.
// For instance, unexpectedly large leaves (e.g., with PQ signatures) could cause us to exceed the 128MB Workers memory limit. Storing 4000 10KB certificates is 40MB.
fn default_pool_size_seconds() -> usize {
    4000
}

fn default_sequence_interval_seconds() -> u64 {
    1
}
