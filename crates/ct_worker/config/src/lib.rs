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
    #[serde(default = "default_sequence_interval_millis")]
    pub sequence_interval_millis: u64,
    #[serde(default = "default_max_pending_entry_holds")]
    pub max_pending_entry_holds: usize,
}

fn default_sequence_interval_millis() -> u64 {
    1000
}

fn default_max_pending_entry_holds() -> usize {
    1
}
