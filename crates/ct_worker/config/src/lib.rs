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
    pub operator_name: String,
    pub logs: HashMap<String, LogParams>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IntendedUse {
    Production,
    Test,
    Decommissioned,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogStatus {
    Active,
    Readonly,
    Inactive,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EndpointInfo {
    pub url: String,
}

#[derive(Deserialize, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct LogParams {
    pub friendly_name: String,
    pub intended_use: IntendedUse,
    pub status: LogStatus,
    pub status_timestamp: DateTime<Utc>,
    pub submission_endpoint: EndpointInfo,
    pub monitoring_endpoint: EndpointInfo,
    pub temporal_interval: TemporalInterval,
    #[serde(default)]
    pub include_in_operator_list: bool,
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
    #[serde(default = "default_bool::<true>")]
    pub reject_expired: bool,
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

#[cfg(test)]
mod tests {
    use super::AppConfig;

    #[test]
    fn reject_expired_defaults_to_true_and_can_be_disabled() {
        let config: AppConfig =
            serde_json::from_str(include_str!("../../config.dev.json")).unwrap();

        assert!(config.logs["e2etestshard"].reject_expired);
        assert!(!config.logs["dev2026h2a"].reject_expired);
    }

    #[test]
    fn operator_list_contains_only_selected_shards() {
        let config: AppConfig =
            serde_json::from_str(include_str!("../../config.dev.json")).unwrap();
        let mut logs = config
            .logs
            .iter()
            .filter_map(|(name, params)| params.include_in_operator_list.then_some(name.as_str()))
            .collect::<Vec<_>>();
        logs.sort_unstable();

        assert_eq!(logs, ["dev2027h1a", "dev2027h2a"]);
    }
}
