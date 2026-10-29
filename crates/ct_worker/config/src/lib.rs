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
    #[serde(default)]
    pub operator_list_entries: Vec<String>,
    pub logs: HashMap<String, LogParams>,
}

impl AppConfig {
    #[must_use]
    pub fn operator_list_urls(&self) -> Vec<String> {
        let mut urls = self
            .logs
            .values()
            .filter(|params| params.include_in_operator_list)
            .map(|params| {
                format!(
                    "{}/metadata.json",
                    params.submission_endpoint.url.trim_end_matches('/')
                )
            })
            .chain(self.operator_list_entries.iter().cloned())
            .collect::<Vec<_>>();
        urls.sort_unstable();
        urls.dedup();
        urls
    }
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
    /// Require the leaf EKU extension to contain `id-kp-serverAuth`.
    ///
    /// Disabling this skips only that presence check. It does not select a
    /// different EKU policy or relax the remaining chain and CT validation.
    #[serde(default = "default_bool::<true>")]
    pub require_server_auth_eku: bool,
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
    fn operator_list_combines_selected_shards_and_manual_entries() {
        let mut config: AppConfig =
            serde_json::from_str(include_str!("../../config.dev.json")).unwrap();
        config
            .operator_list_entries
            .push("http://localhost:8787/logs/dev2027h1a/metadata.json".to_owned());

        assert_eq!(
            config.operator_list_urls(),
            [
                "http://localhost:8787/logs/dev2027h1a/metadata.json",
                "http://localhost:8787/logs/dev2027h2a/metadata.json",
                "https://example.com/external-log/metadata.json",
            ]
        );
    }

    #[test]
    fn require_server_auth_eku_defaults_to_true_and_can_be_disabled() {
        let config: AppConfig =
            serde_json::from_str(include_str!("../../config.dev.json")).unwrap();

        // The default must stay `true`: WebPKI logs depend on it, and a default
        // of `false` would silently relax RFC 6962 section 3.1 for every log
        // that never opted out.
        for (name, log) in &config.logs {
            assert_eq!(log.require_server_auth_eku, name != "dev2027h1a", "{name}");
        }
    }
}
