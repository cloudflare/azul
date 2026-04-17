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
    pub log_id: String,
    pub cosigner_id: String,
    #[serde(default = "default_usize::<604_800>")]
    pub max_certificate_lifetime_secs: usize,
    #[serde(default = "default_usize::<3600>")]
    pub landmark_interval_secs: usize,
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
    #[serde(default = "default_u64::<60>")]
    pub clean_interval_secs: u64,
    /// The version of draft-ietf-plants-merkle-tree-certs that this log implements.
    #[serde(default)]
    pub version: ietf_mtc_api::DraftVersion,
}

impl LogParams {
    /// Return the maximum number of active landmarks (those covering unexpired
    /// certificates).
    ///
    /// # Formula: `ceil(lifetime / interval) + 1`
    ///
    /// The `+ 1` accounts for landmarks not allocated at the exact start of
    /// their time interval, which can push certificate expiry one interval
    /// further than `ceil(lifetime / interval)` alone would bound.
    ///
    /// # Example
    ///
    /// With 7-day (168 hour) certificate lifetime and 1-hour landmark interval:
    /// - Formula: `ceil(168 / 1) + 1 = 168 + 1 = 169`
    /// - This means up to 169 active landmarks
    ///
    /// # Storage Note
    ///
    /// The actual landmark deque stores `max_active_landmarks + 1` entries (170
    /// in the example above). The extra (expired) landmark is needed to compute
    /// subtrees for all active landmarks. See `LandmarkSequence` documentation
    /// for details.
    #[must_use]
    pub fn max_active_landmarks(&self) -> usize {
        self.max_certificate_lifetime_secs
            .div_ceil(self.landmark_interval_secs)
            + 1
    }
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
