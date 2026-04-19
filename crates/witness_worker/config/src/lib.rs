// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Configuration for [`witness_worker`](../witness_worker/).
//!
//! A [`c2sp.org/tlog-witness`][spec] witness is configured with a list of
//! logs it trusts. Each entry gives the log's origin (the first line of its
//! checkpoint notes) and one or more SPKI-encoded public keys that the witness
//! will accept signatures from on an incoming checkpoint.
//!
//! The witness's own signing key is supplied out-of-band as a secret named
//! `WITNESS_SIGNING_KEY` (see the worker's `.dev.vars` in dev mode; use
//! `wrangler secret put WITNESS_SIGNING_KEY` for real deployments).
//!
//! [spec]: https://c2sp.org/tlog-witness

use base64::prelude::*;
use serde::Deserialize;
use serde_with::serde_as;
use std::collections::HashMap;

/// Top-level worker configuration, deserialized from `config.<env>.json`.
#[derive(Deserialize, Debug)]
pub struct AppConfig {
    pub logging_level: Option<String>,
    /// The witness's own identity. The name appears in every cosignature line
    /// the witness produces.
    pub witness_name: String,
    /// Human-readable description for operator dashboards.
    pub description: Option<String>,
    /// URL prefix for write APIs (`add-checkpoint`). Published in the
    /// `/metadata` response so clients know where to send requests.
    pub submission_prefix: String,
    /// URL prefix for read APIs. Currently unused by the tlog-witness spec
    /// but reserved for future monitor-facing endpoints. Published in
    /// `/metadata` alongside `submission_prefix`.
    #[serde(default)]
    pub monitoring_prefix: String,
    /// Logs the witness is configured to cosign. Keyed by a short log
    /// identifier used only in config / routing; the identifier does not
    /// appear on the wire. Entries in this map are matched against an
    /// incoming checkpoint by its `origin` line.
    pub logs: HashMap<String, LogParams>,
}

impl AppConfig {
    /// Return the [`LogParams`] for the given origin, if one is configured.
    ///
    /// The origin is the first line of a checkpoint note; it is the stable,
    /// public identifier of the log.
    #[must_use]
    pub fn log_by_origin(&self, origin: &str) -> Option<&LogParams> {
        self.logs.values().find(|p| p.origin == origin)
    }
}

/// Per-log parameters: the origin to match against incoming checkpoints and
/// the public keys the witness is willing to accept checkpoint signatures
/// from.
#[serde_as]
#[derive(Deserialize, Debug)]
pub struct LogParams {
    /// Optional free-text description.
    pub description: Option<String>,
    /// The log's origin line, as it appears in checkpoint notes.
    pub origin: String,
    /// One or more DER-encoded `SubjectPublicKeyInfo` blobs for keys that may
    /// sign checkpoints for this log. The witness verifies incoming
    /// checkpoints against this list and ignores signatures from other keys.
    /// Typically one entry, but multiple are permitted for key rotation.
    #[serde_as(as = "Vec<Base64>")]
    pub log_public_keys: Vec<Vec<u8>>,
}

/// Base64 helper for `serde_as(as = "Vec<Base64>")`.
pub(crate) struct Base64;

impl<'de> serde_with::DeserializeAs<'de, Vec<u8>> for Base64 {
    fn deserialize_as<D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = serde::Deserialize::deserialize(deserializer)?;
        BASE64_STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}
