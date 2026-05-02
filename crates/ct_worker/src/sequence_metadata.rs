// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! [`StaticCTSequenceMetadata`] — the per-entry metadata produced by the
//! static-ct-api sequencer.

use generic_log_worker::{
    deserialize_sequence_metadata_entries, serialize_sequence_metadata_entries, SequencerMetadata,
};
use serde::{Deserialize, Serialize};
use tlog_checkpoint::UnixTimestampMillis;
use tlog_core::LeafIndex;
use tlog_tiles::LookupKey;

/// Sequencer metadata for a static-ct-api log entry.
///
/// Wire-format constraints (do not change without migration):
///
/// 1. **Durable Object dedup ring buffer**: 32-byte binary layout
///    `[16-byte lookup key | 8-byte leaf_index BE | 8-byte timestamp BE]`,
///    handled via [`serialize_sequence_metadata_entries`] /
///    [`deserialize_sequence_metadata_entries`].
/// 2. **KV long-term dedup cache metadata**: JSON array `[leaf_index, timestamp]`.
///    Preserved automatically because this is a tuple struct (serde serializes
///    tuple structs as JSON arrays).
/// 3. **DO→Worker RPC**: `bitcode` sequence of the two u64 fields. Also
///    preserved by the tuple-struct layout.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StaticCTSequenceMetadata(pub LeafIndex, pub UnixTimestampMillis);

impl StaticCTSequenceMetadata {
    /// Return the leaf index.
    #[must_use]
    pub fn leaf_index(&self) -> LeafIndex {
        self.0
    }

    /// Return the sequencing timestamp (milliseconds since the Unix epoch).
    #[must_use]
    pub fn timestamp(&self) -> UnixTimestampMillis {
        self.1
    }
}

impl SequencerMetadata for StaticCTSequenceMetadata {
    fn new(
        leaf_index: LeafIndex,
        timestamp: UnixTimestampMillis,
        _old_tree_size: u64,
        _new_tree_size: u64,
    ) -> Self {
        Self(leaf_index, timestamp)
    }

    fn serialize_cache_entries(entries: &[(LookupKey, Self)]) -> Vec<u8> {
        let pairs: Vec<(LookupKey, (u64, u64))> =
            entries.iter().map(|(k, m)| (*k, (m.0, m.1))).collect();
        serialize_sequence_metadata_entries(&pairs)
    }

    fn deserialize_cache_entries(buf: &[u8]) -> Result<Vec<(LookupKey, Self)>, String> {
        let pairs = deserialize_sequence_metadata_entries(buf)?;
        Ok(pairs
            .into_iter()
            .map(|(k, (idx, ts))| (k, Self(idx, ts)))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirm the JSON wire format used by the KV long-term dedup cache
    /// metadata matches the historical `(LeafIndex, UnixTimestampMillis)` tuple shape
    /// (i.e. `[leaf_index, timestamp]`). Changing this would orphan pre-existing
    /// KV entries from deployed logs.
    #[test]
    fn test_kv_json_format_unchanged() {
        let m = StaticCTSequenceMetadata(42, 1000);
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, "[42,1000]");

        let parsed: StaticCTSequenceMetadata = serde_json::from_str("[42,1000]").unwrap();
        assert_eq!(parsed, m);
    }
}
