// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! [`BootstrapMtcSequenceMetadata`] — the per-entry metadata produced by the
//! bootstrap MTC sequencer.

use generic_log_worker::{
    deserialize_sequence_metadata_entries, serialize_sequence_metadata_entries, SequencerMetadata,
};
use serde::{Deserialize, Serialize};
use tlog_tiles::{LeafIndex, LookupKey, UnixTimestamp};

/// Sequencer metadata for a bootstrap MTC log entry.
///
/// Carries the leaf index and sequencing timestamp.
///
/// Wire-format constraints (do not change without migration):
///
/// 1. **Durable Object dedup ring buffer**: 32-byte binary layout
///    `[16-byte lookup key | 8-byte leaf_index BE | 8-byte timestamp BE]`.
///    This format matches the one previously used when the type was
///    `(LeafIndex, UnixTimestamp)`; preserving it avoids a one-time deserialize
///    warning on deploy as the sequencer loads any entries already in DO
///    storage.
/// 2. **DO→Worker RPC**: `bitcode` sequence of the two u64 fields (preserved by
///    the tuple-struct layout).
///
/// Bootstrap MTC does not currently use the long-term KV dedup cache.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BootstrapMtcSequenceMetadata(pub LeafIndex, pub UnixTimestamp);

impl BootstrapMtcSequenceMetadata {
    /// Return the leaf index.
    #[must_use]
    pub fn leaf_index(&self) -> LeafIndex {
        self.0
    }

    /// Return the sequencing timestamp (milliseconds since the Unix epoch).
    #[must_use]
    pub fn timestamp(&self) -> UnixTimestamp {
        self.1
    }
}

impl SequencerMetadata for BootstrapMtcSequenceMetadata {
    fn new(
        leaf_index: LeafIndex,
        timestamp: UnixTimestamp,
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
