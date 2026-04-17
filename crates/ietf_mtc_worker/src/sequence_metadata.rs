// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! [`IetfMtcSequenceMetadata`] — the per-entry metadata produced by the
//! IETF MTC sequencer.

use generic_log_worker::SequencerMetadata;
use serde::{Deserialize, Serialize};
use tlog_tiles::{LeafIndex, UnixTimestamp};

/// Sequencer metadata for an IETF MTC log entry.
///
/// Carries only the fields the IETF MTC worker actually consumes downstream:
/// the `leaf_index` of the sequenced entry and the tree sizes before and after
/// the sequencing batch. The frontend uses `old_tree_size` and `new_tree_size`
/// together with `leaf_index` to identify the single covering subtree in
/// `Subtree::split_interval(old, new)` that contains this entry — and
/// therefore the exact R2 key of its cached subtree signature — without
/// having to enumerate candidate subtree keys.
///
/// Unlike bootstrap/static-ct metadata, there is no `timestamp` field: the
/// IETF MTC `add-entry` response is a DER-encoded §6.2 standalone certificate,
/// whose validity is carried inside the TBS entry rather than returned
/// separately.
///
/// IETF MTC does not currently use the long-term KV dedup cache or have any
/// deployed short-term dedup storage, so no wire-format compatibility
/// constraints apply; the default JSON cache serialization is fine.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IetfMtcSequenceMetadata {
    /// Zero-based index of the sequenced entry.
    pub leaf_index: LeafIndex,
    /// Tree size immediately before the batch that sequenced this entry.
    pub old_tree_size: u64,
    /// Tree size immediately after the batch that sequenced this entry.
    pub new_tree_size: u64,
}

impl SequencerMetadata for IetfMtcSequenceMetadata {
    fn new(
        leaf_index: LeafIndex,
        _timestamp: UnixTimestamp,
        old_tree_size: u64,
        new_tree_size: u64,
    ) -> Self {
        Self {
            leaf_index,
            old_tree_size,
            new_tree_size,
        }
    }
}
