// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

use std::{io::Cursor, iter::Iterator};

use length_prefixed::{ReadLengthPrefixedBytesExt, WriteLengthPrefixedBytesExt};
/// Definitions for a generic [tlog-tiles](https://c2sp.org/tlog-tiles) log implementation.
use sha2::{Digest, Sha256};

use crate::TlogError;

pub const LOOKUP_KEY_LEN: usize = 16;
pub type LookupKey = [u8; LOOKUP_KEY_LEN];

/// Unix timestamp, measured since the epoch (January 1, 1970, 00:00),
/// ignoring leap seconds, in milliseconds.
/// This can be unsigned as we never deal with negative timestamps.
pub type UnixTimestamp = u64;

/// Index of a leaf in the Merkle tree.
pub type LeafIndex = u64;

/// Metadata from sequencing that can optionally be incorporated into a
/// `PendingLogEntry` to derive a `LogEntry`. This metadata is also transmitted
/// from the sequencing backend to the frontend to return to the caller.
pub type SequenceMetadata = (LeafIndex, UnixTimestamp);

pub trait PendingLogEntryTrait {
    fn lookup_key(&self) -> LookupKey;
    fn into_log_entry(self, metadata: SequenceMetadata) -> impl LogEntryTrait;
}

pub trait LogEntryTrait {
    fn merkle_tree_leaf(&self) -> Vec<u8>;
    fn tile_leaf(&self) -> Vec<u8>;
    fn metadata(&self) -> SequenceMetadata;
}

pub struct TlogTilesPendingEntry {
    data: Vec<u8>,
}

impl PendingLogEntryTrait for TlogTilesPendingEntry {
    fn lookup_key(&self) -> LookupKey {
        let hash = Sha256::digest(&self.data);
        let mut lookup_key = LookupKey::default();
        lookup_key.copy_from_slice(&hash[..LOOKUP_KEY_LEN]);

        lookup_key
    }

    fn into_log_entry(self, metadata: SequenceMetadata) -> impl LogEntryTrait {
        TlogTilesEntry {
            inner: self,
            metadata,
        }
    }
}

pub struct TlogTilesEntry {
    inner: TlogTilesPendingEntry,
    metadata: SequenceMetadata,
}

impl LogEntryTrait for TlogTilesEntry {
    fn merkle_tree_leaf(&self) -> Vec<u8> {
        self.inner.data.clone()
    }
    fn tile_leaf(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(2 + self.inner.data.len());
        buffer.write_length_prefixed(&self.inner.data, 2).unwrap();
        buffer
    }
    fn metadata(&self) -> SequenceMetadata {
        self.metadata
    }
}

pub trait TlogIteratorTrait {
    fn into_entry_iter(self) -> impl Iterator<Item = Result<impl LogEntryTrait, TlogError>>;
}

impl TlogIteratorTrait for TlogTilesIterator {
    fn into_entry_iter(self) -> impl Iterator<Item = Result<impl LogEntryTrait, TlogError>> {
        self.into_iter()
    }
}

/// An iterator over the contents of an entries bundle.
pub struct TlogTilesIterator {
    s: Cursor<Vec<u8>>,
    size: usize,
    count: usize,
}

impl std::iter::Iterator for TlogTilesIterator {
    type Item = Result<TlogTilesEntry, TlogError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.count == self.size {
            return None;
        }
        self.count += 1;
        Some(self.parse_next())
    }
}

impl TlogTilesIterator {
    /// Returns a new [`TileIterator`], which always attempts to parse exactly
    /// 'size' entries before terminating.
    pub fn new(tile: Vec<u8>, size: usize) -> Self {
        Self {
            s: Cursor::new(tile),
            size,
            count: 0,
        }
    }

    /// Parse the next [`TlogTilesEntry`] from the internal buffer. Entry
    /// bundles contain big-endian uint16 length-prefixed [log
    /// entries](https://c2sp.org/tlog-tiles#log-entries).
    fn parse_next(&mut self) -> Result<TlogTilesEntry, TlogError> {
        Ok(TlogTilesEntry {
            inner: TlogTilesPendingEntry {
                data: self.s.read_length_prefixed(2)?,
            },
            metadata: SequenceMetadata::default(),
        })
    }
}
