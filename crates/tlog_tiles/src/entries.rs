use length_prefixed::{ReadLengthPrefixedBytesExt, WriteLengthPrefixedBytesExt};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Cursor, Read},
    marker::PhantomData,
};

use crate::{Hash, TlogError};

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

/// The functionality exposed by any data type that can be included in a Merkle tree
pub trait PendingLogEntry: core::fmt::Debug + Serialize + DeserializeOwned {
    /// The lookup key belonging to this pending log entry.
    fn lookup_key(&self) -> LookupKey;

    /// The labels this objects wants to be used when it appears in Prometheus logging messages.
    fn logging_labels(&self) -> Vec<String>;
}

pub trait LogEntry: core::fmt::Debug + Sized {
    /// The pending version of this log entry. Usually the same thing but doesn't have a timestamp or tree index
    type Pending: PendingLogEntry;

    /// The error type for [`Self::parse_from_tile_entry`]
    type ParseError: std::error::Error + Send + Sync + 'static;

    fn new(pending: Self::Pending, metadata: SequenceMetadata) -> Self;

    /// Returns the underlying pending entry
    fn inner(&self) -> &Self::Pending;

    /// Returns the Merkle tree leaf hash for this entry. For tlog-tiles, this is the Merkle Tree Hash
    /// (according to <https://datatracker.ietf.org/doc/html/rfc6962#section-2.1>)
    /// of the log entry bytes.
    fn merkle_tree_leaf(&self) -> Hash;

    /// Returns the serialized form of this log entry to be included in the data
    /// tile. For tlog-tiles, this is the big-endian uint16 length-prefixed log entry.
    fn to_data_tile_entry(&self) -> Vec<u8>;

    /// Attempts to parse a `LogEntry` from a reader into a tile. The position of the reader is
    /// expected to be the beginning of an entry. On success, returns a log entry.
    ///
    /// # Errors
    ///
    /// Errors if the log entry cannot be parsed from the reader.
    fn parse_from_tile_entry<R: Read>(input: &mut R) -> Result<Self, Self::ParseError>;
}

/// An iterator over log entries in a data tile.
pub struct TileIterator<L: LogEntry> {
    s: Cursor<Vec<u8>>,
    size: usize,
    count: usize,
    _marker: PhantomData<L>,
}

impl<L: LogEntry> std::iter::Iterator for TileIterator<L> {
    type Item = Result<L, L::ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == self.size {
            return None;
        }
        self.count += 1;
        Some(self.parse_next())
    }
}

impl<L: LogEntry> TileIterator<L> {
    /// Returns a new [`TileIterator`], which always attempts to parse exactly
    /// 'size' entries before terminating.
    pub fn new(tile: Vec<u8>, size: usize) -> Self {
        Self {
            s: Cursor::new(tile),
            size,
            count: 0,
            _marker: PhantomData,
        }
    }

    /// Parse the next [`LogEntry`] from the internal buffer.
    fn parse_next(&mut self) -> Result<L, L::ParseError> {
        L::parse_from_tile_entry(&mut self.s)
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct TlogTilesPendingLogEntry {
    data: Vec<u8>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct TlogTilesLogEntry {
    inner: TlogTilesPendingLogEntry,
}

impl PendingLogEntry for TlogTilesPendingLogEntry {
    fn lookup_key(&self) -> LookupKey {
        let hash = Sha256::digest(&self.data);
        let mut lookup_key = LookupKey::default();
        lookup_key.copy_from_slice(&hash[..LOOKUP_KEY_LEN]);

        lookup_key
    }

    fn logging_labels(&self) -> Vec<String> {
        Vec::new()
    }
}

impl LogEntry for TlogTilesLogEntry {
    type Pending = TlogTilesPendingLogEntry;

    type ParseError = TlogError;

    fn new(pending: Self::Pending, _metadata: SequenceMetadata) -> Self {
        Self { inner: pending }
    }

    fn inner(&self) -> &Self::Pending {
        &self.inner
    }

    fn merkle_tree_leaf(&self) -> Hash {
        crate::tlog::record_hash(&self.inner.data)
    }

    fn to_data_tile_entry(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(2 + self.inner.data.len());
        buffer.write_length_prefixed(&self.inner.data, 2).unwrap();
        buffer
    }

    /// Parse a tlog-tiles log entry from the reader into an entry bundle. Entry
    /// bundles contain big-endian uint16 length-prefixed [log
    /// entries](https://c2sp.org/tlog-tiles#log-entries).
    fn parse_from_tile_entry<R: Read>(input: &mut R) -> Result<Self, Self::ParseError> {
        Ok(Self {
            inner: TlogTilesPendingLogEntry {
                data: input.read_length_prefixed(2)?,
            },
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse_tile_entry() {
        let inner = TlogTilesPendingLogEntry { data: vec![1; 100] };
        let entry = TlogTilesLogEntry::new(inner, (123, 456));
        let tile: Vec<u8> = (0..5).flat_map(|_| entry.to_data_tile_entry()).collect();
        let mut tile_reader: &[u8] = tile.as_ref();

        for _ in 0..5 {
            let parsed_entry = TlogTilesLogEntry::parse_from_tile_entry(&mut tile_reader).unwrap();
            assert_eq!(entry, parsed_entry);
        }
    }
}
