use length_prefixed::{ReadLengthPrefixedBytesExt, WriteLengthPrefixedBytesExt};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read, marker::PhantomData};

use crate::{Hash, PathElem, TlogError};

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
pub trait PendingLogEntry: core::fmt::Debug + Clone + Serialize + DeserializeOwned {
    /// The path to write data tiles in the object store, which is 'entries' for tlog-tiles.
    const DATA_TILE_PATH: PathElem;

    /// If configured, the path to write auxiliary data associated with the
    /// entry to the object store. This is unused in tlog-tiles and
    /// static-ct-api, but is used for publishing 'bootstrap' certificiate
    /// chains in MTC.
    const AUX_TILE_PATH: Option<PathElem>;

    /// Returns the auxiliary data for this entry, if configured. It is an error
    /// to call this function if [`AUX_TILE_PATH`] is not specified.
    fn aux_entry(&self) -> &[u8];

    /// The lookup key belonging to this pending log entry.
    fn lookup_key(&self) -> LookupKey;
}

pub trait LogEntry: core::fmt::Debug + Sized {
    /// Whether or not a timestamped signature is required on checkpoints for log entries of this type.
    const REQUIRE_CHECKPOINT_TIMESTAMP: bool;

    /// The pending version of this log entry. Usually the same thing but doesn't have a timestamp or tree index
    type Pending: PendingLogEntry;

    /// The error type for [`Self::parse_from_tile_entry`]
    type ParseError: std::error::Error + Send + Sync + 'static;

    /// Returns an optional initial entry to add into the log. This is used for
    /// the initial `null_entry` in Merkle Tree Certificates, but likely not
    /// useful anywhere else.
    fn initial_entry() -> Option<Self::Pending>;

    fn new(pending: Self::Pending, metadata: SequenceMetadata) -> Self;

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
pub struct TileIterator<'a, L: LogEntry> {
    input: &'a [u8],
    size: usize,
    count: usize,
    _marker: PhantomData<L>,
}

impl<L: LogEntry> std::iter::Iterator for TileIterator<'_, L> {
    type Item = Result<L, L::ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == self.size {
            return None;
        }
        self.count += 1;
        Some(self.parse_next())
    }
}

impl<'a, L: LogEntry> TileIterator<'a, L> {
    /// Returns a new [`TileIterator`], which always attempts to parse exactly
    /// 'size' entries before terminating.
    pub fn new(input: &'a [u8], size: usize) -> Self {
        Self {
            input,
            size,
            count: 0,
            _marker: PhantomData,
        }
    }

    /// Parse the next [`LogEntry`] from the internal buffer.
    fn parse_next(&mut self) -> Result<L, L::ParseError> {
        L::parse_from_tile_entry(&mut self.input)
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct TlogTilesPendingLogEntry {
    pub data: Vec<u8>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct TlogTilesLogEntry {
    pub inner: TlogTilesPendingLogEntry,
}

impl PendingLogEntry for TlogTilesPendingLogEntry {
    /// The data tile path in tlog-tiles is 'entries'.
    const DATA_TILE_PATH: PathElem = PathElem::Entries;

    /// No auxiliary data tile published in tlog-tiles.
    const AUX_TILE_PATH: Option<PathElem> = None;

    /// Unused in tlog-tiles.
    fn aux_entry(&self) -> &[u8] {
        unimplemented!()
    }

    fn lookup_key(&self) -> LookupKey {
        let hash = Sha256::digest(&self.data);
        let mut lookup_key = LookupKey::default();
        lookup_key.copy_from_slice(&hash[..LOOKUP_KEY_LEN]);

        lookup_key
    }
}

impl LogEntry for TlogTilesLogEntry {
    const REQUIRE_CHECKPOINT_TIMESTAMP: bool = false;
    type Pending = TlogTilesPendingLogEntry;
    type ParseError = TlogError;

    fn initial_entry() -> Option<Self::Pending> {
        None
    }

    fn new(pending: Self::Pending, _metadata: SequenceMetadata) -> Self {
        Self { inner: pending }
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
