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
