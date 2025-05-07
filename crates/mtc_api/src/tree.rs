use byteorder::{BigEndian, WriteBytesExt};
use p256::{ecdsa::VerifyingKey as EcdsaVerifyingKey, pkcs8::EncodePublicKey};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use tlog_tiles::{Error as TlogError, Hash, HashReader, Tile};

use crate::{Error, LogEntry, Marshal, UnixTimestamp, Unmarshal, WriteLengthPrefixedBytesExt};

/// Fixed tile height for [static-ct-api](https://c2sp.org/static-ct-api#merkle-tree).
pub const TILE_HEIGHT: u8 = 8;

/// Fixed tile width for [static-ct-api](https://c2sp.org/static-ct-api#merkle-tree).
pub const TILE_WIDTH: u32 = 1 << TILE_HEIGHT;

const PATH_BASE: u64 = 1000;
/// [`tile_path`] returns a tile coordinate path describing `t`, according to <c2sp.org/static-ct-api>.
/// It differs from [`tlog_tiles::Tile::path`] in that it doesn't include an explicit tile height.
///
/// # Panics
///
/// Panics if `t.h` is not [`TILE_HEIGHT`].
pub fn tile_path(t: &Tile) -> String {
    assert_eq!(
        t.height(),
        TILE_HEIGHT,
        "unexpected tile height {}",
        t.height()
    );
    let mut n = t.level_index();
    let mut n_str = format!("{:03}", n % PATH_BASE);
    while n >= PATH_BASE {
        n /= PATH_BASE;
        n_str = format!("x{:03}/{}", n % PATH_BASE, n_str);
    }
    let p_str = if t.width() == 1 << t.height() {
        String::new()
    } else {
        format!(".p/{}", t.width())
    };
    let l_str = if t.is_data() {
        "data".to_string()
    } else {
        format!("{}", t.level())
    };
    format!("tile/{l_str}/{n_str}{p_str}")
}

/// Calculates the log ID from a verifying key.
///
/// # Errors
///
/// Returns an error if decoding the verifying key fails.
pub fn log_id_from_key(vkey: &EcdsaVerifyingKey) -> Result<[u8; 32], x509_verify::spki::Error> {
    let pkix = vkey.to_public_key_der()?;
    Ok(Sha256::digest(&pkix).into())
}

impl LogEntry {
    /// Returns the bytes to be hashed in the Merkle tree. Notably, this
    /// excludes `extra_data`.
    ///
    /// # Panics
    ///
    /// Panics if the timestamp is invalid, or if there are errors
    /// writing internal buffers.
    pub fn merkle_tree_leaf(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer
            .write_u16::<BigEndian>(self.abridged_subject.typ().into())
            .unwrap();
        buffer
            .write_length_prefixed(self.abridged_subject.info(), 2)
            .unwrap();
        self.claims.marshal(&mut buffer).unwrap();
        assert!(self.not_after <= i64::MAX.try_into().unwrap());
        buffer.write_u64::<BigEndian>(self.not_after).unwrap();
        buffer
    }

    /// Returns a lookup key to uniquely identify the entry.
    pub fn lookup_key(&self) -> [u8; 16] {
        let leaf = self.merkle_tree_leaf();
        let hash = Sha256::digest(&leaf);

        // Return the first 16 bytes of the hash as the entry key
        let mut entry_key = [0u8; 16];
        entry_key.copy_from_slice(&hash[..16]);

        entry_key
    }
}

/// An iterator over the contents of a data tile.
pub struct TileIterator {
    s: Cursor<Vec<u8>>,
    size: usize,
    count: usize,
}

impl std::iter::Iterator for TileIterator {
    type Item = Result<LogEntry, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.count == self.size {
            return None;
        }
        self.count += 1;
        Some(self.parse_next())
    }
}

impl TileIterator {
    /// Returns a new [`TileIterator`], which always attempts to parse exactly
    /// 'size' entries before terminating.
    pub fn new(tile: Vec<u8>, size: usize) -> Self {
        Self {
            s: Cursor::new(tile),
            size,
            count: 0,
        }
    }

    /// Parse the next [`LogEntry`] from the internal buffer.
    fn parse_next(&mut self) -> Result<LogEntry, Error> {
        LogEntry::unmarshal(&mut self.s)
    }
}

/// A transparency log tree with a timestamp.
#[derive(Default, Debug)]
pub struct TreeWithTimestamp {
    size: u64,
    hash: Hash,
    time: UnixTimestamp,
}

impl TreeWithTimestamp {
    /// Returns a new tree with the given hash.
    pub fn new(size: u64, hash: Hash, time: UnixTimestamp) -> Self {
        Self { size, hash, time }
    }

    /// Calculates the tree hash by reading tiles from the reader.
    ///
    /// # Errors
    ///
    /// Returns an error if unable to compute the tree hash.
    ///
    pub fn from_hash_reader<R: HashReader>(
        size: u64,
        r: &R,
        time: UnixTimestamp,
    ) -> Result<TreeWithTimestamp, TlogError> {
        let hash = tlog_tiles::tree_hash(size, r)?;
        Ok(Self { size, hash, time })
    }

    /// Returns the size of the tree.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the root hash of the tree.
    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    /// Returns the timestamp of the tree.
    pub fn time(&self) -> UnixTimestamp {
        self.time
    }
}
