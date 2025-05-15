// Ported from "mod" (https://pkg.go.dev/golang.org/x/mod)
// Copyright 2009 The Go Authors
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause
//
// This ports code from the original Go project "mod" and adapts it to Rust idioms.
//
// Modifications and Rust implementation Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Provides Merkle Tree functionality required for a basic transparency log.
//!
//! This file contains code ported from the original project [tlog](https://pkg.go.dev/golang.org/x/mod/sumdb/tlog).
//!
//! References:
//! - [tlog.go](https://cs.opensource.google/go/x/mod/+/refs/tags/v0.21.0:sumdb/tlog/tlog.go)
//! - [tlog_test.go](https://cs.opensource.google/go/x/mod/+/refs/tags/v0.21.0:sumdb/tlog/tlog_test.go)

use base64::prelude::*;
use serde::{
    de::{self, Visitor},
    Deserialize,
};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;

/// `HashSize` is the size of a Hash in bytes.
pub const HASH_SIZE: usize = 32;

/// A Hash is a hash identifying a log record or tree root.
#[derive(Copy, Clone, Default, PartialEq)]
pub struct Hash(pub [u8; HASH_SIZE]);

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))?;
        Ok(())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct HashVisitor;

        impl Visitor<'_> for HashVisitor {
            type Value = Hash;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a base64 encoded string representing a 32-byte hash")
            }

            fn visit_str<E>(self, value: &str) -> Result<Hash, E>
            where
                E: de::Error,
            {
                let decoded = BASE64_STANDARD.decode(value).map_err(de::Error::custom)?;
                if decoded.len() != HASH_SIZE {
                    return Err(de::Error::custom(format!(
                        "expected {} bytes, got {}",
                        HASH_SIZE,
                        decoded.len()
                    )));
                }
                let array: [u8; HASH_SIZE] = decoded
                    .try_into()
                    .map_err(|_| de::Error::custom("failed to convert vector to array"))?;
                Ok(Hash(array))
            }
        }

        deserializer.deserialize_str(HashVisitor)
    }
}

impl Hash {
    /// Returns a new Hash with contents decoded from the given base64-encoded string.
    ///
    /// # Errors
    ///
    /// Returns an error is the decoded hash size is not `HASH_SIZE`.
    pub fn parse_hash(s: &str) -> Result<Self, TlogError> {
        let data = BASE64_STANDARD.decode(s)?;

        Ok(Hash(data.try_into().map_err(|_| TlogError::MalformedHash)?))
    }
}

/// maxpow2 returns k, the maximum power of 2 smaller than n,
/// as well as l = log₂ k (so k = 1<<l).
///
/// # Panics
///
/// Panics if n <= 1.
fn maxpow2(n: u64) -> (u64, u8) {
    let l = u8::try_from((n - 1).ilog2()).unwrap();
    (1 << l, l)
}

/// Returns the content hash for the given record data.
pub fn record_hash(data: &[u8]) -> Hash {
    // SHA256(0x00 || data)
    // https://tools.ietf.org/html/rfc6962#section-2.1
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(data);
    let result = hasher.finalize();
    Hash(result.into())
}

/// Returns the hash for an interior tree node with the given left and right hashes.
pub fn node_hash(left: Hash, right: Hash) -> Hash {
    // SHA256(0x01 || left || right)
    // https://tools.ietf.org/html/rfc6962#section-2.1
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left.0);
    hasher.update(right.0);
    let result = hasher.finalize();
    Hash(result.into())
}

/// Maps the tree coordinates `(level, n)` to a dense linear ordering that can be used for hash
/// storage.  Hash storage implementations that store hashes in sequential storage can use this
/// function to compute where to read or write a given hash.
///
/// For information about the stored hash index ordering, see section 3.3 of Crosby and Wallach's
/// paper ["Efficient Data Structures for Tamper-Evident
/// Logging"](https://www.usenix.org/legacy/event/sec09/tech/full_papers/crosby.pdf).
pub fn stored_hash_index(level: u8, n: u64) -> u64 {
    // Level L's n'th hash is written right after level L+1's 2n+1'th hash.
    // Work our way down to the level 0 ordering.
    // We'll add back the original level count at the end.
    let mut n = n;
    for _ in 0..level {
        n = 2 * n + 1;
    }

    // Level 0's n'th hash is written at n+n/2+n/4+... (eventually n/2ⁱ hits zero).
    let mut i = 0;
    while n > 0 {
        i += n;
        n >>= 1;
    }

    i + u64::from(level)
}

/// This is the inverse of [`stored_hash_index`].  That is,
/// `split_stored_hash_index(stored_hash_index(level, n)) == level, n`.
///
/// # Panics
///
/// Panics if `stored_hash_index` returns an invalid index, which should never happen.
pub fn split_stored_hash_index(index: u64) -> (u8, u64) {
    // Determine level 0 record before index.
    // StoredHashIndex(0, n) < 2*n,
    // so the n we want is in [index/2, index/2+log₂(index)].
    let mut n = index / 2;
    let mut index_n = stored_hash_index(0, n);
    assert!(index_n <= index, "bad math");
    loop {
        // Each new record n adds 1 + trailingZeros(n) hashes.
        let x = index_n + 1 + u64::from((n + 1).trailing_zeros());
        if x > index {
            break;
        }
        n += 1;
        index_n = x;
    }
    // The hash we want was committed with record n,
    // meaning it is one of (0, n), (1, n/2), (2, n/4), ...
    let level = u8::try_from(index - index_n).unwrap();
    (level, n >> level)
}

/// Returns the number of stored hashes that are expected for a tree with `n` records.
pub fn stored_hash_count(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    // The tree will have the hashes up to the last leaf hash.
    let mut num_hash = stored_hash_index(0, n - 1) + 1;
    let mut i = n - 1;
    while i & 1 != 0 {
        num_hash += 1;
        i >>= 1;
    }
    num_hash
}

/// Returns the hashes that must be stored when writing record n with the given data. The hashes
/// should be stored starting at `stored_hash_index(0, n)`. The result will have at most `1 + log₂
/// n` hashes, but it will average just under two per call for a sequence of calls for `n=1..k`.
///
/// `stored_hashes` may read up to `log n` earlier hashes from `r` in order to compute hashes for
/// completed subtrees.
///
/// # Errors
///
/// See `stored_hashes_for_record_hash`.
pub fn stored_hashes<R: HashReader>(n: u64, data: &[u8], r: &R) -> Result<Vec<Hash>, TlogError> {
    stored_hashes_for_record_hash(n, record_hash(data), r)
}

/// This is like [`stored_hashes`] but takes as its second argument `record_hash(data)` instead of
/// data itself.
///
/// # Errors
///
/// Returns an error if `read_hashes` fails to read hashes.
///
/// # Panics
///
/// Panics if `read_hashes` returns an incorrect number of hashes, or there are internal math errors.
pub fn stored_hashes_for_record_hash<R: HashReader>(
    n: u64,
    h: Hash,
    r: &R,
) -> Result<Vec<Hash>, TlogError> {
    // Start with the record hash.
    let mut hashes = vec![h];

    // Build list of indexes needed for hashes for completed subtrees.
    // Each trailing 1 bit in the binary representation of n completes a subtree
    // and consumes a hash from an adjacent subtree.
    let m = u8::try_from((n + 1).trailing_zeros()).unwrap();
    let mut indexes = vec![0_u64; m.into()];
    for i in 0..m {
        // We arrange indexes in sorted order.
        // Note that n >> i is always odd.
        indexes[usize::from(m - 1 - i)] = stored_hash_index(i, (n >> i) - 1);
    }

    // Fetch hashes.
    let old = r.read_hashes(&indexes)?;
    assert_eq!(old.len(), indexes.len(), "bad read_hashes implementation");

    // Build new hashes.
    let mut h = h;
    for i in 0..m {
        h = node_hash(old[usize::from(m - 1 - i)], h);
        hashes.push(h);
    }

    Ok(hashes)
}

/// A `HashReader` can read hashes for nodes in the log's tree structure.
pub trait HashReader {
    /// Returns the hashes with the given stored hash indexes (see [`stored_hash_index`] and
    /// [`split_stored_hash_index`]). May run faster if indexes is sorted in increasing
    /// order.
    ///
    /// # Errors
    ///
    /// Must return a slice of hashes the same length as indexes, or
    /// else it must return a non-nil error.
    fn read_hashes(&self, indexes: &[u64]) -> Result<Vec<Hash>, TlogError>;
}

/// `EMPTY_HASH` is the hash of the empty tree, per RFC 6962, Section 2.1.
/// It is the hash of the empty string.
pub const EMPTY_HASH: Hash = Hash([
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
]);

/// Computes the hash for the root of the tree with `n` records, using the [`HashReader`] to obtain
/// previously stored hashes (those returned by [`stored_hashes`] during the writes of those `n`
/// records).  `tree_hash` makes a single call to [`HashReader::read_hashes`] requesting at most `1 +
/// log₂ n` hashes.
///
/// # Errors
///
/// Returns an error if `read_hashes` fails to read hashes.
///
/// # Panics
///
/// Panics if `read_hashes` returns a slice of hashes that is not the same
/// length as the requested indexes, or if there are internal math errors.
pub fn tree_hash<R: HashReader>(n: u64, r: &R) -> Result<Hash, TlogError> {
    if n == 0 {
        return Ok(EMPTY_HASH);
    }
    let indexes = sub_tree_index(0, n, vec![]);
    let hashes = r.read_hashes(&indexes)?;
    assert_eq!(
        hashes.len(),
        indexes.len(),
        "bad read_hashes implementation"
    );
    let (hash, remaining_hashes) = sub_tree_hash(0, n, &hashes);
    assert!(remaining_hashes.is_empty(), "bad math in tree_hash");
    Ok(hash)
}

/// Returns the storage indexes needed to compute the hash for the subtree containing records [lo,
/// hi), appending them to need and returning the result.  See
/// <https://tools.ietf.org/html/rfc6962#section-2.1>.
///
/// # Panics
///
/// Panics if there are internal math errors.
pub fn sub_tree_index(lo: u64, hi: u64, mut need: Vec<u64>) -> Vec<u64> {
    // See sub_tree_hash below for commentary.
    let mut lo = lo;
    while lo < hi {
        let (k, level) = maxpow2(hi - lo + 1);
        assert!(lo & (k - 1) == 0, "bad math in sub_tree_index");
        need.push(stored_hash_index(level, lo >> level));
        lo += k;
    }
    need
}

// Computes the hash for the subtree containing records [lo, hi), assuming that hashes are the
// hashes corresponding to the indexes returned by sub_tree_index(lo, hi).  It returns any leftover
// hashes.
//
// May panic if there are internal math errors.
fn sub_tree_hash(lo: u64, hi: u64, hashes: &[Hash]) -> (Hash, Vec<Hash>) {
    // Repeatedly partition the tree into a left side with 2^level nodes,
    // for as large a level as possible, and a right side with the fringe.
    // The left hash is stored directly and can be read from storage.
    // The right side needs further computation.
    let mut num_tree = 0;
    let mut lo = lo;
    while lo < hi {
        let (k, _) = maxpow2(hi - lo + 1);
        assert!(lo & (k - 1) == 0 && lo < hi, "bad math in sub_tree_hash");
        num_tree += 1;
        lo += k;
    }

    assert!(hashes.len() >= num_tree, "bad index math in sub_tree_hash");

    // Reconstruct hash.
    let mut h = hashes[num_tree - 1];
    for i in (0..num_tree - 1).rev() {
        h = node_hash(hashes[i], h);
    }
    (h, hashes[num_tree..].to_vec())
}

/// A `RecordProof` is a verifiable proof that a particular log root contains a particular record.
/// RFC 6962 calls this a “Merkle audit path.”
pub type RecordProof = Vec<Hash>;

/// Returns the proof that the tree of size `t` contains the record with index `n`.
///
/// # Errors
///
/// Returns an error if `read_hashes` fails to read hashes.
///
/// # Panics
///
/// Panics if `read_hashes` returns a slice of hashes that is not the same
/// length as the requested indexes, or if there are internal math errors.
pub fn prove_record<R: HashReader>(t: u64, n: u64, r: &R) -> Result<RecordProof, TlogError> {
    if n >= t {
        return Err(TlogError::InvalidInput("n >= t".into()));
    }
    let indexes = leaf_proof_index(0, t, n, vec![]);
    if indexes.is_empty() {
        return Ok(vec![]);
    }
    let hashes = r.read_hashes(&indexes)?;
    assert_eq!(
        hashes.len(),
        indexes.len(),
        "bad read_hashes implementation"
    );
    let (proof, remaining_hashes) = leaf_proof(0, t, n, hashes);
    assert!(
        remaining_hashes.is_empty(),
        "bad index math in prove_record"
    );
    Ok(proof)
}

// Builds the list of indexes needed to construct the proof
// that leaf n is contained in the subtree with leaves [lo, hi).
// It appends those indexes to need and returns the result.
// See https://tools.ietf.org/html/rfc6962#section-2.1.1
//
// May panic if there are internal math errors.
fn leaf_proof_index(lo: u64, hi: u64, n: u64, mut need: Vec<u64>) -> Vec<u64> {
    // See leaf_proof below for commentary.
    assert!(lo <= n && n < hi, "bad math in leaf_proof_index");
    if lo + 1 == hi {
        return need;
    }
    let (k, _) = maxpow2(hi - lo);
    if n < lo + k {
        need = leaf_proof_index(lo, lo + k, n, need);
        need = sub_tree_index(lo + k, hi, need);
    } else {
        need = sub_tree_index(lo, lo + k, need);
        need = leaf_proof_index(lo + k, hi, n, need);
    }
    need
}

// Constructs the proof that leaf n is contained in the subtree with leaves [lo, hi).
// It returns any leftover hashes as well.
// See https://tools.ietf.org/html/rfc6962#section-2.1.1
//
// May panic if there are internal math errors.
fn leaf_proof(lo: u64, hi: u64, n: u64, mut hashes: Vec<Hash>) -> (RecordProof, Vec<Hash>) {
    // We must have lo <= n < hi or else the code here has a bug.
    assert!(lo <= n && n < hi, "bad math in leaf_proof");

    if lo + 1 == hi {
        // n == lo
        // Reached the leaf node.
        // The verifier knows what the leaf hash is, so we don't need to send it.
        return (vec![], hashes);
    }

    // Walk down the tree toward n.
    // Record the hash of the path not taken (needed for verifying the proof).
    let mut proof: RecordProof;
    let th: Hash;
    let (k, _) = maxpow2(hi - lo);
    if n < lo + k {
        // n is on left side
        (proof, hashes) = leaf_proof(lo, lo + k, n, hashes);
        (th, hashes) = sub_tree_hash(lo + k, hi, &hashes);
    } else {
        // n is on right side
        (th, hashes) = sub_tree_hash(lo, lo + k, &hashes);
        (proof, hashes) = leaf_proof(lo + k, hi, n, hashes);
    }

    proof.push(th);
    (proof, hashes)
}

#[derive(Error, Debug)]
pub enum TlogError {
    #[error("invalid transparency proof")]
    InvalidProof,
    #[error("malformed hash")]
    MalformedHash,
    #[error("invalid tile")]
    InvalidTile,
    #[error("bad math")]
    BadMath,
    #[error("downloaded inconsistent tile")]
    InconsistentTile,
    #[error("indexes not in tree")]
    IndexesNotInTree,
    #[error("indexes out of order")]
    IndexesOutOfOrder,
    #[error("unmet input condition: {0}")]
    InvalidInput(String),
    #[error(transparent)]
    InvalidBase64(#[from] base64::DecodeError),
}

/// Verifies that `p` is a valid proof that the tree of size `t` with hash `th` has an `n`'th
/// record with hash `h`.
///
/// # Errors
///
/// Returns an error if the inputs or proof are invalid.
///
/// # Panics
///
/// Panics if there are internal math errors.
pub fn check_record(p: &RecordProof, t: u64, th: Hash, n: u64, h: Hash) -> Result<(), TlogError> {
    if n >= t {
        return Err(TlogError::InvalidInput("n >= t".into()));
    }
    let th2 = run_record_proof(p, 0, t, n, h)?;
    if th2 == th {
        Ok(())
    } else {
        Err(TlogError::InvalidProof)
    }
}

// Runs the proof p that leaf n is contained in the subtree with leaves [lo, hi).
// Running the proof means constructing and returning the implied hash of that
// subtree.
//
// # Panics
//
// Panics if there are internal math errors.
fn run_record_proof(
    p: &RecordProof,
    lo: u64,
    hi: u64,
    n: u64,
    leaf_hash: Hash,
) -> Result<Hash, TlogError> {
    // We must have lo <= n < hi or else the code here has a bug.
    assert!((lo..hi).contains(&n), "bad math in run_record_proof");

    if lo + 1 == hi {
        // m == lo
        // Reached the leaf node.
        // The proof must not have any unnecessary hashes.
        if !p.is_empty() {
            return Err(TlogError::InvalidProof);
        }
        return Ok(leaf_hash);
    }

    if p.is_empty() {
        return Err(TlogError::InvalidProof);
    }

    let (k, _) = maxpow2(hi - lo);
    if n < lo + k {
        let th = run_record_proof(&p[..p.len() - 1].to_vec(), lo, lo + k, n, leaf_hash)?;
        Ok(node_hash(th, p[p.len() - 1]))
    } else {
        let th = run_record_proof(&p[..p.len() - 1].to_vec(), lo + k, hi, n, leaf_hash)?;
        Ok(node_hash(p[p.len() - 1], th))
    }
}

/// A `TreeProof` is a verifiable proof that a particular log tree contains
/// as a prefix all records present in an earlier tree.
/// RFC 6962 calls this a “Merkle consistency proof.”
pub type TreeProof = Vec<Hash>;

/// Returns the proof that the tree of size `t` contains
/// as a prefix all the records from the tree of smaller size `n`.
///
/// # Errors
///
/// Returns an error if the inputs or proof are invalid or if `read_hashes` fails to read hashes.
///
/// # Panics
///
/// Panics if `read_hashes` returns a slice of hashes that is not the same
/// length as the requested indexes, or if there are internal math errors.
pub fn prove_tree<R: HashReader>(t: u64, n: u64, h: &R) -> Result<TreeProof, TlogError> {
    if !(1..=t).contains(&n) {
        return Err(TlogError::InvalidInput("1 <= n <= t".into()));
    }
    let indexes = tree_proof_index(0, t, n, vec![]);
    if indexes.is_empty() {
        return Ok(vec![]);
    }
    let hashes = h.read_hashes(&indexes)?;
    assert_eq!(
        hashes.len(),
        indexes.len(),
        "bad read_hashes implementation"
    );
    let (p, remaining_hashes) = tree_proof(0, t, n, hashes);
    assert!(remaining_hashes.is_empty(), "bad index math in prove_tree");
    Ok(p)
}

// Builds the list of indexes needed to construct
// the sub-proof related to the subtree containing records [lo, hi).
// See https://tools.ietf.org/html/rfc6962#section-2.1.2.
//
// # Panics
//
// Panics if there are internal math errors.
fn tree_proof_index(lo: u64, hi: u64, n: u64, mut need: Vec<u64>) -> Vec<u64> {
    // See treeProof below for commentary.
    assert!((lo + 1..=hi).contains(&n), "bad math in tree_proof_index");

    if n == hi {
        if lo == 0 {
            return need;
        }
        return sub_tree_index(lo, hi, need);
    }

    let (k, _) = maxpow2(hi - lo);
    if n <= lo + k {
        need = tree_proof_index(lo, lo + k, n, need);
        need = sub_tree_index(lo + k, hi, need);
    } else {
        need = sub_tree_index(lo, lo + k, need);
        need = tree_proof_index(lo + k, hi, n, need);
    }
    need
}

// Constructs the sub-proof related to the subtree containing records [lo, hi).
// It returns any leftover hashes as well.
// See https://tools.ietf.org/html/rfc6962#section-2.1.2.
//
// May panic if there are internal math errors.
fn tree_proof(lo: u64, hi: u64, n: u64, mut hashes: Vec<Hash>) -> (TreeProof, Vec<Hash>) {
    assert!((lo + 1..=hi).contains(&n), "bad math in tree_proof");

    // Reached common ground.
    if n == hi {
        if lo == 0 {
            // This subtree corresponds exactly to the old tree.
            // The verifier knows that hash, so we don't need to send it.
            return (vec![], hashes);
        }
        let (th, hashes) = sub_tree_hash(lo, hi, &hashes);
        return (vec![th], hashes);
    }

    // Interior node for the proof.
    // Decide whether to walk down the left or right side.
    let mut p: TreeProof;
    let th: Hash;
    let (k, _) = maxpow2(hi - lo);
    if n <= lo + k {
        // m is on left side
        (p, hashes) = tree_proof(lo, lo + k, n, hashes);
        (th, hashes) = sub_tree_hash(lo + k, hi, &hashes);
    } else {
        // m is on right side
        (th, hashes) = sub_tree_hash(lo, lo + k, &hashes);
        (p, hashes) = tree_proof(lo + k, hi, n, hashes);
    }
    p.push(th);
    (p, hashes)
}

/// Verifies that `p` is a valid proof that the tree of size `t` with hash `th`
/// contains as a prefix the tree of size `n` with hash `h`.
///
/// # Errors
///
/// Returns an error if the tree proof is invalid.
///
///# Panics
///
/// Panics if there are internal math errors.
pub fn check_tree(p: &TreeProof, t: u64, th: Hash, n: u64, h: Hash) -> Result<(), TlogError> {
    if !(1..=t).contains(&n) {
        return Err(TlogError::InvalidInput("1 <= n <= t".into()));
    }
    let (h2, th2) = run_tree_proof(p, 0, t, n, h)?;
    if th2 == th && h2 == h {
        Ok(())
    } else {
        Err(TlogError::InvalidProof)
    }
}

// Runs the sub-proof p related to the subtree containing records [lo, hi),
// where old is the hash of the old tree with n records.
// Running the proof means constructing and returning the implied hashes of that
// subtree in both the old and new tree.
//
// # Panics
//
// Panics if there are internal math errors.
fn run_tree_proof(
    p: &TreeProof,
    lo: u64,
    hi: u64,
    n: u64,
    old: Hash,
) -> Result<(Hash, Hash), TlogError> {
    assert!((lo + 1..=hi).contains(&n), "bad math in run_tree_proof");

    // Reached common ground.
    if n == hi {
        if lo == 0 {
            if !p.is_empty() {
                return Err(TlogError::InvalidProof);
            }
            return Ok((old, old));
        }
        if p.len() != 1 {
            return Err(TlogError::InvalidProof);
        }
        return Ok((p[0], p[0]));
    }

    if p.is_empty() {
        return Err(TlogError::InvalidProof);
    }

    // Interior node for the proof.
    let (k, _) = maxpow2(hi - lo);
    if n <= lo + k {
        let (oh, th) = run_tree_proof(&p[..p.len() - 1].to_vec(), lo, lo + k, n, old)?;
        Ok((oh, node_hash(th, p[p.len() - 1])))
    } else {
        let (oh, th) = run_tree_proof(&p[..p.len() - 1].to_vec(), lo + k, hi, n, old)?;
        Ok((node_hash(p[p.len() - 1], oh), node_hash(p[p.len() - 1], th)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tile::{Tile, TileHashReader, TileReader};
    use crate::PathElem;
    use std::cell::Cell;
    use std::collections::HashMap;

    type TestHashStorage = Vec<Hash>;

    impl HashReader for TestHashStorage {
        fn read_hashes(&self, indexes: &[u64]) -> Result<Vec<Hash>, TlogError> {
            // It's not required by HashReader that indexes be in increasing order,
            // but check that the functions we are testing only ever ask for
            // indexes in increasing order.
            let mut prev_index = 0;
            for (i, &index) in indexes.iter().enumerate() {
                if i != 0 && index <= prev_index {
                    return Err(TlogError::IndexesOutOfOrder);
                }
                prev_index = index;
            }

            let mut out = Vec::with_capacity(indexes.len());
            for &index in indexes {
                out.push(self[usize::try_from(index).unwrap()]);
            }
            Ok(out)
        }
    }

    #[derive(Default, Debug)]
    struct TestTilesStorage {
        // Make use of interior mutability here to avoid needing to make struct mutable for tests:
        // https://ricardomartins.cc/2016/06/08/interior-mutability
        unsaved: Cell<usize>,
        m: HashMap<Tile, Vec<u8>>,
    }

    impl TileReader for TestTilesStorage {
        fn height(&self) -> u8 {
            2
        }

        fn save_tiles(&self, tiles: &[Tile], _data: &[Vec<u8>]) {
            let new_size = self.unsaved.get() - tiles.len();
            self.unsaved.set(new_size);
        }

        fn read_tiles(&self, tiles: &[Tile]) -> Result<Vec<Vec<u8>>, TlogError> {
            let mut out = Vec::with_capacity(tiles.len());
            for tile in tiles {
                if let Some(data) = self.m.get(tile) {
                    out.push(data.clone());
                } else {
                    panic!("tile {tile:?} not found in map");
                }
            }
            let new_size = self.unsaved.get() + tiles.len();
            self.unsaved.set(new_size);
            Ok(out)
        }
    }

    #[test]
    fn test_tree() {
        const TEST_H: u8 = 2;

        let mut trees = Vec::new();
        let mut leafhashes = Vec::new();
        let mut storage = Vec::new();
        let mut tiles = HashMap::<Tile, Vec<u8>>::new();

        for i in 0..100 {
            let data = format!("leaf {i}");
            let hashes = stored_hashes(i, data.as_bytes(), &storage).unwrap();

            leafhashes.push(record_hash(data.as_bytes()));
            let old_storage_len = storage.len();
            storage.extend(hashes);

            assert_eq!(stored_hash_count(i + 1), storage.len() as u64);

            let th = tree_hash(i + 1, &storage).unwrap();

            for tile in Tile::new_tiles(TEST_H, i, i + 1) {
                let data = tile.read_data(&storage).unwrap();
                let default = Vec::new();
                let old_data = if tile.width() > 1 {
                    let old = Tile::new(
                        tile.height(),
                        tile.level(),
                        tile.level_index(),
                        tile.width() - 1,
                        None,
                    );
                    tiles.get(&old).unwrap_or(&default)
                } else {
                    &default
                };
                assert!(
                    old_data.len() == data.len() - HASH_SIZE && *old_data == data[..old_data.len()],
                    "tile {tile:?} not extending old tile"
                );
                tiles.insert(tile, data);
            }

            for tile in Tile::new_tiles(TEST_H, 0, i + 1) {
                let data = tile.read_data(&storage).unwrap();
                assert_eq!(tiles[&tile], data, "mismatch at {tile:?}");
            }

            for tile in Tile::new_tiles(TEST_H, i / 2, i + 1) {
                let data = tile.read_data(&storage).unwrap();
                assert_eq!(tiles[&tile], data, "mismatch at {tile:?}");
            }

            // Check that all the new hashes are readable from their tiles.
            for (j, stored_hash) in storage.iter().enumerate().skip(old_storage_len) {
                let tile = Tile::from_index(TEST_H, j as u64);
                let data = tiles.get(&tile).cloned().unwrap();
                let h = tile.hash_at_index(&data, j as u64).unwrap();
                assert_eq!(h, *stored_hash);
            }

            trees.push(th);

            // Check that leaf proofs work, for all trees and leaves so far.
            for j in 0..=i {
                let mut p = prove_record(i + 1, j, &storage).unwrap();
                check_record(&p, i + 1, th, j, leafhashes[usize::try_from(j).unwrap()]).unwrap();

                for k in 0..p.len() {
                    p[k].0[0] ^= 1;
                    assert!(
                        check_record(&p, i + 1, th, j, leafhashes[usize::try_from(j).unwrap()])
                            .is_err(),
                        "check_record({}, {j}) succeeded with corrupt proof hash #{k}!",
                        i + 1
                    );
                    p[k].0[0] ^= 1;
                }
            }

            // Check that leaf proofs work using TileReader.
            let tile_storage = TestTilesStorage {
                m: tiles.clone(),
                unsaved: Cell::new(0),
            };
            let thr = TileHashReader::new(i + 1, th, &tile_storage);
            for j in 0..=i {
                let h = thr.read_hashes(&[stored_hash_index(0, j)]).unwrap();
                assert_eq!(h.len(), 1, "bad read_hashes implementation");
                assert_eq!(h[0], leafhashes[usize::try_from(j).unwrap()], "wrong hash");

                // Even though reading the hash suffices, check we can generate the proof too.
                let p = prove_record(i + 1, j, &thr).unwrap();
                check_record(&p, i + 1, th, j, leafhashes[usize::try_from(j).unwrap()]).unwrap();
            }
            assert_eq!(tile_storage.unsaved.get(), 0, "did not save tiles");

            // Check that ReadHashes will give an error if the index is not in the tree.
            assert!(
                thr.read_hashes(&[(i + 1) * 2]).is_err(),
                "read_hashes returned non-err for index not in tree, want err"
            );

            assert_eq!(tile_storage.unsaved.get(), 0, "did not save tiles");

            // Check that tree proofs work, for all trees so far, using TileReader.
            for j in 0..=i {
                let h = tree_hash(j + 1, &thr).unwrap();
                assert_eq!(h, trees[usize::try_from(j).unwrap()]);

                // Even though computing the subtree hash suffices, check that we can generate the proof too.
                let mut p = prove_tree(i + 1, j + 1, &thr).unwrap();
                check_tree(&p, i + 1, th, j + 1, trees[usize::try_from(j).unwrap()]).unwrap();
                for k in 0..p.len() {
                    p[k].0[0] ^= 1;
                    assert!(
                        check_record(&p, i + 1, th, j + 1, trees[usize::try_from(j).unwrap()])
                            .is_err(),
                        "check_record({}, {j}) succeeded with corrupt proof hash #{k}!",
                        i + 1
                    );
                    p[k].0[0] ^= 1;
                }
            }
            assert_eq!(tile_storage.unsaved.get(), 0, "did not save tiles");
        }
    }

    #[test]
    fn test_split_stored_hash_index() {
        for l in 0..10 {
            for n in 0..100 {
                let x = stored_hash_index(l, n);
                let (l1, n1) = split_stored_hash_index(x);
                assert_eq!(l1, l);
                assert_eq!(n1, n);
            }
        }
    }

    #[test]
    fn test_tile_path() {
        let tile_paths = vec![
            ("tile/4/0/001", Some(Tile::new(4, 0, 1, 16, None))),
            ("tile/4/0/001.p/5", Some(Tile::new(4, 0, 1, 5, None))),
            (
                "tile/3/5/x123/x456/078",
                Some(Tile::new(3, 5, 123_456_078, 8, None)),
            ),
            (
                "tile/3/5/x123/x456/078.p/2",
                Some(Tile::new(3, 5, 123_456_078, 2, None)),
            ),
            (
                "tile/1/0/x003/x057/500",
                Some(Tile::new(1, 0, 3_057_500, 2, None)),
            ),
            ("tile/3/5/123/456/078", None),
            ("tile/3/-1/123/456/078", None),
            (
                "tile/1/data/x003/x057/500",
                Some(Tile::new(1, 0, 3_057_500, 2, Some(PathElem::Data))),
            ),
        ];

        for (path, want) in tile_paths {
            let got = Tile::from_path(path).ok();
            assert_eq!(want, got);
            if let Some(t) = want {
                assert_eq!(t.path(), path);
            }
        }
    }

    #[test]
    fn test_empty_tree() {
        let h = tree_hash(0, &TestHashStorage::new()).unwrap();
        assert_eq!(h, EMPTY_HASH);
    }
}
