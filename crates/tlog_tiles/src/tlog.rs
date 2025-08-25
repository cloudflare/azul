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
    #[error("recorded but did not read tiles")]
    RecordedTilesOnly,
    #[error("downloaded inconsistent tile")]
    InconsistentTile,
    #[error("indexes not in tree")]
    IndexesNotInTree,
    #[error("indexes out of order")]
    IndexesOutOfOrder,
    #[error("unmet input condition: {0}")]
    InvalidInput(String),
    #[error("missing verifier signature")]
    MissingVerifierSignature,
    #[error("timestamp is after current time")]
    InvalidTimestamp,
    #[error("checkpoint origin does not match")]
    OriginMismatch,
    #[error(transparent)]
    Note(#[from] signed_note::NoteError),
    #[error(transparent)]
    MalformedCheckpoint(#[from] crate::MalformedCheckpointTextError),
    #[error(transparent)]
    InvalidBase64(#[from] base64::DecodeError),
    #[error(transparent)]
    IO(#[from] std::io::Error),
}

/// `HashSize` is the size of a Hash in bytes.
pub const HASH_SIZE: usize = 32;

/// A Hash is a hash identifying a log record or tree root.
#[derive(Copy, Clone, Default, PartialEq)]
pub struct Hash(pub [u8; HASH_SIZE]);

/// A `Proof` is a verifiable Merkle Tree (subtree) inclusion or consistency
/// proof.
pub type Proof = Vec<Hash>;

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
    subtree_hash(&Subtree::new(0, n)?, r)
}

/// Computes the indexes needed to compute the hash of the tree with `n` records.
pub fn tree_hash_indexes(n: u64) -> Vec<u64> {
    if n == 0 {
        return vec![];
    }
    Subtree { lo: 0, hi: n }.hash_indexes()
}

/// Returns the storage indexes needed to compute the hash for the subtree.
/// See <https://tools.ietf.org/html/rfc6962#section-2.1>.
pub fn subtree_hash_indexes(n: &Subtree) -> Vec<u64> {
    n.hash_indexes()
}

/// Computes the hash for the root of the subtree `[lo, hi)`, using the
/// [`HashReader`] to obtain previously stored hashes (those returned by
/// [`stored_hashes`] during the writes of those `hi-lo` records).  `tree_hash`
/// makes a single call to [`HashReader::read_hashes`] requesting at most `1 +
/// log₂ (hi-lo)` hashes.
///
/// # Errors
///
/// Returns an error if `read_hashes` fails to read hashes or if the subtree is
/// invalid.
///
/// # Panics
///
/// Panics if `read_hashes` returns a slice of hashes that is not the same
/// length as the requested indexes, or if there are internal math errors.
pub fn subtree_hash<R: HashReader>(n: &Subtree, r: &R) -> Result<Hash, TlogError> {
    let indexes = n.hash_indexes();
    let mut hashes = r.read_hashes(&indexes)?;
    assert_eq!(
        hashes.len(),
        indexes.len(),
        "bad read_hashes implementation"
    );
    let hash = n.hash(&mut hashes);
    assert!(hashes.is_empty(), "bad math in subtree_hash");
    Ok(hash)
}

/// Returns the proof that the tree of size `n` contains the record with
/// index `leaf_index`.
///
/// # Errors
///
/// Returns an error if `read_hashes` fails to read hashes.
///
/// # Panics
///
/// Panics if `read_hashes` returns a slice of hashes that is not the same
/// length as the requested indexes, or if there are internal math errors.
pub fn inclusion_proof<R: HashReader>(n: u64, leaf_index: u64, r: &R) -> Result<Proof, TlogError> {
    subtree_inclusion_proof(&Subtree::new(0, n)?, leaf_index, r)
}

/// Returns the subproof that the subtree `n` contains the record with index
/// `leaf_index`.
///
/// # Errors
///
/// Returns an error if `read_hashes` fails to read hashes.
///
/// # Panics
///
/// Panics if `read_hashes` returns a slice of hashes that is not the same
/// length as the requested indexes, or if there are internal math errors.
pub fn subtree_inclusion_proof<R: HashReader>(
    n: &Subtree,
    leaf_index: u64,
    r: &R,
) -> Result<Proof, TlogError> {
    if !n.contains(leaf_index) {
        return Err(TlogError::InvalidInput("`lo <= leaf_index < hi`".into()));
    }

    let m = &Subtree::new(leaf_index, leaf_index + 1)?;

    // SUBTREE_PROOF(start, start + 1, D_n) = PATH(start, D_n)
    let indexes = n.subproof_indexes(m, true)?;

    if indexes.is_empty() {
        return Ok(vec![]);
    }
    let mut hashes = r.read_hashes(&indexes)?;
    assert_eq!(
        hashes.len(),
        indexes.len(),
        "bad read_hashes implementation"
    );
    // SUBTREE_PROOF(start, start + 1, D_n) = PATH(start, D_n)
    let proof = n.subproof(m, &mut hashes, true)?;
    assert!(
        hashes.is_empty(),
        "bad index math in prove_subtree_inclusion"
    );
    Ok(proof)
}

/// Returns the indexes required for the proof that the tree of size `n`
/// contains the record with index `leaf_index`.
///
/// # Errors
///
/// Returns an error if the `[lo, hi)` is not a valid subtree, or if
/// `leaf_index` is not in that subtree.
pub fn inclusion_proof_indexes(n: u64, leaf_index: u64) -> Result<Vec<u64>, TlogError> {
    subtree_inclusion_proof_indexes(&Subtree::new(0, n)?, leaf_index)
}

/// Returns the indexes required for the proof that the subtree `[lo, hi)`
/// contains the record with index `leaf_index`.
///
/// # Errors
///
/// Returns an error if the `[lo, hi)` is not a valid subtree, or if
/// `leaf_index` is not in that subtree.
pub fn subtree_inclusion_proof_indexes(
    n: &Subtree,
    leaf_index: u64,
) -> Result<Vec<u64>, TlogError> {
    // SUBTREE_PROOF(start, start + 1, D_n) = PATH(start, D_n)
    n.subproof_indexes(&Subtree::new(leaf_index, leaf_index + 1)?, true)
}

/// Verify an inclusion proof that the tree of size `tree_size` with root hash
/// `root_hash` contains a leaf at index `leaf_index` with hash `hash`. This
/// follows <https://www.rfc-editor.org/rfc/rfc9162#section-2.1.3.2>.
///
/// # Errors
///
/// Will return an error if proof verification fails.
pub fn verify_inclusion_proof(
    proof: &Proof,
    tree_size: u64,
    root_hash: Hash,
    leaf_index: u64,
    leaf_hash: Hash,
) -> Result<(), TlogError> {
    // 1. Compare leaf_index from the inclusion_proof_v2 structure against tree_size. If leaf_index is greater than or equal to tree_size, then fail the proof verification.
    if leaf_index >= tree_size {
        return Err(TlogError::InvalidProof);
    }
    // 2. Set fn to leaf_index and sn to tree_size - 1.
    let mut f_n = leaf_index;
    let mut s_n = tree_size - 1;
    // 3. Set r to hash.
    let mut r = leaf_hash;
    // 4. For each value p in the inclusion_path array:
    for p in proof {
        // a. If sn is 0, then stop the iteration and fail the proof verification.
        if s_n == 0 {
            return Err(TlogError::InvalidProof);
        }
        // b. If LSB(fn) is set, or if fn is equal to sn, then:
        if lsb_set(f_n) || f_n == s_n {
            // i. Set r to HASH(0x01 || p || r).
            r = node_hash(*p, r);
            // ii. If LSB(fn) is not set, then right-shift both fn and sn equally until either LSB(fn) is set or fn is 0.
            while !lsb_set(f_n) || f_n == 0 {
                f_n >>= 1;
                s_n >>= 1;
            }
        } else {
            // i. Set r to HASH(0x01 || r || p).
            r = node_hash(r, *p);
        }
        // c. Finally, right-shift both fn and sn one time.
        f_n >>= 1;
        s_n >>= 1;
    }
    // 5. Compare sn to 0. Compare r against the root_hash. If sn is equal to 0 and r and the root_hash are equal, then the log has proven the inclusion of hash. Otherwise, fail the proof verification.
    if s_n == 0 && r == root_hash {
        Ok(())
    } else {
        Err(TlogError::InvalidProof)
    }
}

/// Verify the proof that a leaf at index `leaf_index` and hash `leaf_hash` is
/// included in the subtree `[n_lo, n_hi)` with hash `n_hash`, following
/// <https://www.ietf.org/archive/id/draft-davidben-tls-merkle-tree-certs-06.html#section-4.2>.
///
/// # Errors
///
/// Will return an error if proof verification fails.
pub fn verify_subtree_inclusion_proof(
    proof: &Proof,
    n: &Subtree,
    n_hash: Hash,
    leaf_index: u64,
    leaf_hash: Hash,
) -> Result<(), TlogError> {
    verify_inclusion_proof(proof, n.hi - n.lo, n_hash, leaf_index - n.lo, leaf_hash)
}

/// Returns the proof that the tree of size `n` contains as a prefix all the
/// records from the tree of smaller size `m`.
///
/// # Errors
///
/// Returns an error if the inputs or proof are invalid or if `read_hashes`
/// fails to read hashes.
///
/// # Panics
///
/// Panics if `read_hashes` returns a slice of hashes that is not the same
/// length as the requested indexes, or if there are internal math errors.
pub fn consistency_proof<R: HashReader>(n: u64, m: u64, r: &R) -> Result<Proof, TlogError> {
    // SUBTREE_PROOF(0, end, D_n) = PROOF(end, D_n)
    subtree_consistency_proof(n, &Subtree::new(0, m)?, r)
}

/// Returns the proof that the tree of size `tree_size` is consistent with the
///  subtree `m` following
/// <https://www.ietf.org/archive/id/draft-davidben-tls-merkle-tree-certs-06.html#section-4.2>.
///
/// # Errors
///
/// Returns an error if the inputs or proof are invalid or if `read_hashes`
/// fails to read hashes.
///
/// # Panics
///
/// Panics if `read_hashes` returns a slice of hashes that is not the same
/// length as the requested indexes, or if there are internal math errors.
pub fn subtree_consistency_proof<R: HashReader>(
    tree_size: u64,
    m: &Subtree,
    r: &R,
) -> Result<Proof, TlogError> {
    let n = Subtree::new(0, tree_size)?;
    if !n.contains_subtree(m) {
        return Err(TlogError::InvalidInput(format!("{n} does not contain {m}")));
    }
    let indexes = n.subproof_indexes(m, true)?;
    if indexes.is_empty() {
        return Ok(vec![]);
    }
    let mut hashes = r.read_hashes(&indexes)?;
    assert_eq!(
        hashes.len(),
        indexes.len(),
        "bad read_hashes implementation"
    );
    let proof = n.subproof(m, &mut hashes, true)?;
    assert!(
        hashes.is_empty(),
        "bad index math in subtree_consistency_proof"
    );
    Ok(proof)
}

/// Builds the list of indexes needed to construct the proof that
/// the tree of size `n` contains as a prefix all the records from the tree of
/// smaller size `m`.
///
/// # Errors
///
/// Will return an error if the parameters are invalid.
pub fn consistency_proof_indexes(n: u64, m: u64) -> Result<Vec<u64>, TlogError> {
    subtree_consistency_proof_indexes(n, &Subtree::new(0, m)?)
}

/// Builds the list of indexes needed to construct the proof that the tree of
/// size `tree_size` is consistent with the subtree `m`.
///
/// # Errors
///
/// Will return an error if the parameters are invalid.
pub fn subtree_consistency_proof_indexes(
    tree_size: u64,
    m: &Subtree,
) -> Result<Vec<u64>, TlogError> {
    Subtree::new(0, tree_size)?.subproof_indexes(m, true)
}

/// Verify a consistency proof that the tree of size `n` with hash `root_hash`
/// contains the tree of size `m` with hash `m_hash` as a prefix. This follows
/// <https://www.rfc-editor.org/rfc/rfc9162#section-2.1.4.2>.
///
/// # Errors
///
/// Will return an error if proof verification fails.
pub fn verify_consistency_proof(
    proof: &Proof,
    n: u64,
    root_hash: Hash,
    m: u64,
    m_hash: Hash,
) -> Result<(), TlogError> {
    verify_subtree_consistency_proof(proof, n, root_hash, &Subtree::new(0, m)?, m_hash)
}

/// Verify a subtree consistency proof that the tree of size `n` with hash
/// `root_hash` is consistent with the subtree `m` with hash
/// `subtree_hash`. This follows
/// <https://www.ietf.org/archive/id/draft-davidben-tls-merkle-tree-certs-06.html#section-4.3.2>.
///
/// # Errors
///
/// Will return an error if proof verification fails.
pub fn verify_subtree_consistency_proof(
    proof: &Proof,
    n: u64,
    root_hash: Hash,
    m: &Subtree,
    subtree_hash: Hash,
) -> Result<(), TlogError> {
    let Subtree { lo: start, hi: end } = *m;
    // 1. If end is n, run the following:
    if end == n {
        // 1. Set fn to start and sn to end - 1.
        let mut f_n = start;
        let mut s_n = end - 1;
        // 2. Set r to node_hash.
        let mut r = subtree_hash;
        // 3. Right-shift fn and sn equally until LSB(fn) is set or sn is zero.
        while !(lsb_set(f_n) || s_n == 0) {
            f_n >>= 1;
            s_n >>= 1;
        }
        // 4. For each value p in the proof array:
        for p in proof {
            // 1. If sn is 0, then stop iteration and fail the proof verification.
            if s_n == 0 {
                return Err(TlogError::InvalidProof);
            }
            // 2. Set r to HASH(0x01, || p || r).
            r = node_hash(*p, r);
            // 3. If LSB(sn) is not set, the right-shift sn until either LSB(sn) is set or sn is zero.
            while !(lsb_set(s_n) || s_n == 0) {
                s_n >>= 1;
            }
            // 4. Right-shift once more.
            s_n >>= 1;
        }
        // 5. Check sn is 0 and r is root_hash. If either is not equal, fail the proof verification. If all are equal, accept the proof.
        if s_n == 0 && r == root_hash {
            Ok(())
        } else {
            Err(TlogError::InvalidProof)
        }
    }
    // 2. Otherwise, run the following:
    else {
        // 1. If proof is an empty array, stop and fail verification.
        if proof.is_empty() {
            return Err(TlogError::InvalidProof);
        }
        // 2. If end - start is an exact power of 2, prepend node_hash to the proof array.
        let mut proof = proof.clone();
        if (end - start).is_power_of_two() {
            proof.insert(0, subtree_hash);
        }
        // 3. Set fn to start, sn to end - 1, and tn to n - 1.
        let mut f_n = start;
        let mut s_n = end - 1;
        let mut t_n = n - 1;
        // 4. Right-shift fn, sn, and tn equally until LSB(sn) is not set or fn = sn.
        while lsb_set(s_n) && f_n != s_n {
            f_n >>= 1;
            s_n >>= 1;
            t_n >>= 1;
        }
        // 5. Set both fr and sr to the first value in the proof array.
        let mut f_r = proof[0];
        let mut s_r = proof[0];
        // 6. For each subsequent value c in the proof array:
        for c in proof.into_iter().skip(1) {
            // 1. If tn is 0, then stop the iteration and fail the proof verification.
            if t_n == 0 {
                return Err(TlogError::InvalidProof);
            }
            // 2. If LSB(sn) is set, or if sn is equal to tn, then:
            if lsb_set(s_n) || s_n == t_n {
                // 1. If fn < sn, set fr to HASH(0x01 || c || fr).
                if f_n < s_n {
                    f_r = node_hash(c, f_r);
                }
                // 2. Set sr to HASH(0x01 || c || sr).
                s_r = node_hash(c, s_r);
                // 3. If LSB(sn) is not set, then right-shift each of fn, sn, and tn equally until either LSB(sn) is set or sn is 0.
                while !lsb_set(s_n) {
                    f_n >>= 1;
                    s_n >>= 1;
                    t_n >>= 1;
                    if s_n == 0 {
                        break;
                    }
                }
            }
            // 3. Otherwise:
            else {
                // 1. Set sr to HASH(0x01 || sr || c).
                s_r = node_hash(s_r, c);
            }
            // 4. Finally, right-shift each of fn, sn, and tn one time.
            f_n >>= 1;
            s_n >>= 1;
            t_n >>= 1;
        }
        // 7. Check tn is 0, fr is node_hash, and sr is root_hash. If any are not equal, fail the proof verification. If all are equal, accept the proof.
        if t_n == 0 && f_r == subtree_hash && s_r == root_hash {
            Ok(())
        } else {
            Err(TlogError::InvalidProof)
        }
    }
}

// Return whether LSB(i) is set.
fn lsb_set(i: u64) -> bool {
    (i & 1) == 1
}

/// A subtree of a Merkle Tree of size `n` is defined by two integers `lo` and `hi` such that:
/// - 0 ≤ lo < hi ≤ n
/// - if `s` is the smallest power of two `≥ hi - lo`, `lo` is a multple of `s`
#[derive(Debug, PartialEq, Eq)]
pub struct Subtree {
    lo: u64,
    hi: u64,
}

impl fmt::Display for Subtree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {})", self.lo, self.hi)
    }
}

impl Subtree {
    /// Returns a subtree for the given range.
    ///
    /// # Errors
    ///
    /// Will return an error if `[lo, hi)` is not a valid subtree.
    pub fn new(lo: u64, hi: u64) -> Result<Self, TlogError> {
        if lo >= hi {
            return Err(TlogError::InvalidInput("`lo < hi`".into()));
        }
        // `s` is the smallest power of 2 that is greater than or equal
        // to `lo - hi`.
        let s = {
            let n = hi - lo;
            let l = n.ilog2();
            // If n is not already a power of two, round up.
            if n > 1 << l {
                1 << (l + 1)
            } else {
                1 << l
            }
        };
        if lo & (s - 1) != 0 {
            return Err(TlogError::InvalidInput(
                "`lo` must be a multiple of the smallest power of two ≥ `hi - lo`".into(),
            ));
        }
        Ok(Self { lo, hi })
    }
    /// Return the lower (inclusive) bound on indices in the subtree.
    pub fn lo(&self) -> u64 {
        self.lo
    }
    /// Return the upper (exclusive) bound on indices in the subtree.
    pub fn hi(&self) -> u64 {
        self.hi
    }
    /// Return whether or not the subtree contains the given leaf index.
    pub fn contains(&self, leaf_index: u64) -> bool {
        (self.lo..self.hi).contains(&leaf_index)
    }
    /// Return whether or not the subtree contains the given subtree.
    fn contains_subtree(&self, other: &Subtree) -> bool {
        (self.lo..self.hi).contains(&other.lo) && (self.lo + 1..=self.hi).contains(&other.hi)
    }
    /// Return left and right children.
    fn children(&self) -> (Self, Self) {
        let (k, _) = maxpow2(self.hi - self.lo);
        (
            Self {
                lo: self.lo,
                hi: self.lo + k,
            },
            Self {
                lo: self.lo + k,
                hi: self.hi,
            },
        )
    }
    /// Returns a list of one or two subtrees that efficiently cover `[lo, hi)`.
    ///
    /// # Errors
    ///
    /// Will return an error if `lo ≤ hi`.
    pub fn split_interval(lo: u64, hi: u64) -> Result<(Self, Option<Self>), TlogError> {
        if lo >= hi {
            return Err(TlogError::InvalidInput("`lo < hi`".into()));
        }
        if hi - lo == 1 {
            return Ok((Self { lo, hi }, None));
        }
        let last = hi - 1;
        // Find where `lo` and `last`'s tree paths diverge. The two subtrees
        // will be on either side of the split.
        // SAFETY: `lo ^ last` is guaranteed to be non-zero, so `ilog2` won't panic.
        let split = (lo ^ last).ilog2();
        let mask = (1 << split) - 1;
        let mid = last & !mask;
        // Maximize the left endpoint. This is just before `lo`'s path leaves
        // the right edge of its new subtree.
        let left_split = (!lo & mask).ilog2() + 1;
        let left = lo & !((1 << left_split) - 1);

        Ok((Self { lo: left, hi: mid }, Some(Self { lo: mid, hi })))
    }
}

// Strategy used for combining items in `walk_subproof`.
#[derive(Clone, Copy)]
enum CombinationStrategy {
    /// For subproofs of indexes. Order is [sibling, recursive] on
    /// right-recursion in order to preserve index ordering.
    Index,
    /// For subproofs of hashes. Order is always [recursive, sibling].
    Hash,
}

impl Subtree {
    /// Helper function to compute the `MTH` traversal logic from
    /// <https://datatracker.ietf.org/doc/html/rfc9162#section-2.1.1>.
    ///
    /// Repeatedly partition the tree into a left side with 2^level nodes, for
    /// as large a level as possible, and a right side with the fringe and call
    /// `f` to update some state for each level.
    ///
    /// This function is generic over:
    /// - `F`: The type of closure that performs the action.
    fn walk_hash<F>(&self, f: &mut F)
    where
        F: FnMut(u8, u64),
    {
        let mut lo = self.lo;
        while lo < self.hi {
            let (k, level) = maxpow2(self.hi - lo + 1);
            assert!(lo & (k - 1) == 0 && lo < self.hi, "bad math in walk_hash");
            f(level, lo);
            lo += k;
        }
    }

    /// Returns the storage indexes needed to compute the subtree's root hash.
    /// See <https://tools.ietf.org/html/rfc6962#section-2.1>.
    ///
    /// # Panics
    ///
    /// Panics if there are internal math errors.
    fn hash_indexes(&self) -> Vec<u64> {
        let mut need = Vec::new();
        let mut get_indexes = |level: u8, lo: u64| {
            need.push(stored_hash_index(level, lo >> level));
        };
        self.walk_hash(&mut get_indexes);

        need
    }

    /// Computes the subtree's root hash, assuming that `hashes` are the hashes
    /// corresponding to the indexes returned by `hash_indexes`.  It consumes
    /// the requisite hashes from `hashes`.
    ///
    /// # Panics
    ///
    /// Panics if there are internal math errors.
    fn hash(&self, hashes: &mut Vec<Hash>) -> Hash {
        let mut num_hashes = 0;
        let mut get_hash = |_: u8, _: u64| {
            num_hashes += 1;
        };
        self.walk_hash(&mut get_hash);

        assert!(
            hashes.len() >= num_hashes,
            "not enough hashes for reconstruction"
        );

        // The indexes are sorted in increasing order. In order to compute the
        // root hash, start from the rightmost index and hash up.
        let root_hash = hashes
            .drain(0..num_hashes)
            .rev()
            .reduce(|fringe, sibling| node_hash(sibling, fringe))
            // This expect is safe because the loop to calculate num_tree ensures
            // it's > 0 if the subtree has a non-zero range.
            .expect("num_tree must be positive for a valid subtree range");

        root_hash
    }

    /// Helper function to implement the `SUBTREE_SUBPROOF` traversal logic from
    /// <https://www.ietf.org/archive/id/draft-davidben-tls-merkle-tree-certs-06.html#section-4.3.1>.
    ///
    /// This can used to construct (sub)tree inclusion proofs and (sub)tree
    /// consistency proofs. This implementation of the algorithm uses absolute
    /// indexes as opposed to the relative indexes described in the spec.
    ///
    /// In order to calculate either the storage hash indexes needed for the
    /// subproof or the subproof hashes, this function is generic over:
    /// - `T`: The type of item to be collected (`u64` or `Hash`).
    /// - `F`: The type of the closure that performs the action.
    ///
    /// When computing indexes, `strategy` indicates how to combine items.
    /// Indexes are kept in increasing order as that may make retrieval from
    /// backend storage more efficient, but for hashes the sibling node's hash
    /// is always appended to the recursive proof according to the spec.
    fn walk_subproof<T, F>(
        &self,
        m: &Subtree,
        known: bool,
        f: &mut F,
        strategy: CombinationStrategy,
    ) -> Result<Vec<T>, TlogError>
    where
        F: FnMut(&Subtree) -> Vec<T>,
    {
        if !self.contains_subtree(m) {
            return Err(TlogError::InvalidInput(format!(
                "{self} does not contain {m}"
            )));
        }
        // Base case: the subtrees are equal.
        if m == self {
            // If the subtree was one of the inputs it is `known` and there is
            // no need to return it.
            return if known { Ok(vec![]) } else { Ok(f(self)) };
        }

        // Recursive step: traverse the children.
        let (left, right) = self.children();
        if left.contains_subtree(m) {
            // Recurse on the left, fully include the right.
            let (mut recursive_proof, mut sibling) =
                (left.walk_subproof(m, known, f, strategy)?, f(&right));
            recursive_proof.append(&mut sibling);
            Ok(recursive_proof)
        } else {
            let (mut sibling, mut recursive_proof) = if right.contains_subtree(m) {
                // Fully include the left, recurse on the right.
                (f(&left), right.walk_subproof(m, known, f, strategy)?)
            } else {
                // `m` is split across children. Fully include the left, recurse
                // on right child of `m` with `known` set to false as the right
                // child of `m` was not one of the inputs to the algorithm.
                assert!(m.lo == self.lo, "bad math in subproof walk");
                let m_right = m.children().1;
                (f(&left), right.walk_subproof(&m_right, false, f, strategy)?)
            };

            match strategy {
                CombinationStrategy::Hash => {
                    // Always append the sibling to the end of the recursive proof.
                    recursive_proof.append(&mut sibling);
                    Ok(recursive_proof)
                }
                CombinationStrategy::Index => {
                    // Prepend the indexes needed to compute the sibling in
                    // order to keep the indexes in increasing order.
                    sibling.append(&mut recursive_proof);
                    Ok(sibling)
                }
            }
        }
    }

    /// Returns only the storage hash indexes needed for the subproof.
    fn subproof_indexes(&self, m: &Subtree, known: bool) -> Result<Vec<u64>, TlogError> {
        // Get all hash indexes for a given subtree.
        let mut get_indexes = |t: &Subtree| -> Vec<u64> { t.hash_indexes() };

        self.walk_subproof(m, known, &mut get_indexes, CombinationStrategy::Index)
    }

    /// Returns the hashes for the subproof.
    fn subproof(
        &self,
        m: &Subtree,
        hashes: &mut Vec<Hash>,
        known: bool,
    ) -> Result<Proof, TlogError> {
        // Reconstruct a single hash for a subtree and wrap it in a Vec.
        // The closure captures the mutable `hashes` vector to pass it to `reconstruct_hash`.
        let mut get_hash = |t: &Subtree| -> Vec<Hash> { vec![t.hash(hashes)] };

        // The closure's error type is Infallible, so we can safely unwrap.
        self.walk_subproof(m, known, &mut get_hash, CombinationStrategy::Hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tile::{Tile, TileHashReader, TileReader};
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

    #[allow(clippy::too_many_lines)]
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

            // Check that inclusion proofs work, for all trees and leaves so far.
            for j in 0..=i {
                let mut p = inclusion_proof(i + 1, j, &storage).unwrap();
                verify_inclusion_proof(&p, i + 1, th, j, leafhashes[usize::try_from(j).unwrap()])
                    .unwrap();

                for k in 0..p.len() {
                    p[k].0[0] ^= 1;
                    assert!(
                        verify_inclusion_proof(
                            &p,
                            i + 1,
                            th,
                            j,
                            leafhashes[usize::try_from(j).unwrap()]
                        )
                        .is_err(),
                        "verify_inclusion_proof({}, {j}) succeeded with corrupt proof hash #{k}!",
                        i + 1
                    );
                    p[k].0[0] ^= 1;
                }
            }

            // Check that inclusion proofs work using TileReader.
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
                let p = inclusion_proof(i + 1, j, &thr).unwrap();
                verify_inclusion_proof(&p, i + 1, th, j, leafhashes[usize::try_from(j).unwrap()])
                    .unwrap();
            }
            assert_eq!(tile_storage.unsaved.get(), 0, "did not save tiles");

            // Check that ReadHashes will give an error if the index is not in the tree.
            assert!(
                thr.read_hashes(&[(i + 1) * 2]).is_err(),
                "read_hashes returned non-err for index not in tree, want err"
            );

            assert_eq!(tile_storage.unsaved.get(), 0, "did not save tiles");

            // Check that consistency proofs work, for all trees so far, using TileReader.
            for j in 0..=i {
                let h = tree_hash(j + 1, &thr).unwrap();
                assert_eq!(h, trees[usize::try_from(j).unwrap()]);

                // Even though computing the subtree hash suffices, check that we can generate the proof too.
                let mut p = consistency_proof(i + 1, j + 1, &thr).unwrap();
                verify_consistency_proof(&p, i + 1, th, j + 1, trees[usize::try_from(j).unwrap()])
                    .unwrap();
                for k in 0..p.len() {
                    p[k].0[0] ^= 1;
                    assert!(
                        verify_consistency_proof(
                            &p,
                            i + 1,
                            th,
                            j + 1,
                            trees[usize::try_from(j).unwrap()]
                        )
                        .is_err(),
                        "verify_consistency_proof({}, {j}) succeeded with corrupt proof hash #{k}!",
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
    fn test_new_subtree() {
        // Valid subtrees.
        assert!(Subtree::new(0, 1).is_ok());
        assert!(Subtree::new(36, 39).is_ok());

        // Invalid subtrees.
        assert!(Subtree::new(39, 36).is_err());
        assert!(Subtree::new(123, 456).is_err());
        assert!(Subtree::new(0, 0).is_err());
    }

    #[test]
    fn test_empty_tree() {
        assert_eq!(tree_hash(0, &TestHashStorage::new()).unwrap(), EMPTY_HASH);
    }

    #[test]
    fn test_subtrees_split_interval() {
        assert_eq!(
            Subtree::split_interval(123, 124).unwrap(),
            (Subtree::new(123, 124).unwrap(), None)
        );

        assert_eq!(
            Subtree::split_interval(1200, 1300).unwrap(),
            (
                Subtree::new(1152, 1280).unwrap(),
                Some(Subtree::new(1280, 1300).unwrap())
            )
        );
    }
}
