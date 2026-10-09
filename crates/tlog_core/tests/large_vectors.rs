// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Large subtree test vectors from draft-ietf-plants-merkle-tree-certs
//! Appendix C.2.
//!
//! These exercise trees bounded by 2^48-1, 2^63-1, and 2^64-1, which the
//! exhaustive Appendix C.1 vectors in the crate's unit tests do not reach.
//! The vectors are verify-only: no tree is built, so the inputs are the
//! published hashes and proofs rather than a [`tlog_core::HashReader`].
//!
//! The JSON fixtures under `tests/vectors/` are copied from the `demo`
//! directory of <https://github.com/ietf-plants-wg/merkle-tree-certs>,
//! referenced by Appendix C.2.2 and C.2.3.

use base64::prelude::*;
use serde::Deserialize;
use tlog_core::{
    Hash, Proof, Subtree, evaluate_subtree_inclusion_proof, verify_subtree_consistency_proof,
    verify_subtree_inclusion_proof,
};

#[derive(Deserialize)]
struct InclusionVector {
    #[serde(rename = "Index")]
    index: String,
    #[serde(rename = "Start")]
    start: String,
    #[serde(rename = "End")]
    end: String,
    #[serde(rename = "EntryHash")]
    entry_hash: Hash,
    #[serde(rename = "SubtreeHash")]
    subtree_hash: Hash,
    #[serde(rename = "Proof")]
    proof: String,
}

#[derive(Deserialize)]
struct ConsistencyVector {
    #[serde(rename = "Start")]
    start: String,
    #[serde(rename = "End")]
    end: String,
    #[serde(rename = "TreeSize")]
    tree_size: String,
    #[serde(rename = "SubtreeHash")]
    subtree_hash: Hash,
    #[serde(rename = "TreeHash")]
    tree_hash: Hash,
    #[serde(rename = "Proof")]
    proof: String,
}

/// Tree sizes exceed `2^53`, so the vectors encode integers as decimal strings.
fn u64_field(value: &str) -> u64 {
    value.parse().unwrap()
}

/// Proofs are a base64 concatenation of 32-byte hashes.
fn parse_proof(encoded: &str) -> Proof {
    let bytes = BASE64_STANDARD.decode(encoded).unwrap();
    assert_eq!(bytes.len() % 32, 0, "proof is not a whole number of hashes");
    bytes
        .as_chunks::<32>()
        .0
        .iter()
        .copied()
        .map(Hash)
        .collect()
}

fn flip_first_bit(hash: Hash) -> Hash {
    let mut flipped = hash;
    flipped.0[0] ^= 1;
    flipped
}

#[test]
#[ignore = "large MTC vectors; run with `cargo test -p tlog_core --test large_vectors -- --ignored`"]
fn large_subtree_validity_vectors() {
    for (start, end) in [
        (0, (1_u64 << 47) + 1),
        (0, (1_u64 << 48) - 1),
        (0, (1_u64 << 62) + 1),
        (0, (1_u64 << 63) - 1),
        (0, (1_u64 << 63) + 1),
        (0, u64::MAX),
    ] {
        assert!(Subtree::new(start, end).is_ok(), "[{start}, {end})");
    }
    for (start, end) in [
        (1_u64 << 46, (1_u64 << 47) + 1),
        (1_u64 << 46, (1_u64 << 48) - 1),
        (1_u64 << 61, (1_u64 << 62) + 1),
        (1_u64 << 61, (1_u64 << 63) - 1),
        (1_u64 << 62, (1_u64 << 63) + 1),
        (1_u64 << 62, u64::MAX),
    ] {
        assert!(Subtree::new(start, end).is_err(), "[{start}, {end})");
    }
}

#[test]
#[ignore = "large MTC vectors; run with `cargo test -p tlog_core --test large_vectors -- --ignored`"]
fn large_subtree_inclusion_proof_vectors() {
    let vectors: Vec<InclusionVector> =
        serde_json::from_str(include_str!("vectors/large_inclusion_proofs.json")).unwrap();
    assert_eq!(vectors.len(), 24);

    for vector in vectors {
        let index = u64_field(&vector.index);
        let start = u64_field(&vector.start);
        let end = u64_field(&vector.end);
        let subtree = Subtree::new(start, end).unwrap();
        let proof = parse_proof(&vector.proof);
        let label = format!("{index} [{start}, {end})");

        assert_eq!(
            evaluate_subtree_inclusion_proof(&proof, &subtree, index, vector.entry_hash).unwrap(),
            vector.subtree_hash,
            "{label}: evaluated subtree hash mismatch"
        );
        verify_subtree_inclusion_proof(
            &proof,
            &subtree,
            vector.subtree_hash,
            index,
            vector.entry_hash,
        )
        .unwrap();

        // Appendix C.2.2 inherits the C.1.2 negative obligations: a proof
        // truncated or extended by a hash must not verify. Byte-level
        // mutation is unrepresentable in `Proof`.
        if !proof.is_empty() {
            let mut truncated = proof.clone();
            truncated.pop();
            assert!(
                verify_subtree_inclusion_proof(
                    &truncated,
                    &subtree,
                    vector.subtree_hash,
                    index,
                    vector.entry_hash,
                )
                .is_err(),
                "{label}: truncated proof verified"
            );
        }
        let mut extended = proof.clone();
        extended.push(Hash::default());
        assert!(
            verify_subtree_inclusion_proof(
                &extended,
                &subtree,
                vector.subtree_hash,
                index,
                vector.entry_hash,
            )
            .is_err(),
            "{label}: extended proof verified"
        );
        assert!(
            verify_subtree_inclusion_proof(
                &proof,
                &subtree,
                flip_first_bit(vector.subtree_hash),
                index,
                vector.entry_hash,
            )
            .is_err(),
            "{label}: proof verified against a corrupted subtree hash"
        );
    }
}

#[test]
#[ignore = "large MTC vectors; run with `cargo test -p tlog_core --test large_vectors -- --ignored`"]
fn large_subtree_consistency_proof_vectors() {
    let vectors: Vec<ConsistencyVector> =
        serde_json::from_str(include_str!("vectors/large_consistency_proofs.json")).unwrap();
    assert_eq!(vectors.len(), 21);

    for vector in vectors {
        let start = u64_field(&vector.start);
        let end = u64_field(&vector.end);
        let tree_size = u64_field(&vector.tree_size);
        let subtree = Subtree::new(start, end).unwrap();
        let proof = parse_proof(&vector.proof);
        let label = format!("[{start}, {end}) {tree_size}");

        verify_subtree_consistency_proof(
            &proof,
            tree_size,
            vector.tree_hash,
            &subtree,
            vector.subtree_hash,
        )
        .unwrap();

        if !proof.is_empty() {
            let mut truncated = proof.clone();
            truncated.pop();
            assert!(
                verify_subtree_consistency_proof(
                    &truncated,
                    tree_size,
                    vector.tree_hash,
                    &subtree,
                    vector.subtree_hash,
                )
                .is_err(),
                "{label}: truncated proof verified"
            );
        }
        let mut extended = proof.clone();
        extended.push(Hash::default());
        assert!(
            verify_subtree_consistency_proof(
                &extended,
                tree_size,
                vector.tree_hash,
                &subtree,
                vector.subtree_hash,
            )
            .is_err(),
            "{label}: extended proof verified"
        );
        assert!(
            verify_subtree_consistency_proof(
                &proof,
                tree_size,
                vector.tree_hash,
                &subtree,
                flip_first_bit(vector.subtree_hash),
            )
            .is_err(),
            "{label}: proof verified against a corrupted subtree hash"
        );
        if start != end {
            assert!(
                verify_subtree_consistency_proof(
                    &proof,
                    tree_size,
                    flip_first_bit(vector.tree_hash),
                    &subtree,
                    vector.subtree_hash,
                )
                .is_err(),
                "{label}: proof verified against a corrupted tree hash"
            );
        }
    }
}

/// Sample ranges and their covering subtrees from Appendix C.2.4.
#[rustfmt::skip]
const COVERING_SUBTREES: [(u64, u64, u64, u64, u64, u64); 15] = [
    (0x0, 0x8000_0000_0000, 0x0, 0x4000_0000_0000, 0x4000_0000_0000, 0x8000_0000_0000),
    (0x5000_0000_0000, 0xd000_0000_0000, 0x4000_0000_0000, 0x8000_0000_0000, 0x8000_0000_0000, 0xd000_0000_0000),
    (0x7fff_ffff_ffff, 0x8000_0000_0001, 0x7fff_ffff_ffff, 0x8000_0000_0000, 0x8000_0000_0000, 0x8000_0000_0001),
    (0xffff_ffff_fffe, 0xffff_ffff_ffff, 0xffff_ffff_fffe, 0xffff_ffff_ffff, 0xffff_ffff_ffff, 0xffff_ffff_ffff),
    (0xffff_ffff_ffff, 0xffff_ffff_ffff, 0xffff_ffff_ffff, 0xffff_ffff_ffff, 0xffff_ffff_ffff, 0xffff_ffff_ffff),
    (0x0, 0x4000_0000_0000_0000, 0x0, 0x2000_0000_0000_0000, 0x2000_0000_0000_0000, 0x4000_0000_0000_0000),
    (0x2800_0000_0000_0000, 0x6800_0000_0000_0000, 0x2000_0000_0000_0000, 0x4000_0000_0000_0000, 0x4000_0000_0000_0000, 0x6800_0000_0000_0000),
    (0x3fff_ffff_ffff_ffff, 0x4000_0000_0000_0001, 0x3fff_ffff_ffff_ffff, 0x4000_0000_0000_0000, 0x4000_0000_0000_0000, 0x4000_0000_0000_0001),
    (0x7fff_ffff_ffff_fffe, 0x7fff_ffff_ffff_ffff, 0x7fff_ffff_ffff_fffe, 0x7fff_ffff_ffff_ffff, 0x7fff_ffff_ffff_ffff, 0x7fff_ffff_ffff_ffff),
    (0x7fff_ffff_ffff_ffff, 0x7fff_ffff_ffff_ffff, 0x7fff_ffff_ffff_ffff, 0x7fff_ffff_ffff_ffff, 0x7fff_ffff_ffff_ffff, 0x7fff_ffff_ffff_ffff),
    (0x0, 0x8000_0000_0000_0000, 0x0, 0x4000_0000_0000_0000, 0x4000_0000_0000_0000, 0x8000_0000_0000_0000),
    (0x5000_0000_0000_0000, 0xd000_0000_0000_0000, 0x4000_0000_0000_0000, 0x8000_0000_0000_0000, 0x8000_0000_0000_0000, 0xd000_0000_0000_0000),
    (0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0001, 0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000, 0x8000_0000_0000_0000, 0x8000_0000_0000_0001),
    (0xffff_ffff_ffff_fffe, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_fffe, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff),
    (0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff),
];

#[test]
#[ignore = "large MTC vectors; run with `cargo test -p tlog_core --test large_vectors -- --ignored`"]
fn large_covering_subtree_vectors() {
    for (start, end, left_start, left_end, right_start, right_end) in COVERING_SUBTREES {
        assert_eq!(
            Subtree::split_interval(start, end).unwrap(),
            (
                Subtree::new(left_start, left_end).unwrap(),
                Subtree::new(right_start, right_end).unwrap(),
            ),
            "[{start:#x}, {end:#x})"
        );
    }
}
