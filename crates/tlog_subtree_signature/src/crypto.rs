// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Binary signing format and signer/verifier abstraction for subtree
//! cosignatures.
//!
//! The current binary message format is `mtc-subtree/v1\n\0`, defined in
//! [draft-ietf-plants-merkle-tree-certs-02 §5.4.1][mtc-541]. This crate
//! anticipates the format being renamed / restructured when the `sign-subtree`
//! protocol migrates into its own C2SP specification (provisionally
//! `c2sp.org/tlog-subtree-signature`), so the public helpers below are named
//! without the `mtc-` prefix; the string `mtc-subtree/v1` appears only inside
//! `serialize_subtree_signature_input` where the wire format demands it.
//!
//! Signing and verification are abstracted by the [`RawSigner`] and
//! [`RawVerifier`] traits — this crate is algorithm-agnostic. Concrete
//! implementations (Ed25519, ML-DSA-44, …) live in downstream crates.
//!
//! [mtc-541]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-02.html#name-signature-format

use byteorder::{BigEndian, WriteBytesExt};
use length_prefixed::WriteLengthPrefixedBytesExt;
use signed_note::{KeyName, NoteError, NoteVerifier};
use tlog_tiles::{Hash, LeafIndex, HASH_SIZE};

use base64::prelude::*;

// ---------------------------------------------------------------------------
// Algorithm-agnostic signer / verifier traits
// ---------------------------------------------------------------------------

/// A signer producing raw signature bytes over an arbitrary byte message.
///
/// Implementations hold a private key and any algorithm-specific state. This
/// crate does not care which algorithm they use; the returned bytes are
/// whatever a paired [`RawVerifier`] will consume.
pub trait RawSigner {
    /// Sign `msg`, returning the algorithm's raw signature bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails (e.g. entropy exhaustion for
    /// randomized schemes).
    fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>, signature::Error>;
}

/// A verifier checking raw signature bytes against a message.
///
/// Implementations hold a public key. Paired with a [`RawSigner`] for the
/// same algorithm.
pub trait RawVerifier {
    /// Return true iff `sig` is a valid signature of `msg`.
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool;
}

// ---------------------------------------------------------------------------
// Binary signing input
// ---------------------------------------------------------------------------

/// Serialize the binary message a subtree signer signs, per
/// draft-ietf-plants-merkle-tree-certs-02 §5.4.1.
///
/// ```text
/// opaque HashValue[HASH_SIZE];
/// opaque TrustAnchorID<1..2^8-1>;
/// struct {
///     TrustAnchorID log_id;
///     uint64 start;
///     uint64 end;
///     HashValue hash;
/// } MTCSubtree;
/// struct {
///     uint8 label[16] = "mtc-subtree/v1\n\0";
///     TrustAnchorID cosigner_id;
///     MTCSubtree subtree;
/// } MTCSubtreeSignatureInput;
/// ```
///
/// The `cosigner_id` and `log_id` are opaque byte strings from this crate's
/// point of view; callers encode them in whatever scheme the spec demands
/// (today: BER-encoded `TrustAnchorID` relative OIDs from the MTC draft).
///
/// # Panics
///
/// Panics if writing to an internal buffer fails, which should never happen
/// for an in-memory `Vec`.
#[must_use]
pub fn serialize_subtree_signature_input(
    cosigner_id: &[u8],
    log_id: &[u8],
    start: LeafIndex,
    end: LeafIndex,
    root_hash: &Hash,
) -> Vec<u8> {
    let mut buffer: Vec<u8> = b"mtc-subtree/v1\n\x00".to_vec();
    buffer.write_length_prefixed(cosigner_id, 1).unwrap();
    buffer.write_length_prefixed(log_id, 1).unwrap();
    buffer.write_u64::<BigEndian>(start).unwrap();
    buffer.write_u64::<BigEndian>(end).unwrap();
    buffer.extend(root_hash.0);
    buffer
}

// ---------------------------------------------------------------------------
// Subtree signing
// ---------------------------------------------------------------------------

/// Sign a subtree, returning the raw signature bytes of
/// `signer` applied to [`serialize_subtree_signature_input`].
///
/// # Errors
///
/// Returns an error if `signer.try_sign` fails.
pub fn sign_subtree<S: RawSigner + ?Sized>(
    signer: &S,
    cosigner_id: &[u8],
    log_id: &[u8],
    start: LeafIndex,
    end: LeafIndex,
    root_hash: &Hash,
) -> Result<Vec<u8>, signature::Error> {
    let input = serialize_subtree_signature_input(cosigner_id, log_id, start, end, root_hash);
    signer.try_sign(&input)
}

// ---------------------------------------------------------------------------
// Note verifier over subtree-format notes
// ---------------------------------------------------------------------------

/// [`NoteVerifier`] that accepts a subtree signed note and validates the
/// attached signature against the `mtc-subtree/v1` binary format.
///
/// The [`NoteVerifier::verify`] input is the raw *note text* — the Appendix
/// C.1 format `<origin>\n<start> <end>\n<base64-hash>\n` — which this
/// implementation parses to reconstruct the binary signing input, then
/// delegates to the wrapped [`RawVerifier`].
///
/// The `name` and `key_id` exposed via the trait impl are whatever the
/// caller supplies at construction time; this crate does not prescribe a
/// name-format convention (MTC uses `oid/{id_rdna_trustanchor_id}.{log_id}`
/// with a key ID derived via `signed_note::compute_key_id` over
/// `\xffmtc-subtree/v1`, but that is a caller concern).
#[derive(Clone)]
pub struct SubtreeNoteVerifier<V: RawVerifier> {
    name: KeyName,
    key_id: u32,
    cosigner_id: Vec<u8>,
    log_id: Vec<u8>,
    verifier: V,
}

impl<V: RawVerifier> SubtreeNoteVerifier<V> {
    /// Build a verifier bound to a specific `(name, key_id, cosigner_id,
    /// log_id, verifier)`. The `name` and `key_id` are what incoming note
    /// signature lines must match for this verifier to consider them. The
    /// `cosigner_id` / `log_id` are the opaque bytes baked into the
    /// reconstructed binary signing input.
    pub fn new(
        name: KeyName,
        key_id: u32,
        cosigner_id: Vec<u8>,
        log_id: Vec<u8>,
        verifier: V,
    ) -> Self {
        Self {
            name,
            key_id,
            cosigner_id,
            log_id,
            verifier,
        }
    }
}

impl<V: RawVerifier> NoteVerifier for SubtreeNoteVerifier<V> {
    fn name(&self) -> &KeyName {
        &self.name
    }

    fn key_id(&self) -> u32 {
        self.key_id
    }

    fn verify(&self, msg: &[u8], sig_bytes: &[u8]) -> bool {
        let Some((start, end, hash)) = parse_subtree_note_body_for_verify(msg) else {
            return false;
        };
        let input =
            serialize_subtree_signature_input(&self.cosigner_id, &self.log_id, start, end, &hash);
        self.verifier.verify(&input, sig_bytes)
    }

    fn extract_timestamp_millis(&self, _sig: &[u8]) -> Result<Option<u64>, NoteError> {
        Ok(None)
    }
}

/// Minimal parser of the subtree note body text `<origin>\n<start> <end>\n<base64-hash>\n`.
///
/// Returns `None` on any malformation so that [`NoteVerifier::verify`] can
/// report "signature did not verify" without exposing parse errors. The
/// richer-error sibling is the private `parse_subtree_note_body` in
/// `lib.rs`, which [`crate::parse_sign_subtree_request`] uses to
/// distinguish error categories.
fn parse_subtree_note_body_for_verify(msg: &[u8]) -> Option<(LeafIndex, LeafIndex, Hash)> {
    let text = std::str::from_utf8(msg).ok()?;
    let mut lines = text.splitn(4, '\n');
    let _origin = lines.next()?;
    let range_line = lines.next()?;
    let hash_line = lines.next()?;

    let mut parts = range_line.splitn(2, ' ');
    let start: LeafIndex = parts.next()?.parse().ok()?;
    let end: LeafIndex = parts.next()?.parse().ok()?;
    if start > end {
        return None;
    }

    let hash_bytes = BASE64_STANDARD.decode(hash_line).ok()?;
    let hash_arr: [u8; HASH_SIZE] = hash_bytes.try_into().ok()?;
    Some((start, end, Hash(hash_arr)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the binary message layout: label + length-prefixed `cosigner_id` +
    /// length-prefixed `log_id` + BE u64 start + BE u64 end + 32-byte hash.
    ///
    /// Changing this format would invalidate every previously-produced
    /// subtree signature, so any change here must be paired with the
    /// corresponding spec-level version bump.
    #[test]
    fn serialize_subtree_signature_input_format_unchanged() {
        // These are BER-encoded `RelativeOID` values matching the MTC
        // `TrustAnchorID` encoding scheme from
        // draft-ietf-plants-merkle-tree-certs §4.1: each arc is a big-endian
        // base-128 integer with the continuation bit set on all but the last
        // byte. Representative values for a Cloudflare-style (experimental)
        // arc `1.3.6.1.4.1.44363.48.{1,2}`, matching the encoding used by
        // `bootstrap_mtc_api::RelativeOid` today.
        let cosigner_id = b"\x82\xda\x4b\x30\x02"; // RelativeOID 44363.48.2
        let log_id = b"\x82\xda\x4b\x30\x01"; // RelativeOID 44363.48.1
        let start: u64 = 0x0102_0304_0506_0708;
        let end: u64 = 0x0910_1112_1314_1516;
        let hash = Hash([0x42u8; HASH_SIZE]);
        let out = serialize_subtree_signature_input(cosigner_id, log_id, start, end, &hash);

        let mut expected = Vec::new();
        expected.extend_from_slice(b"mtc-subtree/v1\n\x00");
        expected.push(u8::try_from(cosigner_id.len()).unwrap());
        expected.extend_from_slice(cosigner_id);
        expected.push(u8::try_from(log_id.len()).unwrap());
        expected.extend_from_slice(log_id);
        expected.extend_from_slice(&start.to_be_bytes());
        expected.extend_from_slice(&end.to_be_bytes());
        expected.extend_from_slice(&[0x42u8; HASH_SIZE]);

        assert_eq!(out, expected, "mtc-subtree/v1 binary format changed");
    }

    /// A counting [`RawSigner`] that records the message it was asked to
    /// sign, so tests can assert the input [`sign_subtree`] hands off.
    struct CaptureSigner {
        captured: std::cell::RefCell<Option<Vec<u8>>>,
    }

    impl RawSigner for CaptureSigner {
        fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
            *self.captured.borrow_mut() = Some(msg.to_vec());
            Ok(vec![0xccu8; 64])
        }
    }

    #[test]
    fn sign_subtree_hands_off_expected_bytes() {
        let signer = CaptureSigner {
            captured: std::cell::RefCell::new(None),
        };
        let cosigner_id = b"\x05\x02";
        let log_id = b"\x05\x01";
        let hash = Hash([0x11u8; HASH_SIZE]);

        let sig = sign_subtree(&signer, cosigner_id, log_id, 4, 8, &hash).unwrap();
        assert_eq!(sig, vec![0xccu8; 64]);

        let captured = signer.captured.into_inner().unwrap();
        let expected = serialize_subtree_signature_input(cosigner_id, log_id, 4, 8, &hash);
        assert_eq!(captured, expected);
    }

    /// A toy verifier that accepts iff the signature bytes match a
    /// pre-canned value. Used to test `SubtreeNoteVerifier` without touching
    /// real crypto.
    struct ToyVerifier {
        expected_sig: Vec<u8>,
    }

    impl RawVerifier for ToyVerifier {
        fn verify(&self, _msg: &[u8], sig: &[u8]) -> bool {
            sig == self.expected_sig
        }
    }

    #[test]
    fn subtree_note_verifier_happy_path() {
        let cosigner_id = b"\x05\x02".to_vec();
        let log_id = b"\x05\x01".to_vec();
        let hash = Hash([0x77u8; HASH_SIZE]);
        let start = 4u64;
        let end = 8u64;

        // Build a raw signature that our ToyVerifier will accept.
        let canned_sig = vec![0xffu8; 64];
        let verifier = SubtreeNoteVerifier::new(
            KeyName::new("oid/test".to_owned()).unwrap(),
            0xdead_beef,
            cosigner_id.clone(),
            log_id.clone(),
            ToyVerifier {
                expected_sig: canned_sig.clone(),
            },
        );

        // Reconstruct the note body text that the verifier will parse.
        let hash_b64 = BASE64_STANDARD.encode(hash.0);
        let note_body = format!("oid/test\n{start} {end}\n{hash_b64}\n");

        assert!(verifier.verify(note_body.as_bytes(), &canned_sig));
        assert!(!verifier.verify(note_body.as_bytes(), b"wrong-sig"));
    }

    #[test]
    fn subtree_note_verifier_rejects_malformed_text() {
        let verifier = SubtreeNoteVerifier::new(
            KeyName::new("oid/test".to_owned()).unwrap(),
            0,
            Vec::new(),
            Vec::new(),
            ToyVerifier {
                expected_sig: vec![],
            },
        );
        // Non-UTF-8.
        assert!(!verifier.verify(&[0xff, 0xfe, 0xfd], &[]));
        // Missing range line.
        assert!(!verifier.verify(b"oid/test\n", &[]));
        // Non-numeric range.
        assert!(!verifier.verify(b"oid/test\nfour eight\nAAAA\n", &[]));
        // start > end.
        let hash_b64 = BASE64_STANDARD.encode([0u8; HASH_SIZE]);
        let body = format!("oid/test\n8 4\n{hash_b64}\n");
        assert!(!verifier.verify(body.as_bytes(), &[]));
    }

    /// The origin line (first line of the subtree note body) is not
    /// authenticated by the binary signing input — that input only covers
    /// `cosigner_id`, `log_id`, `start`, `end`, and the hash. Pin this
    /// behavior so nobody silently starts binding origin later without
    /// thinking through the spec implications.
    ///
    /// Concretely: two note bodies that differ only in their first-line
    /// origin must both verify against the same signature, provided
    /// `(start, end, hash)` match what was signed.
    #[test]
    fn subtree_note_verifier_does_not_authenticate_origin() {
        let cosigner_id = b"\x05\x02".to_vec();
        let log_id = b"\x05\x01".to_vec();
        let hash = Hash([0x33u8; HASH_SIZE]);
        let start = 0u64;
        let end = 16u64;

        let canned_sig = vec![0xcdu8; 64];
        let verifier = SubtreeNoteVerifier::new(
            KeyName::new("oid/test".to_owned()).unwrap(),
            0x1234_5678,
            cosigner_id,
            log_id,
            ToyVerifier {
                expected_sig: canned_sig.clone(),
            },
        );

        let hash_b64 = BASE64_STANDARD.encode(hash.0);
        let body_a = format!("oid/origin-a\n{start} {end}\n{hash_b64}\n");
        let body_b = format!("oid/origin-b\n{start} {end}\n{hash_b64}\n");

        // Same canned signature, different origins: both verify, because
        // origin is not part of the binary signing input.
        assert!(verifier.verify(body_a.as_bytes(), &canned_sig));
        assert!(verifier.verify(body_b.as_bytes(), &canned_sig));
    }
}
