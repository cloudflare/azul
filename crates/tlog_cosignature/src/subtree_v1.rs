// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! `subtree/v1` cosignatures, per [c2sp.org/tlog-cosignature][spec].
//!
//! Compared to the older Ed25519 [`cosignature/v1`][cosignature_v1] format
//! (which is locked to checkpoints), `subtree/v1` is a cosignature that
//! signs an arbitrary subtree of the log. A "checkpoint cosignature" is
//! the special case `start = 0`, `end = checkpoint_size`.
//!
//! # What this module provides
//!
//! - [`build_cosigned_message`]: pure body builder for the
//!   [`cosigned_message`][spec] struct. Algorithm-independent — used by
//!   both the C2SP signed-note flow below and by other consumers (notably
//!   [draft-ietf-plants-merkle-tree-certs][mtc], which embeds the same
//!   body inside an X.509 certificate's `signatureValue`).
//! - [`timestamped_signature`]: pure wrapper builder for the
//!   `BE u64 timestamp || raw signature` blob used inside signed-note
//!   lines. Available as a building block for callers that need to
//!   produce signed-note lines but supply their own algorithm.
//! - [`SubtreeV1CheckpointSigner`] / [`SubtreeV1NoteVerifier`]:
//!   ML-DSA-44 signer / verifier for the C2SP-mandated signed-note
//!   variant. C2SP `tlog-cosignature` mandates ML-DSA-44 for
//!   `subtree/v1`; these types are spec-faithful and not generic.
//!
//! Consumers needing a different signature algorithm (e.g. an MTC CA
//! cosigner using ECDSA or RSA per its own X.509 SPKI) should use
//! [`build_cosigned_message`] (and [`timestamped_signature`] if they
//! need signed-note-line output) directly with their own signer/verifier
//! types; the algorithm-independent body builder is the abstraction
//! point.
//!
//! # Signed message
//!
//! The signed message is the [`cosigned_message`][spec] TLS-presentation
//! struct from the cosignature spec:
//!
//! ```text
//! struct {
//!     uint8 label[12] = "subtree/v1\n\0";
//!     opaque cosigner_name<1..2^8-1>;
//!     uint64 timestamp;
//!     opaque log_origin<1..2^8-1>;
//!     uint64 start;
//!     uint64 end;
//!     uint8 hash[32];
//! } cosigned_message;
//! ```
//!
//! `cosigner_name` is the cosigner's signed-note key name. `log_origin`
//! is the log's checkpoint-origin line *without* its trailing newline.
//!
//! `timestamp` is a POSIX-seconds value. It MAY be zero, in which case
//! no statement is made about the signing time or the largest observed
//! tree. If `start` is non-zero, `timestamp` MUST be zero. If
//! `timestamp` is non-zero, `end` MUST be the size of the largest
//! consistent tree the cosigner has observed for the log.
//!
//! # Wire format for signed-note lines
//!
//! The signed-note signature blob is the [`timestamped_signature`][spec]
//! struct: a big-endian `u64` timestamp prefix followed by the raw
//! algorithm-specific signature bytes. For ML-DSA-44 the signature is
//! 2420 bytes; [`SubtreeV1CheckpointSigner`] produces this layout
//! directly. Other consumers (e.g. MTC certificates) embed the raw
//! signature without the timestamp prefix; the timestamp is conveyed
//! by the `cosigned_message` body itself.
//!
//! # Key identity
//!
//! For the ML-DSA-44 signed-note variant, the key ID is derived per the
//! spec as
//! `SHA-256(<name> || "\n" || 0x06 || 1312-byte ML-DSA-44 cosigner public key)[:4]`.
//! Algorithm byte `0x06` is [`SignatureType::MlDsa44`]. Other consumers
//! that produce signed-note lines with different algorithms must derive
//! their own key IDs per the C2SP `signed-note` spec.
//!
//! [spec]: https://c2sp.org/tlog-cosignature
//! [mtc]: https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/
//! [cosignature_v1]: crate::cosignature_v1
//! [`SignatureType::MlDsa44`]: signed_note::SignatureType::MlDsa44

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use length_prefixed::WriteLengthPrefixedBytesExt;
use ml_dsa::{
    signature::{Signer as MlDsaSigner, Verifier as MlDsaVerifier},
    EncodedSignature as MlDsaEncodedSignature, ExpandedSigningKey as MlDsaExpandedSigningKey,
    MlDsa44, Signature as MlDsaSignature, VerifyingKey as MlDsaVerifyingKey,
};
use signed_note::{KeyName, NoteError, NoteSignature, NoteVerifier, SignatureType};
use tlog_tiles::{CheckpointSigner, CheckpointText, Hash, Subtree, UnixTimestamp, HASH_SIZE};

/// The fixed 12-byte label prefix domain-separating `subtree/v1` from
/// other cosignature formats.
const LABEL: &[u8; 12] = b"subtree/v1\n\0";

/// The encoded ML-DSA-44 signature length per FIPS 204.
///
/// Derived from the public [`MlDsaEncodedSignature<MlDsa44>`] type
/// rather than hardcoded: that type is `hybrid_array::Array<u8, N>`
/// which is `#[repr(transparent)]` over `[u8; N]`, so its `size_of`
/// equals the parameterized signature length the `ml-dsa` crate uses
/// internally. The `SignatureParams` trait carrying the `SignatureSize`
/// associated type is in a private module (`ml_dsa::param`) and so
/// can't be named in projection syntax from outside the crate.
///
/// `subtree/v1` currently has a single codepoint
/// (`SignatureType::MlDsa44 = 0x06`). If `tlog-cosignature` allocates
/// further codepoints, the parser/verifier helpers would generalize
/// over a per-algorithm descriptor and this constant would be
/// replaced.
const MLDSA_44_SIGNATURE_LEN: usize = core::mem::size_of::<MlDsaEncodedSignature<MlDsa44>>();

/// The size in bytes of the ML-DSA-44 `timestamped_signature` blob: a
/// big-endian `u64` timestamp prefix followed by the
/// [`MLDSA_44_SIGNATURE_LEN`]-byte ML-DSA-44 signature.
const TIMESTAMPED_SIGNATURE_LEN: usize = 8 + MLDSA_44_SIGNATURE_LEN;

/// Build the [`cosigned_message`][spec] bytes for a `subtree/v1`
/// cosignature.
///
/// This is the algorithm-independent body that every `subtree/v1`
/// signature is computed over. Both the [C2SP `tlog-cosignature`][spec]
/// signed-note flow ([`SubtreeV1CheckpointSigner`]) and other consumers
/// (notably [draft-ietf-plants-merkle-tree-certs][mtc] CA cosigners,
/// which sign with PKIX-defined algorithms and embed the raw signature
/// inside an X.509 `signatureValue`) call this builder to produce the
/// bytes they then sign with their own primitive.
///
/// `log_origin` is the checkpoint origin line *without* a trailing
/// newline. `cosigner_name` is the signed-note key name of the cosigner.
///
/// `start` and `end` are taken as bare `u64`s rather than a typed
/// [`Subtree`] because this builder is the low-level entry point for
/// consumers that have already validated their inputs upstream (e.g.
/// an MTC CA cosigner that constructed the `(start, end)` pair from a
/// log it operates). Callers MUST ensure `[start, end)` is a valid
/// subtree per [`Subtree::new`]'s contract; the higher-level
/// [`SubtreeV1CheckpointSigner::sign_subtree`] and
/// [`SubtreeV1NoteVerifier::verify_subtree`] entry points take a
/// [`&Subtree`] and so enforce this at the type level.
///
/// # Panics
///
/// Panics if `log_origin` is empty or longer than 255 bytes — the
/// `cosigned_message` struct's `log_origin<1..2^8-1>` field is TLS-style
/// length-prefixed and cannot encode either case. The `cosigner_name`
/// length is already enforced at construction time by
/// [`KeyName::new`][signed_note::KeyName::new], which caps at
/// [`KeyName::MAX_LEN`][signed_note::KeyName::MAX_LEN] = 255 bytes for
/// exactly this reason.
///
/// The internal `unwrap` calls on `Vec<u8>` writes cannot fail; they
/// are infallible operations on a growable buffer.
///
/// [spec]: https://c2sp.org/tlog-cosignature
/// [mtc]: https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/
#[must_use]
pub fn build_cosigned_message(
    cosigner_name: &KeyName,
    timestamp: u64,
    log_origin: &str,
    start: u64,
    end: u64,
    hash: &Hash,
) -> Vec<u8> {
    let name_bytes = cosigner_name.as_str().as_bytes();
    let origin_bytes = log_origin.as_bytes();
    debug_assert!(
        (1..=255).contains(&name_bytes.len()),
        "cosigner_name violates KeyName length invariant",
    );
    assert!(
        (1..=255).contains(&origin_bytes.len()),
        "log_origin must be 1..=255 bytes per the spec",
    );

    let mut buf = Vec::with_capacity(
        LABEL.len() + 1 + name_bytes.len() + 8 + 1 + origin_bytes.len() + 8 + 8 + HASH_SIZE,
    );
    buf.extend_from_slice(LABEL);
    buf.write_length_prefixed(name_bytes, 1).unwrap();
    buf.write_u64::<BigEndian>(timestamp).unwrap();
    buf.write_length_prefixed(origin_bytes, 1).unwrap();
    buf.write_u64::<BigEndian>(start).unwrap();
    buf.write_u64::<BigEndian>(end).unwrap();
    buf.extend_from_slice(&hash.0);
    buf
}

/// Build the [`timestamped_signature`][spec] blob for a signed-note line:
/// a big-endian `u64` timestamp prefix followed by `raw_signature`.
///
/// This is the wire format for signed-note lines carrying a `subtree/v1`
/// cosignature, irrespective of signature algorithm. Consumers that
/// produce signed-note-line output but use an algorithm other than
/// ML-DSA-44 (e.g. an MTC log serving its own `sign-subtree` responses)
/// can call this directly. Consumers embedding raw signatures elsewhere
/// (e.g. inside an X.509 certificate's `signatureValue`) do not need
/// this wrapper; the signature is the bare algorithm output, and the
/// timestamp is conveyed via the [`cosigned_message`][spec] body alone.
///
/// `timestamp_unix_secs` MUST match the timestamp embedded in the
/// signed `cosigned_message` body — verifiers parse this prefix and
/// re-derive the body to check the signature, so a mismatch fails
/// verification.
///
/// # Panics
///
/// Cannot panic. `Vec<u8>::write_u64` and `Vec::extend_from_slice` are
/// both infallible; the `unwrap` on the former is a syntactic
/// formality.
///
/// [spec]: https://c2sp.org/tlog-cosignature
#[must_use]
pub fn timestamped_signature(timestamp_unix_secs: u64, raw_signature: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(8 + raw_signature.len());
    blob.write_u64::<BigEndian>(timestamp_unix_secs).unwrap();
    blob.extend_from_slice(raw_signature);
    blob
}

// ---------------------------------------------------------------------------
// Signer
// ---------------------------------------------------------------------------

/// An ML-DSA-44 [`subtree/v1`][spec] cosigner.
///
/// Signs both checkpoint and arbitrary-subtree cosignatures. For the
/// checkpoint case the [`CheckpointSigner`] impl handles
/// `start = 0, end = checkpoint_size, hash = checkpoint_hash` from a
/// [`CheckpointText`]. For arbitrary subtrees, use [`Self::sign_subtree`]
/// directly.
///
/// [spec]: https://c2sp.org/tlog-cosignature
pub struct SubtreeV1CheckpointSigner {
    v: SubtreeV1NoteVerifier,
    k: MlDsaExpandedSigningKey<MlDsa44>,
}

impl SubtreeV1CheckpointSigner {
    /// Returns a new `SubtreeV1CheckpointSigner` from a name and signing key.
    ///
    /// The name's signed-note and length constraints (non-empty, no
    /// whitespace, no `+`, ≤ [`KeyName::MAX_LEN`] bytes) are
    /// guaranteed by [`KeyName::new`].
    ///
    /// [`KeyName::MAX_LEN`]: signed_note::KeyName::MAX_LEN
    #[must_use]
    pub fn new(name: KeyName, k: MlDsaExpandedSigningKey<MlDsa44>) -> Self {
        let vk = k.verifying_key();
        Self {
            v: SubtreeV1NoteVerifier::new(name, vk),
            k,
        }
    }

    /// Sign an arbitrary subtree, returning a `subtree/v1`
    /// [`NoteSignature`].
    ///
    /// `subtree` carries `(start, end)` as a `tlog_tiles::Subtree`,
    /// which has been validated at construction time to be a valid
    /// `[start, end)` subtree per draft-ietf-plants-merkle-tree-certs
    /// §4.1 (`start < end`, alignment to the next-power-of-two width).
    ///
    /// `timestamp_unix_secs` is the POSIX-seconds timestamp embedded in
    /// the [`cosigned_message`][spec]. Per the spec it MAY be zero, in
    /// which case no statement is made about the signing time or the
    /// largest observed tree.
    ///
    /// Note that for the checkpoint case (`subtree.lo() == 0`) the
    /// [c2sp.org/tlog-witness][witness] spec additionally REQUIRES a
    /// non-zero timestamp; passing zero here for the checkpoint case
    /// produces a spec-legal cosignature that is operationally useless
    /// for a witness response. This is not enforced by `sign_subtree`
    /// because the signer doesn't know the calling context — callers
    /// producing checkpoint cosignatures for witness use must supply a
    /// non-zero timestamp themselves. The [`CheckpointSigner`] impl
    /// forwards a millis timestamp from its caller and trusts that
    /// caller to set it correctly.
    ///
    /// # Panics
    ///
    /// Panics if `subtree.lo() != 0` and `timestamp_unix_secs != 0`
    /// (the spec requires `timestamp == 0` whenever `start != 0`), or
    /// if `log_origin` does not satisfy the TLS-presentation
    /// `opaque<1..2^8-1>` length bound.
    ///
    /// [spec]: https://c2sp.org/tlog-cosignature
    /// [witness]: https://c2sp.org/tlog-witness
    #[must_use]
    pub fn sign_subtree(
        &self,
        timestamp_unix_secs: u64,
        log_origin: &str,
        subtree: &Subtree,
        hash: &Hash,
    ) -> NoteSignature {
        assert!(
            !(subtree.lo() != 0 && timestamp_unix_secs != 0),
            "timestamp must be zero when start is non-zero",
        );

        let msg = build_cosigned_message(
            self.v.name(),
            timestamp_unix_secs,
            log_origin,
            subtree.lo(),
            subtree.hi(),
            hash,
        );
        let sig: MlDsaSignature<MlDsa44> = self.k.sign(&msg);
        let blob = timestamped_signature(timestamp_unix_secs, sig.encode().as_slice());
        NoteSignature::new(self.v.name().clone(), self.v.key_id(), blob)
    }
}

impl CheckpointSigner for SubtreeV1CheckpointSigner {
    fn name(&self) -> &KeyName {
        self.v.name()
    }

    fn key_id(&self) -> u32 {
        self.v.key_id()
    }

    fn sign(
        &self,
        timestamp_unix_millis: UnixTimestamp,
        checkpoint: &CheckpointText,
    ) -> Result<NoteSignature, NoteError> {
        // The checkpoint case fixes start = 0 and end = checkpoint_size.
        // `[0, n)` for any n > 0 is always a valid subtree (`0` is a
        // multiple of every power of 2); `Subtree::new(0, size)` only
        // fails for `size == 0`, where there is no meaningful subtree
        // to cosign.
        let subtree = Subtree::new(0, checkpoint.size()).map_err(|_| NoteError::Format)?;
        // The spec requires the witness to use a non-zero timestamp
        // for checkpoint cosignatures; we forward the caller-supplied
        // timestamp unchanged (in seconds), trusting them not to pass
        // zero in this path.
        Ok(self.sign_subtree(
            timestamp_unix_millis / 1000,
            checkpoint.origin(),
            &subtree,
            checkpoint.hash(),
        ))
    }

    fn verifier(&self) -> Box<dyn NoteVerifier> {
        Box::new(self.v.clone())
    }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Verifier for ML-DSA-44 `subtree/v1` cosignatures.
///
/// As a [`NoteVerifier`] this verifies the *checkpoint* case (`start = 0`,
/// `end = checkpoint_size`); the verifier reconstructs the
/// [`cosigned_message`][spec] from the checkpoint's origin, size, and
/// root hash. For arbitrary-subtree verification use
/// [`Self::verify_subtree`] directly with the `(start, end, hash)` the
/// caller already knows out of band.
///
/// [spec]: https://c2sp.org/tlog-cosignature
#[derive(Clone)]
pub struct SubtreeV1NoteVerifier {
    name: KeyName,
    id: u32,
    verifying_key: MlDsaVerifyingKey<MlDsa44>,
}

impl SubtreeV1NoteVerifier {
    /// Construct a new verifier from a key name and verifying key.
    #[must_use]
    pub fn new(name: KeyName, verifying_key: MlDsaVerifyingKey<MlDsa44>) -> Self {
        let pk_bytes = verifying_key.encode();
        let id = signed_note::compute_key_id(
            &name,
            &[SignatureType::MlDsa44 as u8],
            pk_bytes.as_slice(),
        );
        Self {
            name,
            id,
            verifying_key,
        }
    }

    /// Verify a subtree cosignature blob against an arbitrary
    /// `(subtree, hash)`.
    ///
    /// Returns `true` if `sig_blob` is a well-formed
    /// `timestamped_signature` (8-byte big-endian POSIX-seconds
    /// timestamp followed by a 2420-byte ML-DSA-44 signature) over
    /// the [`cosigned_message`][spec] for the given subtree. Returns
    /// `false` for any malformation, including when the spec's
    /// timestamp/start invariant is violated.
    ///
    /// `subtree` carries `(start, end)` as a `tlog_tiles::Subtree`,
    /// which has been validated at construction time; the previous
    /// runtime `start < end` check is now expressed in the type.
    ///
    /// [spec]: https://c2sp.org/tlog-cosignature
    #[must_use]
    pub fn verify_subtree(
        &self,
        log_origin: &str,
        subtree: &Subtree,
        hash: &Hash,
        sig_blob: &[u8],
    ) -> bool {
        let Some(timestamp) = parse_timestamped_signature_timestamp(sig_blob) else {
            return false;
        };
        // Spec: `timestamp` MUST be zero when `start` is non-zero.
        if subtree.lo() != 0 && timestamp != 0 {
            return false;
        }
        let Some(sig) = decode_signature(&sig_blob[8..]) else {
            return false;
        };
        let msg = build_cosigned_message(
            &self.name,
            timestamp,
            log_origin,
            subtree.lo(),
            subtree.hi(),
            hash,
        );
        MlDsaVerifier::verify(&self.verifying_key, &msg, &sig).is_ok()
    }
}

impl NoteVerifier for SubtreeV1NoteVerifier {
    fn name(&self) -> &KeyName {
        &self.name
    }

    fn key_id(&self) -> u32 {
        self.id
    }

    /// Verify a `subtree/v1` cosignature attached to a checkpoint note.
    ///
    /// `msg` is the checkpoint note body. The verifier parses it as a
    /// [`CheckpointText`] and reconstructs the [`cosigned_message`][spec]
    /// with `start = 0, end = checkpoint.size(), hash = checkpoint.hash()`.
    ///
    /// [spec]: https://c2sp.org/tlog-cosignature
    fn verify(&self, msg: &[u8], sig_blob: &[u8]) -> bool {
        let Ok(checkpoint) = CheckpointText::from_bytes(msg) else {
            return false;
        };
        // `[0, n)` for n > 0 is always a valid subtree; reject empty
        // checkpoints (size == 0) at this layer rather than panicking
        // inside `verify_subtree`.
        let Ok(subtree) = Subtree::new(0, checkpoint.size()) else {
            return false;
        };
        self.verify_subtree(checkpoint.origin(), &subtree, checkpoint.hash(), sig_blob)
    }

    /// Parse the timestamp prefix from a `timestamped_signature` blob
    /// and return it in milliseconds.
    ///
    /// This is a **parse-only** helper for callers that need to read a
    /// note signature's embedded timestamp before verifying the signature
    /// itself (e.g. for ordering, rate limiting, or coarse pruning).
    /// Returning `Ok(Some(_))` means the blob has the correct envelope
    /// shape (exactly [`TIMESTAMPED_SIGNATURE_LEN`] bytes — 8-byte
    /// timestamp + [`MLDSA_44_SIGNATURE_LEN`]-byte tail) and the prefix
    /// decodes as a `u64`. It does **not** mean the signature itself is
    /// valid, or that the timestamp is the one the signer actually
    /// committed to — the tail bytes are not parsed or verified here.
    /// Use [`Self::verify_subtree`] (or the [`NoteVerifier::verify`]
    /// path on this type) for that.
    ///
    /// Returns [`NoteError::Timestamp`] if the blob length is wrong, or
    /// if the seconds-to-millis conversion would overflow `u64`
    /// (impossible for any timestamp this side of POSIX year 5.85e14).
    fn extract_timestamp_millis(&self, sig_blob: &[u8]) -> Result<Option<u64>, NoteError> {
        let ts_secs =
            parse_timestamped_signature_timestamp(sig_blob).ok_or(NoteError::Timestamp)?;
        let ts_millis = ts_secs.checked_mul(1000).ok_or(NoteError::Timestamp)?;
        Ok(Some(ts_millis))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read the 8-byte big-endian timestamp prefix from a
/// `timestamped_signature` blob, returning `None` unless the blob is
/// exactly [`TIMESTAMPED_SIGNATURE_LEN`] bytes (8-byte timestamp prefix
/// + [`MLDSA_44_SIGNATURE_LEN`]-byte signature tail).
///
/// The exact-length check rejects malformed blobs at the parse layer
/// rather than deferring to the signature decode, so callers using this
/// helper for pre-verification ordering or rate-limiting can't be fed
/// an attacker-supplied timestamp inside an over-long envelope.
///
/// Hardcoded to the ML-DSA-44 envelope length today; would take an
/// algorithm descriptor when [`MLDSA_44_SIGNATURE_LEN`] does.
fn parse_timestamped_signature_timestamp(sig_blob: &[u8]) -> Option<u64> {
    if sig_blob.len() != TIMESTAMPED_SIGNATURE_LEN {
        return None;
    }
    let mut head = &sig_blob[..8];
    head.read_u64::<BigEndian>().ok()
}

/// Decode the [`MLDSA_44_SIGNATURE_LEN`]-byte ML-DSA-44 signature from
/// the tail of a `timestamped_signature` blob. See
/// [`MLDSA_44_SIGNATURE_LEN`] for the future-extension note.
fn decode_signature(bytes: &[u8]) -> Option<MlDsaSignature<MlDsa44>> {
    let encoded = MlDsaEncodedSignature::<MlDsa44>::try_from(bytes).ok()?;
    MlDsaSignature::<MlDsa44>::decode(&encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::ExpandedSigningKey;
    use tlog_tiles::HASH_SIZE;

    /// Construct a deterministic ML-DSA-44 expanded signing key from a
    /// 32-byte seed; the companion verifying key is derived via
    /// [`ExpandedSigningKey::verifying_key`].
    fn signing_key(seed_byte: u8) -> ExpandedSigningKey<MlDsa44> {
        let seed = ml_dsa::B32::from([seed_byte; 32]);
        ExpandedSigningKey::<MlDsa44>::from_seed(&seed)
    }

    fn name(s: &str) -> KeyName {
        KeyName::new(s.to_owned()).unwrap()
    }

    fn subtree(lo: u64, hi: u64) -> Subtree {
        Subtree::new(lo, hi).expect("valid test subtree")
    }

    /// Sign-then-verify roundtrip for a checkpoint cosignature
    /// (start = 0, end = size, non-zero timestamp).
    #[test]
    fn checkpoint_sign_verify_roundtrip() {
        let sk = signing_key(1);
        let signer = SubtreeV1CheckpointSigner::new(name("witness.example/w"), sk.clone());
        let sig = signer.sign_subtree(
            1_700_000_000,
            "log.example/origin",
            &subtree(0, 42),
            &Hash([0x33u8; HASH_SIZE]),
        );

        let verifier = SubtreeV1NoteVerifier::new(name("witness.example/w"), sk.verifying_key());
        assert!(verifier.verify_subtree(
            "log.example/origin",
            &subtree(0, 42),
            &Hash([0x33u8; HASH_SIZE]),
            sig.signature(),
        ));
    }

    /// Sign-then-verify roundtrip for a non-zero-start subtree
    /// cosignature (timestamp must be zero per the spec).
    #[test]
    fn subtree_sign_verify_roundtrip() {
        let sk = signing_key(2);
        let signer = SubtreeV1CheckpointSigner::new(name("ca.example/c"), sk.clone());
        let sig = signer.sign_subtree(
            0,
            "log.example/origin",
            &subtree(8, 16),
            &Hash([0x77u8; HASH_SIZE]),
        );

        let verifier = SubtreeV1NoteVerifier::new(name("ca.example/c"), sk.verifying_key());
        assert!(verifier.verify_subtree(
            "log.example/origin",
            &subtree(8, 16),
            &Hash([0x77u8; HASH_SIZE]),
            sig.signature(),
        ));
    }

    /// `verify_subtree` rejects when the spec invariant
    /// "timestamp == 0 if start != 0" is violated, even when ML-DSA
    /// verification of the underlying signature succeeds.
    #[test]
    fn verify_rejects_nonzero_timestamp_with_nonzero_start() {
        let sk = signing_key(3);
        let name = name("witness/w");
        let verifier = SubtreeV1NoteVerifier::new(name.clone(), sk.verifying_key());

        // Hand-craft a sig blob with a non-zero timestamp paired with
        // start=4. `build_cosigned_message` takes `(start, end)`
        // directly because callers may have already validated
        // upstream; the test goes through it to forge a
        // cryptographically-valid blob with the bad timestamp/start
        // combination.
        let msg = build_cosigned_message(&name, 12345, "log/origin", 4, 8, &Hash([0u8; HASH_SIZE]));
        let raw_sig: MlDsaSignature<MlDsa44> = sk.sign(&msg);
        let mut blob = Vec::new();
        blob.write_u64::<BigEndian>(12345).unwrap();
        blob.extend_from_slice(raw_sig.encode().as_slice());

        assert!(!verifier.verify_subtree(
            "log/origin",
            &subtree(4, 8),
            &Hash([0u8; HASH_SIZE]),
            &blob
        ));
    }

    /// `verify_subtree` rejects when the embedded `(subtree, hash)`
    /// don't match the bytes the signer signed.
    #[test]
    fn verify_rejects_mismatched_subtree() {
        let sk = signing_key(4);
        let signer = SubtreeV1CheckpointSigner::new(name("w"), sk.clone());
        let sig = signer.sign_subtree(0, "log", &subtree(0, 100), &Hash([0xAAu8; HASH_SIZE]));

        let verifier = SubtreeV1NoteVerifier::new(name("w"), sk.verifying_key());
        // Different subtree (and a valid one in its own right per
        // `Subtree::new`'s alignment rules).
        assert!(!verifier.verify_subtree(
            "log",
            &subtree(64, 128),
            &Hash([0xAAu8; HASH_SIZE]),
            sig.signature()
        ));
        // Same subtree but different hash.
        assert!(!verifier.verify_subtree(
            "log",
            &subtree(0, 100),
            &Hash([0xBBu8; HASH_SIZE]),
            sig.signature()
        ));
        // Different log origin.
        assert!(!verifier.verify_subtree(
            "other",
            &subtree(0, 100),
            &Hash([0xAAu8; HASH_SIZE]),
            sig.signature()
        ));
    }

    /// `NoteVerifier::verify` reconstructs the `cosigned_message` from a
    /// checkpoint note body and verifies the signature against
    /// `start = 0, end = size, hash = root`.
    #[test]
    fn note_verifier_verifies_checkpoint() {
        use signed_note::{Note, VerifierList};

        let sk = signing_key(5);
        let signer = SubtreeV1CheckpointSigner::new(name("witness/w"), sk.clone());

        // Build a checkpoint note body and sign with the CheckpointSigner
        // path. Timestamp is in millis; signer divides by 1000 internally.
        let cp_text = tlog_tiles::CheckpointText::new(
            "log.example/origin",
            42,
            Hash([0x55u8; HASH_SIZE]),
            &[],
        )
        .unwrap();
        let sig = signer.sign(1_700_000_000_000, &cp_text).unwrap();

        // Assemble the note + signature and verify via NoteVerifier.
        let note = Note::new(&cp_text.to_bytes(), &[sig]).unwrap();
        let (verified, _unverified) = note
            .verify(&VerifierList::new(vec![signer.verifier()]))
            .unwrap();
        assert_eq!(verified.len(), 1);
    }

    /// Pin the binary layout of the `cosigned_message` struct against
    /// known bytes, mirroring the format-fix tests other crates carry.
    /// Any change here would invalidate every previously-produced
    /// `subtree/v1` cosignature.
    #[test]
    fn cosigned_message_layout_unchanged() {
        let msg = build_cosigned_message(
            &name("a"), // 1-byte cosigner_name
            0x0102_0304_0506_0708,
            "b", // 1-byte log_origin
            0x0910_1112_1314_1516,
            0x1718_191a_1b1c_1d1e,
            &Hash([0x42u8; HASH_SIZE]),
        );

        let mut expected = Vec::new();
        expected.extend_from_slice(b"subtree/v1\n\x00");
        expected.push(1);
        expected.extend_from_slice(b"a");
        expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        expected.push(1);
        expected.extend_from_slice(b"b");
        expected.extend_from_slice(&0x0910_1112_1314_1516u64.to_be_bytes());
        expected.extend_from_slice(&0x1718_191a_1b1c_1d1eu64.to_be_bytes());
        expected.extend_from_slice(&[0x42u8; HASH_SIZE]);

        assert_eq!(msg, expected, "subtree/v1 cosigned_message layout changed");
    }

    /// Pin the key-ID derivation (algorithm byte `0x06`) against the spec.
    #[test]
    fn key_id_uses_signature_type_ml_dsa_44() {
        let sk = signing_key(6);
        let v = SubtreeV1NoteVerifier::new(name("witness.example/w"), sk.verifying_key());

        // Recompute manually with explicit 0x06 to confirm we got the
        // signed-note key-ID algorithm byte right.
        let pk_bytes = sk.verifying_key().encode();
        let expected = signed_note::compute_key_id(
            &name("witness.example/w"),
            &[0x06], // SignatureType::MlDsa44
            pk_bytes.as_slice(),
        );
        assert_eq!(v.key_id(), expected);
    }

    /// `extract_timestamp_millis` parses the BE-u64 prefix and returns
    /// it in milliseconds.
    #[test]
    fn extract_timestamp_millis_parses_prefix() {
        let sk = signing_key(7);
        let signer = SubtreeV1CheckpointSigner::new(name("w"), sk.clone());
        let sig = signer.sign_subtree(
            1_700_000_000,
            "log",
            &subtree(0, 1),
            &Hash([0u8; HASH_SIZE]),
        );
        let v = signer.verifier();
        let ts = v.extract_timestamp_millis(sig.signature()).unwrap();
        assert_eq!(ts, Some(1_700_000_000_000));
    }

    /// `extract_timestamp_millis` rejects blobs whose length doesn't match
    /// the `timestamped_signature` envelope exactly. Both a too-short
    /// blob and an over-long blob with otherwise-valid 8-byte prefix
    /// must be rejected at the parse layer so callers using the helper
    /// for pre-verification ordering can't be fed a timestamp inside
    /// a malformed envelope.
    #[test]
    fn extract_timestamp_millis_rejects_wrong_length() {
        let sk = signing_key(8);
        let v = SubtreeV1NoteVerifier::new(name("w"), sk.verifying_key());

        // Too short: 8 bytes — just a u64 prefix, no signature tail.
        let too_short = [0u8; 8];
        assert!(v.extract_timestamp_millis(&too_short).is_err());

        // Too long: TIMESTAMPED_SIGNATURE_LEN + 1 — looks like a
        // well-formed envelope plus one trailing byte. Pre-tightening
        // this would have decoded the prefix and returned a timestamp.
        let too_long = vec![0u8; TIMESTAMPED_SIGNATURE_LEN + 1];
        assert!(v.extract_timestamp_millis(&too_long).is_err());

        // Exact length is accepted (even with garbage tail — the helper
        // is parse-only).
        let exact = vec![0u8; TIMESTAMPED_SIGNATURE_LEN];
        assert_eq!(v.extract_timestamp_millis(&exact).unwrap(), Some(0));
    }

    /// `Subtree::new` rejects misaligned `(start, end)` per draft-ietf-
    /// plants-merkle-tree-certs §4.1, so callers of `sign_subtree` /
    /// `verify_subtree` cannot supply non-subtree inputs at all (the
    /// type system rules them out before the cosignature layer ever
    /// sees them). Pin the rejection here as a regression check.
    #[test]
    fn subtree_constructor_rejects_misaligned_pairs() {
        // `[3, 5)`: 3 is not a multiple of BIT_CEIL(2) = 2.
        assert!(Subtree::new(3, 5).is_err());
        // `[16, 100)`: 16 is not a multiple of BIT_CEIL(84) = 128.
        assert!(Subtree::new(16, 100).is_err());
        // `[5, 5)`: empty subtree (lo >= hi).
        assert!(Subtree::new(5, 5).is_err());
        // `[8, 16)`: 8 is a multiple of BIT_CEIL(8) = 8. ✓
        assert!(Subtree::new(8, 16).is_ok());
    }

    /// `extract_timestamp_millis` returns an error rather than wrapping
    /// or panicking when a malformed prefix would overflow seconds-to-
    /// millis multiplication.
    #[test]
    fn extract_timestamp_millis_rejects_overflow() {
        let sk = signing_key(9);
        let v = SubtreeV1NoteVerifier::new(name("w"), sk.verifying_key());

        // Build a well-shaped envelope with a u64 timestamp prefix
        // that overflows when multiplied by 1000.
        let mut blob = vec![0u8; TIMESTAMPED_SIGNATURE_LEN];
        blob[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(v.extract_timestamp_millis(&blob).is_err());
    }
}
