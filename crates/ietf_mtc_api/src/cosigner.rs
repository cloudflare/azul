// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Draft-06 MTC cosigner types for checkpoints, subtrees, and certificate proofs.
//!
//! Ed25519 and ML-DSA-44 signatures use the `subtree/v1` cosigned message. Checkpoint
//! signature values carry a POSIX-seconds timestamp prefix. Subtree signature values are
//! raw signatures and commit to timestamp zero.

use byteorder::{BigEndian, ReadBytesExt};
use ed25519_dalek::pkcs8::EncodePublicKey as Ed25519EncodePublicKey;
use ed25519_dalek::{
    SigningKey as Ed25519SigningKey, Verifier as Ed25519Verifier,
    VerifyingKey as Ed25519VerifyingKey,
    ed25519::signature::{self, Signer as Ed25519SignerTrait},
};
use ml_dsa::{
    EncodedSignature as MlDsaEncodedSignature, ExpandedSigningKey as MlDsaExpandedSigningKey,
    MlDsa44, Signature as MlDsaSignature, VerifyingKey as MlDsaVerifyingKey,
    signature::Verifier as MlDsaVerifier,
};
use pkcs8::EncodePublicKey as PkcsEncodePublicKey;
use signed_note::{KeyName, NoteError, NoteSignature, NoteVerifier, SignatureType};
use std::collections::BTreeMap;
use tlog_checkpoint::{CheckpointSigner, CheckpointText, UnixTimestampMillis};
use tlog_core::{HASH_SIZE, Hash, LeafIndex, Subtree};
use tlog_cosignature::subtree_v1::{build_cosigned_message, checkpoint_cosignature};

use crate::RelativeOid;

pub type TrustAnchorID = RelativeOid;

// ---------------------------------------------------------------------------
// Multi-algorithm key types
// ---------------------------------------------------------------------------

/// A signing key for MTC checkpoint and subtree cosignatures.
// ML-DSA signing key is ~2.5× the size of Ed25519's; the enum is always used
// behind indirection (via `MtcCosigner`) so the size difference is not a
// hot-path concern.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum MtcSigningKey {
    Ed25519(Ed25519SigningKey),
    MlDsa44(MlDsaExpandedSigningKey<MlDsa44>),
}

/// A verifying key for MTC checkpoint and subtree cosignatures.
// ML-DSA verifying key is much larger than Ed25519's; see note on MtcSigningKey.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum MtcVerifyingKey {
    Ed25519(Ed25519VerifyingKey),
    MlDsa44(MlDsaVerifyingKey<MlDsa44>),
}

impl MtcSigningKey {
    /// Sign `msg`, returning the signature bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails. Not possible with current variants,
    /// but future algorithms (e.g. randomized schemes requiring entropy) may
    /// be fallible.
    pub fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
        Ok(match self {
            Self::Ed25519(sk) => sk.sign(msg).to_bytes().to_vec(),
            Self::MlDsa44(sk) => sk.sign(msg).encode().as_slice().to_vec(),
        })
    }
}

impl MtcVerifyingKey {
    fn signature_len(&self) -> usize {
        match self {
            Self::Ed25519(_) => ed25519_dalek::SIGNATURE_LENGTH,
            Self::MlDsa44(_) => core::mem::size_of::<MlDsaEncodedSignature<MlDsa44>>(),
        }
    }

    fn note_key_id(&self, name: &KeyName) -> u32 {
        match self {
            Self::Ed25519(key) => {
                signed_note::compute_key_id(name, &[SignatureType::Ed25519 as u8], &key.to_bytes())
            }
            Self::MlDsa44(key) => signed_note::compute_key_id(
                name,
                &[SignatureType::MlDsa44 as u8],
                key.encode().as_slice(),
            ),
        }
    }

    fn verify(&self, msg: &[u8], sig_bytes: &[u8]) -> bool {
        match self {
            Self::Ed25519(vk) => {
                let Ok(sig_arr) = sig_bytes.try_into() else {
                    return false;
                };
                let sig = ed25519_dalek::Signature::from_bytes(sig_arr);
                Ed25519Verifier::verify(vk, msg, &sig).is_ok()
            }
            Self::MlDsa44(vk) => MlDsaEncodedSignature::<MlDsa44>::try_from(sig_bytes)
                .ok()
                .and_then(|enc| MlDsaSignature::<MlDsa44>::decode(&enc))
                .is_some_and(|sig| MlDsaVerifier::verify(vk, msg, &sig).is_ok()),
        }
    }

    /// Return the DER-encoded `SubjectPublicKeyInfo` for this key. This includes the algorithm
    /// prefix to allow for distinguishing between key types.
    ///
    /// # Panics
    ///
    /// Panics if PKCS#8 encoding fails, which should never happen for a valid key.
    #[must_use]
    pub fn to_public_key_der(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(vk) => Ed25519EncodePublicKey::to_public_key_der(vk)
                .expect("Ed25519 SPKI encoding failed")
                .to_vec(),
            Self::MlDsa44(vk) => PkcsEncodePublicKey::to_public_key_der(vk)
                .expect("ML-DSA-44 SPKI encoding failed")
                .to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// MtcCosigner
// ---------------------------------------------------------------------------

pub struct MtcCosigner {
    v: MtcCheckpointNoteVerifier,
    k: MtcSigningKey,
}

impl MtcCosigner {
    /// Return a checkpoint cosigner from an `MtcSigningKey` and `MtcVerifyingKey`.
    ///
    /// # Errors
    ///
    /// Returns an error if an ID cannot be represented in the signature format.
    pub fn new_checkpoint(
        cosigner_id: TrustAnchorID,
        ca_id: &TrustAnchorID,
        log_number: u16,
        sk: MtcSigningKey,
        vk: MtcVerifyingKey,
    ) -> Result<Self, crate::MtcError> {
        Ok(Self {
            v: MtcCheckpointNoteVerifier::new(cosigner_id, ca_id, log_number, vk)?,
            k: sk,
        })
    }

    /// Compute a subtree cosignature as defined in
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs#name-signature-format>.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails. Future algorithm variants may be
    /// fallible; use this method when the error can be propagated.
    pub fn sign_subtree(
        &self,
        start: LeafIndex,
        end: LeafIndex,
        root_hash: &Hash,
    ) -> Result<Vec<u8>, signature::Error> {
        let serialized = build_cosigned_message(
            &self.v.name,
            0,
            &self.v.log_id.oid_name(),
            start,
            end,
            root_hash,
        );
        self.k.try_sign(&serialized)
    }

    /// Return the log ID.
    #[must_use]
    pub fn log_id(&self) -> &TrustAnchorID {
        &self.v.log_id
    }

    /// Return the cosigner ID.
    #[must_use]
    pub fn cosigner_id(&self) -> &TrustAnchorID {
        &self.v.cosigner_id
    }

    /// Return the DER-encoded `SubjectPublicKeyInfo` of the verifying key.
    /// This allows clients pulling the get from the /metadata endpoint to determine the algorithm.
    #[must_use]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.v.verifying_key.to_public_key_der()
    }
}

/// Support signing tlog-checkpoints. For checkpoints, the subtree start index is always 0.
impl CheckpointSigner for MtcCosigner {
    fn name(&self) -> &KeyName {
        self.v.name()
    }

    fn key_id(&self) -> u32 {
        self.v.key_id()
    }

    fn sign(
        &self,
        timestamp_unix_millis: UnixTimestampMillis,
        checkpoint: &CheckpointText,
    ) -> Result<NoteSignature, NoteError> {
        let timestamp = timestamp_unix_millis / 1000;
        let msg = build_cosigned_message(
            &self.v.name,
            timestamp,
            checkpoint.origin(),
            0,
            checkpoint.size(),
            checkpoint.hash(),
        );
        let sig = self.k.try_sign(&msg)?;
        Ok(NoteSignature::new(
            self.name().clone(),
            self.key_id(),
            checkpoint_cosignature(timestamp, &sig),
        ))
    }

    fn verifier(&self) -> Box<dyn NoteVerifier> {
        Box::new(self.v.clone())
    }
}

// ---------------------------------------------------------------------------
// MtcCheckpointNoteVerifier
// ---------------------------------------------------------------------------

/// Verifier for MTC checkpoint cosignatures (subtrees with `start = 0`).
///
/// Used with the tlog signed-note machinery to verify the `/checkpoint` endpoint
/// and `open_checkpoint` calls.
#[derive(Clone)]
pub struct MtcCheckpointNoteVerifier {
    cosigner_id: TrustAnchorID,
    log_id: TrustAnchorID,
    name: KeyName,
    id: u32,
    verifying_key: MtcVerifyingKey,
}

impl MtcCheckpointNoteVerifier {
    /// Construct a new checkpoint note verifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the IDs cannot be represented in their wire formats.
    pub fn new(
        cosigner_id: TrustAnchorID,
        ca_id: &TrustAnchorID,
        log_number: u16,
        verifying_key: MtcVerifyingKey,
    ) -> Result<Self, crate::MtcError> {
        let name = KeyName::new(cosigner_id.oid_name())
            .map_err(|error| crate::MtcError::Dynamic(format!("invalid cosigner ID: {error}")))?;
        let id = verifying_key.note_key_id(&name);
        Ok(Self {
            cosigner_id,
            log_id: ca_id.log_id(log_number)?,
            name,
            id,
            verifying_key,
        })
    }
}

impl NoteVerifier for MtcCheckpointNoteVerifier {
    fn name(&self) -> &KeyName {
        &self.name
    }

    fn key_id(&self) -> u32 {
        self.id
    }

    /// Verify a checkpoint cosignature. The `msg` is the raw checkpoint note body;
    /// it is parsed to extract the tree size and root hash, which are then used to
    /// reconstruct the `MTCSubtreeSignatureInput` with `start = 0`.
    fn verify(&self, msg: &[u8], sig_bytes: &[u8]) -> bool {
        let Ok(checkpoint) = CheckpointText::from_bytes(msg) else {
            return false;
        };
        if sig_bytes.len() != 8 + self.verifying_key.signature_len() {
            return false;
        }
        let mut timestamp_bytes = &sig_bytes[..8];
        let Ok(timestamp) = timestamp_bytes.read_u64::<BigEndian>() else {
            return false;
        };
        let msg = build_cosigned_message(
            &self.name,
            timestamp,
            checkpoint.origin(),
            0,
            checkpoint.size(),
            checkpoint.hash(),
        );
        self.verifying_key.verify(&msg, &sig_bytes[8..])
    }

    fn extract_timestamp_millis(&self, mut sig: &[u8]) -> Result<Option<u64>, NoteError> {
        if sig.len() != 8 + self.verifying_key.signature_len() {
            return Err(NoteError::Timestamp);
        }
        let timestamp = sig
            .read_u64::<BigEndian>()
            .map_err(|_| NoteError::Timestamp)?;
        Ok(Some(
            timestamp.checked_mul(1000).ok_or(NoteError::Timestamp)?,
        ))
    }
}

// ---------------------------------------------------------------------------
// MtcSubtreeNoteVerifier
// ---------------------------------------------------------------------------

/// Verifier for MTC subtree cosignatures in signed-note format (Appendix C.1/C.2).
///
/// Used when verifying subtree notes obtained from the `sign-subtree` endpoint
/// (Appendix C.2).
///
/// Note: certificates embed the raw signature bytes directly — use
/// [`ParsedMtcProof::verify_cosignature`] for those, which does not go through
/// the note machinery.
///
/// See <https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs#name-signature-format>.
#[derive(Clone)]
pub struct MtcSubtreeNoteVerifier {
    log_id: TrustAnchorID,
    name: KeyName,
    id: u32,
    verifying_key: MtcVerifyingKey,
}

impl MtcSubtreeNoteVerifier {
    /// Construct a new subtree note verifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the IDs cannot be represented in their wire formats.
    pub fn new(
        cosigner_id: &TrustAnchorID,
        ca_id: &TrustAnchorID,
        log_number: u16,
        verifying_key: MtcVerifyingKey,
    ) -> Result<Self, crate::MtcError> {
        let name = KeyName::new(cosigner_id.oid_name())
            .map_err(|error| crate::MtcError::Dynamic(format!("invalid cosigner ID: {error}")))?;
        let id = verifying_key.note_key_id(&name);
        Ok(Self {
            log_id: ca_id.log_id(log_number)?,
            name,
            id,
            verifying_key,
        })
    }
}

impl NoteVerifier for MtcSubtreeNoteVerifier {
    fn name(&self) -> &KeyName {
        &self.name
    }

    fn key_id(&self) -> u32 {
        self.id
    }

    /// Verify a subtree cosignature. The `msg` is the raw subtree note body in the
    /// Appendix C.1 text format (`<origin>\n<start> <end>\n<base64-hash>\n`); it is
    /// parsed to extract the subtree parameters, which are then used to reconstruct
    /// the `MTCSubtreeSignatureInput`.
    fn verify(&self, msg: &[u8], sig_bytes: &[u8]) -> bool {
        let Some((origin, start, end, hash)) = parse_subtree_note_body(msg) else {
            return false;
        };
        if origin != self.log_id.oid_name() || sig_bytes.len() != self.verifying_key.signature_len()
        {
            return false;
        }
        let msg = build_cosigned_message(&self.name, 0, &origin, start, end, &hash);
        self.verifying_key.verify(&msg, sig_bytes)
    }

    fn extract_timestamp_millis(&self, _sig: &[u8]) -> Result<Option<u64>, NoteError> {
        Ok(None)
    }
}

/// Parse a subtree note body in the Appendix C.1 text format:
/// ```text
/// <origin>\n<start> <end>\n<base64-hash>\n
/// ```
/// Returns `(start, end, hash)` on success, or `None` if the format is invalid.
fn parse_subtree_note_body(msg: &[u8]) -> Option<(String, LeafIndex, LeafIndex, Hash)> {
    let text = std::str::from_utf8(msg).ok()?;
    let mut lines = text.splitn(4, '\n');
    let origin = lines.next()?;
    let range_line = lines.next()?;
    let hash_line = lines.next()?;

    let mut parts = range_line.splitn(2, ' ');
    let start: LeafIndex = parts.next()?.parse().ok()?;
    let end: LeafIndex = parts.next()?.parse().ok()?;

    let hash_bytes = base64_decode_standard(hash_line)?;
    let hash_arr: [u8; 32] = hash_bytes.try_into().ok()?;
    if !lines.next()?.is_empty() {
        return None;
    }
    Some((origin.to_string(), start, end, Hash(hash_arr)))
}

fn base64_decode_standard(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

// ---------------------------------------------------------------------------
// Proof parsing and verification
// ---------------------------------------------------------------------------

/// A decoded `MTCProof` extracted from a certificate's `signatureValue`.
///
/// See draft-ietf-plants-merkle-tree-certs §6.1.
#[derive(Debug)]
pub struct ParsedMtcProof {
    /// Extensions copied from the log entry.
    pub extensions: Vec<crate::MerkleTreeCertEntryExtension>,
    /// Start of the covering subtree interval (inclusive).
    pub start: u64,
    /// End of the covering subtree interval (exclusive).
    pub end: u64,
    /// Merkle inclusion proof hashes.
    pub inclusion_proof: Vec<Hash>,
    /// Cosignatures keyed by `cosigner_id`.
    pub signatures: BTreeMap<TrustAnchorID, Vec<u8>>,
}

impl ParsedMtcProof {
    /// Parse an `MTCProof` from the raw `signatureValue` bytes of an MTC certificate.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are malformed.
    ///
    /// # Panics
    ///
    /// Panics if a 32-byte hash slice cannot be converted to a fixed-size array,
    /// which cannot happen since `chunks_exact(32)` guarantees the length.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, crate::MtcError> {
        let extensions = crate::read_extensions(&mut bytes)?;
        let start = read_u48(&mut bytes)?;
        let end = read_u48(&mut bytes)?;
        Subtree::new(start, end)?;

        // inclusion_proof: uint16-prefixed list of 32-byte hashes
        let proof_len = bytes.read_u16::<BigEndian>()? as usize;
        if bytes.len() < proof_len {
            return Err(crate::MtcError::Dynamic("truncated inclusion proof".into()));
        }
        let (proof_bytes, rest) = bytes.split_at(proof_len);
        bytes = rest;
        let (proof_hashes, remainder) = proof_bytes.as_chunks::<HASH_SIZE>();
        if !remainder.is_empty() {
            return Err(crate::MtcError::Dynamic(
                "inclusion proof is not hash-aligned".into(),
            ));
        }
        let inclusion_proof = proof_hashes.iter().copied().map(Hash).collect();

        // signatures: uint24-prefixed list of MtcSignature
        let sigs_len = read_u24(&mut bytes)?;
        if bytes.len() < sigs_len {
            return Err(crate::MtcError::Dynamic("truncated signatures".into()));
        }
        let mut sig_bytes = &bytes[..sigs_len];
        let mut signatures = BTreeMap::new();
        let mut previous_id: Option<Vec<u8>> = None;
        while !sig_bytes.is_empty() {
            let id_len = sig_bytes.read_u8()? as usize;
            if sig_bytes.len() < id_len {
                return Err(crate::MtcError::Dynamic("truncated cosigner_id".into()));
            }
            let id_raw = &sig_bytes[..id_len];
            if id_raw.is_empty()
                || previous_id.as_ref().is_some_and(|previous| {
                    (previous.len(), previous.as_slice()) >= (id_raw.len(), id_raw)
                })
            {
                return Err(crate::MtcError::Dynamic(
                    "cosigner IDs must be ordered and unique".into(),
                ));
            }
            sig_bytes = &sig_bytes[id_len..];
            let cosigner_id = TrustAnchorID::from_ber_bytes(id_raw)
                .map_err(|e| crate::MtcError::Dynamic(format!("invalid cosigner_id: {e}")))?;

            let signature_len = sig_bytes.read_u16::<BigEndian>()? as usize;
            if sig_bytes.len() < signature_len {
                return Err(crate::MtcError::Dynamic("truncated signature".into()));
            }
            let sig = sig_bytes[..signature_len].to_vec();
            sig_bytes = &sig_bytes[signature_len..];
            signatures.insert(cosigner_id, sig);
            previous_id = Some(id_raw.to_vec());
        }
        bytes = &bytes[sigs_len..];
        if !bytes.is_empty() {
            return Err(crate::MtcError::Dynamic("trailing proof bytes".into()));
        }

        Ok(Self {
            extensions,
            start,
            end,
            inclusion_proof,
            signatures,
        })
    }

    /// Verify that one of the proof's cosignatures is valid for the given
    /// subtree hash, cosigner verifying key, cosigner ID, and log ID.
    ///
    /// This verifies the raw `MTCSubtreeSignatureInput` bytes directly, bypassing
    /// the signed-note layer. For verifying subtree notes from the `sign-subtree`
    /// endpoint, use [`MtcSubtreeNoteVerifier`] instead.
    ///
    /// # Errors
    ///
    /// Returns an error if no matching cosignature is found or verification fails.
    pub fn verify_cosignature(
        &self,
        subtree_hash: &Hash,
        verifying_key: &MtcVerifyingKey,
        cosigner_id: &TrustAnchorID,
        ca_id: &TrustAnchorID,
        log_number: u16,
    ) -> Result<(), crate::MtcError> {
        let sig_bytes = self.signatures.get(cosigner_id).ok_or_else(|| {
            crate::MtcError::Dynamic(format!("no signature found for cosigner_id {cosigner_id}"))
        })?;
        let subtree = Subtree::new(self.start, self.end)?;
        let log_id = ca_id.log_id(log_number)?;
        let msg = build_cosigned_message(
            &KeyName::new(cosigner_id.oid_name())
                .map_err(|e| crate::MtcError::Dynamic(format!("invalid cosigner name: {e}")))?,
            0,
            &log_id.oid_name(),
            subtree.lo(),
            subtree.hi(),
            subtree_hash,
        );
        if verifying_key.verify(&msg, sig_bytes) {
            Ok(())
        } else {
            Err(crate::MtcError::Dynamic(
                "cosignature verification failed".into(),
            ))
        }
    }
}

fn read_u48(bytes: &mut &[u8]) -> Result<u64, crate::MtcError> {
    if bytes.len() < 6 {
        return Err(crate::MtcError::Dynamic("truncated uint48".into()));
    }
    let mut encoded = [0_u8; 8];
    encoded[2..].copy_from_slice(&bytes[..6]);
    *bytes = &bytes[6..];
    Ok(u64::from_be_bytes(encoded))
}

fn read_u24(bytes: &mut &[u8]) -> Result<usize, crate::MtcError> {
    if bytes.len() < 3 {
        return Err(crate::MtcError::Dynamic("truncated uint24".into()));
    }
    let value =
        (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]);
    *bytes = &bytes[3..];
    Ok(value)
}

#[cfg(test)]
mod tests {

    use tlog_checkpoint::{TreeWithTimestamp, open_checkpoint};
    use tlog_core::record_hash;

    use super::*;
    use signed_note::VerifierList;
    use std::str::FromStr;

    #[test]
    fn test_cosignature_v1_sign_verify() {
        let origin = "example.com/origin";
        let timestamp = 100_000;
        let tree_size = 4;

        // Make a tree head and sign it
        let tree = TreeWithTimestamp::new(tree_size, record_hash(b"hello world"), timestamp);
        let signer = {
            let sk = Ed25519SigningKey::generate(&mut rand::rng());
            let vk = sk.verifying_key();
            MtcCosigner::new_checkpoint(
                TrustAnchorID::from_str("1.2.3").unwrap(),
                &TrustAnchorID::from_str("4.5.6").unwrap(),
                1,
                MtcSigningKey::Ed25519(sk),
                MtcVerifyingKey::Ed25519(vk),
            )
            .unwrap()
        };
        let checkpoint = tree
            .sign(origin, &[], &[&signer], &mut rand::rng())
            .unwrap();

        // Now verify the signed checkpoint
        let verifier = signer.verifier();
        let (_, signed_at) = open_checkpoint(
            origin,
            &VerifierList::new(vec![verifier]),
            timestamp,
            &checkpoint,
        )
        .unwrap();
        assert_eq!(signed_at, Some(timestamp));
    }

    fn proof_bytes(ids: &[&[u8]], proof: &[u8]) -> Vec<u8> {
        let mut signatures = Vec::new();
        for id in ids {
            signatures.push(u8::try_from(id.len()).unwrap());
            signatures.extend_from_slice(id);
            signatures.extend_from_slice(&0_u16.to_be_bytes());
        }
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&0_u16.to_be_bytes());
        encoded.extend_from_slice(&[0; 6]);
        encoded.extend_from_slice(&[0, 0, 0, 0, 0, 1]);
        encoded.extend_from_slice(&u16::try_from(proof.len()).unwrap().to_be_bytes());
        encoded.extend_from_slice(proof);
        let sig_len = signatures.len();
        encoded.extend_from_slice(&[
            u8::try_from(sig_len >> 16).unwrap(),
            u8::try_from((sig_len >> 8) & 0xff).unwrap(),
            u8::try_from(sig_len & 0xff).unwrap(),
        ]);
        encoded.extend(signatures);
        encoded
    }

    #[test]
    fn proof_parser_is_strict() {
        assert!(ParsedMtcProof::from_bytes(&proof_bytes(&[&[1], &[2]], &[])).is_ok());
        assert!(ParsedMtcProof::from_bytes(&proof_bytes(&[&[2], &[1]], &[])).is_err());
        assert!(ParsedMtcProof::from_bytes(&proof_bytes(&[&[1], &[1]], &[])).is_err());
        assert!(ParsedMtcProof::from_bytes(&proof_bytes(&[], &[0; HASH_SIZE - 1])).is_err());

        let mut trailing = proof_bytes(&[], &[]);
        trailing.push(0);
        assert!(ParsedMtcProof::from_bytes(&trailing).is_err());

        let mut short_prefix = proof_bytes(&[], &[]);
        short_prefix.remove(short_prefix.len() - 1);
        assert!(ParsedMtcProof::from_bytes(&short_prefix).is_err());

        let mut duplicate_extensions = proof_bytes(&[], &[]);
        duplicate_extensions.splice(0..2, [0, 8, 0, 1, 0, 0, 0, 1, 0, 0]);
        assert!(ParsedMtcProof::from_bytes(&duplicate_extensions).is_err());
    }

    #[test]
    fn ml_dsa_subtree_signature_round_trip() {
        let sk = MlDsaExpandedSigningKey::<MlDsa44>::from_seed(&ml_dsa::B32::from([7; 32]));
        let vk = sk.verifying_key();
        let ca_id = TrustAnchorID::from_str("44363.5").unwrap();
        let signer = MtcCosigner::new_checkpoint(
            ca_id.clone(),
            &ca_id,
            3,
            MtcSigningKey::MlDsa44(sk),
            MtcVerifyingKey::MlDsa44(vk.clone()),
        )
        .unwrap();
        let hash = Hash([9; HASH_SIZE]);
        let signature = signer.sign_subtree(8, 16, &hash).unwrap();
        let mut signatures = BTreeMap::new();
        signatures.insert(ca_id.clone(), signature);
        let proof = ParsedMtcProof {
            extensions: Vec::new(),
            start: 8,
            end: 16,
            inclusion_proof: Vec::new(),
            signatures,
        };
        proof
            .verify_cosignature(&hash, &MtcVerifyingKey::MlDsa44(vk), &ca_id, &ca_id, 3)
            .unwrap();
    }

    #[test]
    fn ml_dsa_subtree_note_uses_raw_signature() {
        use base64::prelude::*;

        let sk = MlDsaExpandedSigningKey::<MlDsa44>::from_seed(&ml_dsa::B32::from([8; 32]));
        let vk = sk.verifying_key();
        let ca_id = TrustAnchorID::from_str("44363.5").unwrap();
        let signer = MtcCosigner::new_checkpoint(
            ca_id.clone(),
            &ca_id,
            3,
            MtcSigningKey::MlDsa44(sk),
            MtcVerifyingKey::MlDsa44(vk.clone()),
        )
        .unwrap();
        let verifier =
            MtcSubtreeNoteVerifier::new(&ca_id, &ca_id, 3, MtcVerifyingKey::MlDsa44(vk)).unwrap();
        let hash = Hash([9; HASH_SIZE]);
        let signature = signer.sign_subtree(8, 16, &hash).unwrap();
        let note = format!(
            "{}\n8 16\n{}\n",
            signer.log_id().oid_name(),
            BASE64_STANDARD.encode(hash.0)
        );

        assert_eq!(signature.len(), verifier.verifying_key.signature_len());
        assert!(verifier.verify(note.as_bytes(), &signature));
        assert_eq!(verifier.extract_timestamp_millis(&signature).unwrap(), None);

        let mut prefixed = vec![0; 8];
        prefixed.extend_from_slice(&signature);
        assert!(!verifier.verify(note.as_bytes(), &prefixed));
    }
}
