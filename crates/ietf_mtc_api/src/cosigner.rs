// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

use byteorder::{BigEndian, WriteBytesExt};
use ed25519_dalek::Signer as Ed25519Signer;
use length_prefixed::WriteLengthPrefixedBytesExt;
use ml_dsa::{signature::Verifier as MlDsaVerifier, MlDsa44, MlDsa65, MlDsa87};
use sha2::{Digest, Sha256};
use signed_note::{KeyName, NoteError, NoteSignature, NoteVerifier};
use tlog_tiles::{CheckpointSigner, CheckpointText, Hash, LeafIndex, UnixTimestamp};

use crate::{RelativeOid, ID_RDNA_TRUSTANCHOR_ID};

pub type TrustAnchorID = RelativeOid;

// ---------------------------------------------------------------------------
// Multi-algorithm key types
// ---------------------------------------------------------------------------

/// A signing key for MTC subtree cosignatures.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum MtcSigningKey {
    Ed25519(ed25519_dalek::SigningKey),
    MlDsa44(ml_dsa::SigningKey<MlDsa44>),
    MlDsa65(ml_dsa::SigningKey<MlDsa65>),
    MlDsa87(ml_dsa::SigningKey<MlDsa87>),
}

/// A verifying key for MTC subtree cosignatures.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum MtcVerifyingKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    MlDsa44(ml_dsa::VerifyingKey<MlDsa44>),
    MlDsa65(ml_dsa::VerifyingKey<MlDsa65>),
    MlDsa87(ml_dsa::VerifyingKey<MlDsa87>),
}

impl MtcSigningKey {
    /// Sign `msg`, returning the signature bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails. Not possible with current variants,
    /// but future algorithms (e.g. randomized schemes requiring entropy) may
    /// be fallible.
    pub fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>, ml_dsa::signature::Error> {
        Ok(match self {
            Self::Ed25519(sk) => sk.sign(msg).to_bytes().to_vec(),
            Self::MlDsa44(sk) => sk.sign(msg).encode().as_slice().to_vec(),
            Self::MlDsa65(sk) => sk.sign(msg).encode().as_slice().to_vec(),
            Self::MlDsa87(sk) => sk.sign(msg).encode().as_slice().to_vec(),
        })
    }
}

impl MtcVerifyingKey {
    /// The signature type identifier bytes for this algorithm, as used in the
    /// c2sp.org/signed-note key ID computation:
    ///
    /// `key ID = SHA-256(key name || 0x0A || signature_type_bytes || public key)[:4]`
    ///
    /// Ed25519 uses the allocated single byte `0x01`.
    ///
    /// ML-DSA variants use `0xff` (unassigned per c2sp.org/signed-note §Signature types)
    /// followed by the algorithm OID in dotted-decimal ASCII, as RECOMMENDED by the
    /// spec for types without an assigned identifier byte.
    ///
    /// TODO: Replace ML-DSA entries with their allocated single-byte identifiers
    /// once c2sp.org/signed-note assigns them.
    fn signature_type_bytes(&self) -> &'static [u8] {
        match self {
            Self::Ed25519(_) => &[0x01],
            Self::MlDsa44(_) => b"\xff2.16.840.1.101.3.4.3.17",
            Self::MlDsa65(_) => b"\xff2.16.840.1.101.3.4.3.18",
            Self::MlDsa87(_) => b"\xff2.16.840.1.101.3.4.3.19",
        }
    }

    fn verify(&self, msg: &[u8], sig_bytes: &[u8]) -> bool {
        match self {
            Self::Ed25519(vk) => {
                let Ok(sig_arr) = sig_bytes.try_into() else {
                    return false;
                };
                let sig = ed25519_dalek::Signature::from_bytes(sig_arr);
                ed25519_dalek::Verifier::verify(vk, msg, &sig).is_ok()
            }
            Self::MlDsa44(vk) => verify_ml_dsa(vk, msg, sig_bytes),
            Self::MlDsa65(vk) => verify_ml_dsa(vk, msg, sig_bytes),
            Self::MlDsa87(vk) => verify_ml_dsa(vk, msg, sig_bytes),
        }
    }

    /// Return the DER-encoded `SubjectPublicKeyInfo` for this key.
    ///
    /// Including the `AlgorithmIdentifier` allows clients to determine the
    /// algorithm without out-of-band information, which is important now that
    /// the CA supports multiple signing algorithms.
    ///
    /// # Panics
    ///
    /// Panics if PKCS#8 encoding fails, which should never happen for a valid key.
    #[must_use]
    pub fn to_public_key_der(&self) -> Vec<u8> {
        use pkcs8::EncodePublicKey;
        match self {
            Self::Ed25519(vk) => vk
                .to_public_key_der()
                .expect("Ed25519 SPKI encoding failed")
                .to_vec(),
            Self::MlDsa44(vk) => vk
                .to_public_key_der()
                .expect("ML-DSA-44 SPKI encoding failed")
                .to_vec(),
            Self::MlDsa65(vk) => vk
                .to_public_key_der()
                .expect("ML-DSA-65 SPKI encoding failed")
                .to_vec(),
            Self::MlDsa87(vk) => vk
                .to_public_key_der()
                .expect("ML-DSA-87 SPKI encoding failed")
                .to_vec(),
        }
    }
}

/// Generic ML-DSA signature verification helper.
fn verify_ml_dsa<P>(vk: &ml_dsa::VerifyingKey<P>, msg: &[u8], sig_bytes: &[u8]) -> bool
where
    P: ml_dsa::MlDsaParams,
{
    ml_dsa::EncodedSignature::<P>::try_from(sig_bytes)
        .ok()
        .and_then(|enc| ml_dsa::Signature::<P>::decode(&enc))
        .is_some_and(|sig| MlDsaVerifier::verify(vk, msg, &sig).is_ok())
}

// ---------------------------------------------------------------------------
// MtcCosigner
// ---------------------------------------------------------------------------

pub struct MtcCosigner {
    v: MtcNoteVerifier,
    k: MtcSigningKey,
}

impl MtcCosigner {
    /// Return a checkpoint cosigner from an `MtcSigningKey` and `MtcVerifyingKey`.
    #[must_use]
    pub fn new_checkpoint(
        cosigner_id: TrustAnchorID,
        log_id: TrustAnchorID,
        sk: MtcSigningKey,
        vk: MtcVerifyingKey,
    ) -> Self {
        let sig_type = vk.signature_type_bytes();
        Self {
            v: MtcNoteVerifier::new_checkpoint(cosigner_id, log_id, vk, sig_type),
            k: sk,
        }
    }

    /// Compute a subtree cosignature as defined in
    /// <https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-02.html#name-signature-format>.
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
    ) -> Result<Vec<u8>, ml_dsa::signature::Error> {
        let serialized = serialize_mtc_subtree_signature_input(
            &self.v.cosigner_id,
            &self.v.log_id,
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
    #[must_use]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.v.verifying_key.to_public_key_der()
    }
}

/// Support signing tlog-checkpoint with the subtree cosigner.
impl CheckpointSigner for MtcCosigner {
    fn name(&self) -> &KeyName {
        self.v.name()
    }

    fn key_id(&self) -> u32 {
        self.v.key_id()
    }

    fn sign(
        &self,
        _timestamp_unix_millis: UnixTimestamp,
        checkpoint: &tlog_tiles::CheckpointText,
    ) -> Result<NoteSignature, NoteError> {
        let sig = self.sign_subtree(0, checkpoint.size(), checkpoint.hash())?;
        Ok(NoteSignature::new(self.name().clone(), self.key_id(), sig))
    }

    fn verifier(&self) -> Box<dyn NoteVerifier> {
        Box::new(self.v.clone())
    }
}

// ---------------------------------------------------------------------------
// MtcNoteVerifier
// ---------------------------------------------------------------------------

/// Verifier for MTC subtree cosignatures.
#[derive(Clone)]
pub struct MtcNoteVerifier {
    cosigner_id: TrustAnchorID,
    log_id: TrustAnchorID,
    name: KeyName,
    id: u32,
    verifying_key: MtcVerifyingKey,
}

impl MtcNoteVerifier {
    /// Return a checkpoint verifier.
    ///
    /// # Panics
    ///
    /// Will panic if the trust anchor ID cannot be parsed as a valid key name
    /// according to <https://c2sp.org/signed-note#format>.
    #[must_use]
    pub fn new_checkpoint(
        cosigner_id: TrustAnchorID,
        log_id: TrustAnchorID,
        verifying_key: MtcVerifyingKey,
        signature_type_bytes: &[u8],
    ) -> Self {
        let name = KeyName::new(format!("oid/{ID_RDNA_TRUSTANCHOR_ID}.{log_id}")).unwrap();

        let id = {
            let mut hasher = Sha256::new();
            hasher.update(name.as_str().as_bytes());
            hasher.update([0x0a]);
            hasher.update(signature_type_bytes);
            hasher.update(b"mtc-checkpoint/v1");
            let result = hasher.finalize();
            u32::from_be_bytes(result[0..4].try_into().unwrap())
        };

        Self {
            cosigner_id,
            log_id,
            name,
            id,
            verifying_key,
        }
    }
}

impl NoteVerifier for MtcNoteVerifier {
    fn name(&self) -> &KeyName {
        &self.name
    }

    fn key_id(&self) -> u32 {
        self.id
    }

    fn verify(&self, msg: &[u8], sig_bytes: &[u8]) -> bool {
        let Ok(checkpoint) = CheckpointText::from_bytes(msg) else {
            return false;
        };

        let message = serialize_mtc_subtree_signature_input(
            &self.cosigner_id,
            &self.log_id,
            0,
            checkpoint.size(),
            checkpoint.hash(),
        );

        self.verifying_key.verify(&message, sig_bytes)
    }

    fn extract_timestamp_millis(&self, _sig: &[u8]) -> Result<Option<u64>, NoteError> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Serializes the passed in parameters into the correct format for signing
/// according to <https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/>.
/// ```text
///
/// opaque HashValue[HASH_SIZE];
///
/// /* From Section 4.1 of draft-ietf-tls-trust-anchor-ids */
/// opaque TrustAnchorID<1..2^8-1>;
///
/// struct {
///     TrustAnchorID log_id;
///     uint64 start;
///     uint64 end;
///     HashValue hash;
/// } MTCSubtree;
///
/// struct {
///     uint8 label[16] = "mtc-subtree/v1\n\0";
///     TrustAnchorID cosigner_id;
///     MTCSubtree subtree;
/// } MTCSubtreeSignatureInput;
/// ```
///
/// # Panics
///
/// Panics if writing to an internal buffer fails, which should never happen.
fn serialize_mtc_subtree_signature_input(
    cosigner_id: &TrustAnchorID,
    log_id: &TrustAnchorID,
    start: LeafIndex,
    end: LeafIndex,
    root_hash: &Hash,
) -> Vec<u8> {
    let mut buffer: Vec<u8> = b"mtc-subtree/v1\n\x00".to_vec();
    buffer
        .write_length_prefixed(cosigner_id.as_bytes(), 1)
        .unwrap();
    buffer.write_length_prefixed(log_id.as_bytes(), 1).unwrap();
    buffer.write_u64::<BigEndian>(start).unwrap();
    buffer.write_u64::<BigEndian>(end).unwrap();
    buffer.extend(root_hash.0);
    buffer
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use tlog_tiles::{open_checkpoint, record_hash, TreeWithTimestamp};

    use super::*;
    use ml_dsa::KeyGen;
    use rand::rngs::OsRng;
    use signed_note::VerifierList;
    use std::str::FromStr;

    fn run_sign_verify_test(signer: MtcCosigner) {
        let mut rng = OsRng;
        let origin = "example.com/origin";
        let timestamp = 100;
        let tree = TreeWithTimestamp::new(4, record_hash(b"hello world"), timestamp);
        let checkpoint = tree.sign(origin, &[], &[&signer], &mut rng).unwrap();
        let verifier = signer.verifier();
        open_checkpoint(
            origin,
            &VerifierList::new(vec![verifier]),
            timestamp,
            &checkpoint,
        )
        .unwrap();
    }

    #[test]
    fn test_cosignature_ed25519() {
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        run_sign_verify_test(MtcCosigner::new_checkpoint(
            TrustAnchorID::from_str("1.2.3").unwrap(),
            TrustAnchorID::from_str("4.5.6").unwrap(),
            MtcSigningKey::Ed25519(sk),
            MtcVerifyingKey::Ed25519(vk),
        ));
    }

    #[test]
    fn test_cosignature_ml_dsa_44() {
        let kp = MlDsa44::key_gen(&mut OsRng);
        run_sign_verify_test(MtcCosigner::new_checkpoint(
            TrustAnchorID::from_str("1.2.3").unwrap(),
            TrustAnchorID::from_str("4.5.6").unwrap(),
            MtcSigningKey::MlDsa44(kp.signing_key().clone()),
            MtcVerifyingKey::MlDsa44(kp.verifying_key().clone()),
        ));
    }

    #[test]
    fn test_cosignature_ml_dsa_65() {
        let kp = ml_dsa::MlDsa65::key_gen(&mut OsRng);
        run_sign_verify_test(MtcCosigner::new_checkpoint(
            TrustAnchorID::from_str("1.2.3").unwrap(),
            TrustAnchorID::from_str("4.5.6").unwrap(),
            MtcSigningKey::MlDsa65(kp.signing_key().clone()),
            MtcVerifyingKey::MlDsa65(kp.verifying_key().clone()),
        ));
    }

    #[test]
    fn test_cosignature_ml_dsa_87() {
        let kp = ml_dsa::MlDsa87::key_gen(&mut OsRng);
        run_sign_verify_test(MtcCosigner::new_checkpoint(
            TrustAnchorID::from_str("1.2.3").unwrap(),
            TrustAnchorID::from_str("4.5.6").unwrap(),
            MtcSigningKey::MlDsa87(kp.signing_key().clone()),
            MtcVerifyingKey::MlDsa87(kp.verifying_key().clone()),
        ));
    }
}
