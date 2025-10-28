// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

use byteorder::{BigEndian, WriteBytesExt};
use ed25519_dalek::{
    ed25519::signature::{self, Signer},
    SigningKey as Ed25519SigningKey, Verifier as Ed25519Verifier,
    VerifyingKey as Ed25519VerifyingKey,
};
use length_prefixed::WriteLengthPrefixedBytesExt;
use sha2::{Digest, Sha256};
use signed_note::{KeyName, NoteError, NoteSignature, NoteVerifier};
use tlog_tiles::{CheckpointSigner, CheckpointText, Hash, LeafIndex, UnixTimestamp};

use crate::{RelativeOid, ID_RDNA_TRUSTANCHOR_ID};

pub type TrustAnchorID = RelativeOid;

pub struct MTCSubtreeCosigner {
    v: MTCSubtreeNoteVerifier,
    k: Ed25519SigningKey,
}

impl MTCSubtreeCosigner {
    pub fn new(cosigner_id: TrustAnchorID, log_id: TrustAnchorID, k: Ed25519SigningKey) -> Self {
        Self {
            v: MTCSubtreeNoteVerifier::new(cosigner_id, log_id, k.verifying_key()),
            k,
        }
    }
}

impl MTCSubtreeCosigner {
    /// Compute an Ed25519 subtree cosignature as defined in
    /// <https://www.ietf.org/archive/id/draft-davidben-tls-merkle-tree-certs-05.html#name-signature-format>.
    ///
    /// # Errors
    ///
    /// Will return `signature::Error` if signing fails. This cannot happen for
    /// Ed25519 signatures, but might for other signature types added in the future.
    pub fn sign_subtree(
        &self,
        start: LeafIndex,
        end: LeafIndex,
        root_hash: &Hash,
    ) -> Result<Vec<u8>, signature::Error> {
        let serialized = serialize_mtc_subtree_signature_input(
            &self.v.cosigner_id,
            &self.v.log_id,
            start,
            end,
            root_hash,
        );

        Ok(self.k.try_sign(&serialized)?.to_vec())
    }

    /// Return the log ID as bytes.
    pub fn log_id(&self) -> &[u8] {
        self.v.log_id.as_bytes()
    }

    /// Return the cosigner ID as bytes.
    pub fn cosigner_id(&self) -> &[u8] {
        self.v.cosigner_id.as_bytes()
    }

    /// Return the verifying key as bytes.
    pub fn verifying_key(&self) -> &[u8] {
        self.v.verifying_key.as_bytes()
    }
}

/// Support signing tlog-checkpoint with the subtree cosigner.
impl CheckpointSigner for MTCSubtreeCosigner {
    fn name(&self) -> &KeyName {
        self.v.name()
    }

    fn key_id(&self) -> u32 {
        self.v.key_id()
    }

    /// Sign a checkpoint with the subtree cosigner. For checkpoints, the start index is always 0.
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

/// [`MTCSubtreeNoteVerifier`] is the verifier for subtree cosignatures defined in <https://www.ietf.org/archive/id/draft-davidben-tls-merkle-tree-certs-05.html#name-cosigners>
/// It currently supports only Ed25519 signatures.
#[derive(Clone)]
pub struct MTCSubtreeNoteVerifier {
    cosigner_id: TrustAnchorID,
    log_id: TrustAnchorID,
    name: KeyName,
    id: u32,
    verifying_key: Ed25519VerifyingKey,
}

impl MTCSubtreeNoteVerifier {
    pub fn new(
        cosigner_id: TrustAnchorID,
        log_id: TrustAnchorID,
        verifying_key: Ed25519VerifyingKey,
    ) -> Self {
        let name = KeyName::new(format!("oid/{}.{}", ID_RDNA_TRUSTANCHOR_ID, log_id)).unwrap();

        let id = {
            let mut hasher = Sha256::new();
            hasher.update(name.as_str().as_bytes());
            hasher.update([0x0a, 0xff]);
            hasher.update(b"mtc-subtree/v1");
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

/// Support verifying signed note signatures created using the subtree cosigner.
impl NoteVerifier for MTCSubtreeNoteVerifier {
    fn name(&self) -> &KeyName {
        &self.name
    }

    fn key_id(&self) -> u32 {
        self.id
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        // The message itself should be a valid checkpoint.
        let Ok(checkpoint) = CheckpointText::from_bytes(msg) else {
            return false;
        };
        // Ed25519 signature (no prepended timestamp)
        let sig_bytes: [u8; ed25519_dalek::SIGNATURE_LENGTH] = match sig.try_into() {
            Ok(ok) => ok,
            Err(_) => return false,
        };

        // Construct message to be signed from <https://www.ietf.org/archive/id/draft-davidben-tls-merkle-tree-certs-05.html#name-signature-format>.
        let msg = serialize_mtc_subtree_signature_input(
            &self.cosigner_id,
            &self.log_id,
            0,
            checkpoint.size(),
            checkpoint.hash(),
        );

        self.verifying_key
            .verify(&msg, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .is_ok()
    }

    fn extract_timestamp_millis(&self, _sig: &[u8]) -> Result<Option<u64>, NoteError> {
        // No timestamp for subtree signatures.
        Ok(None)
    }
}

/// Serializes the passed in parameters into the correct format for signing
/// according to <https://datatracker.ietf.org/doc/draft-davidben-tls-merkle-tree-certs/>.
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

#[cfg(test)]
mod tests {

    use tlog_tiles::{open_checkpoint, record_hash, TreeWithTimestamp};

    use super::*;
    use rand::rngs::OsRng;
    use signed_note::VerifierList;
    use std::str::FromStr;

    #[test]
    fn test_cosignature_v1_sign_verify() {
        let mut rng = OsRng;

        let origin = "example.com/origin";
        let timestamp = 100;
        let tree_size = 4;

        // Make a tree head and sign it
        let tree = TreeWithTimestamp::new(tree_size, record_hash(b"hello world"), timestamp);
        let signer = {
            let sk = Ed25519SigningKey::generate(&mut rng);
            MTCSubtreeCosigner::new(
                TrustAnchorID::from_str("1.2.3").unwrap(),
                TrustAnchorID::from_str("4.5.6").unwrap(),
                sk,
            )
        };
        let checkpoint = tree.sign(origin, &[], &[&signer], &mut rng).unwrap();

        // Now verify the signed checkpoint
        let verifier = signer.verifier();
        open_checkpoint(
            origin,
            &VerifierList::new(vec![verifier]),
            timestamp,
            &checkpoint,
        )
        .unwrap();
    }
}
