// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use ed25519_dalek::{
    Signer as Ed25519Signer, SigningKey as Ed25519SigningKey, Verifier as Ed25519Verifier,
    VerifyingKey as Ed25519VerifyingKey,
};
use signed_note::{compute_key_id, KeyName, NoteError, NoteSignature, NoteVerifier, SignatureType};

use crate::{Checkpoint, CheckpointSigner, UnixTimestamp};

/// Implementation of [`CheckpointSigner`] that produces a timestamped Ed25519 cosignature/v1 (alg 0x04 from <c2sp.org/signed-note>).
pub struct CosignatureV1CheckpointSigner {
    v: CosignatureV1NoteVerifier,
    k: Ed25519SigningKey,
}

impl CosignatureV1CheckpointSigner {
    /// Returns a new `CosignatureV1CheckpointSigner`.
    pub fn new(name: KeyName, k: Ed25519SigningKey) -> Self {
        Self {
            v: CosignatureV1NoteVerifier::new(name, k.verifying_key()),
            k,
        }
    }
}

impl CheckpointSigner for CosignatureV1CheckpointSigner {
    fn name(&self) -> &KeyName {
        self.v.name()
    }

    fn key_id(&self) -> u32 {
        self.v.key_id()
    }

    fn sign(
        &self,
        timestamp_unix_millis: UnixTimestamp,
        checkpoint: &Checkpoint,
    ) -> Result<NoteSignature, NoteError> {
        // Timestamp is in seconds.
        let timestamp_unix_secs = timestamp_unix_millis / 1000;
        let mut msg = format!("cosignature/v1\ntime {timestamp_unix_secs}\n").into_bytes();
        msg.extend(checkpoint.to_bytes());

        // Ed25519 signing cannot fail
        let sig = self.k.try_sign(&msg).unwrap();

        // Now format the final signature according to <https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md#format>.
        // struct timestamped_signature {
        //     u64 timestamp;
        //     u8 signature[64];
        // }
        let mut note_sig = Vec::new();
        note_sig
            .write_u64::<BigEndian>(timestamp_unix_secs)
            .unwrap();
        note_sig.extend(&sig.to_bytes());

        // Return the note signature.
        Ok(NoteSignature::new(
            self.name().clone(),
            self.key_id(),
            note_sig,
        ))
    }

    fn verifier(&self) -> Box<dyn NoteVerifier> {
        Box::new(self.v.clone())
    }
}

/// [`CosignatureV1NoteVerifier`] is the verifier for the timestamped Ed25519 cosignature type defined in <https://c2sp.org/tlog-cosignature>.
#[derive(Clone)]
pub struct CosignatureV1NoteVerifier {
    name: KeyName,
    id: u32,
    verifying_key: Ed25519VerifyingKey,
}

impl CosignatureV1NoteVerifier {
    pub fn new(name: KeyName, verifying_key: Ed25519VerifyingKey) -> Self {
        let id = {
            let pubkey = [
                &[SignatureType::CosignatureV1 as u8],
                verifying_key.to_bytes().as_slice(),
            ]
            .concat();
            compute_key_id(&name, &pubkey)
        };
        Self {
            name,
            id,
            verifying_key,
        }
    }
}

impl NoteVerifier for CosignatureV1NoteVerifier {
    fn name(&self) -> &KeyName {
        &self.name
    }

    fn key_id(&self) -> u32 {
        self.id
    }

    fn verify(&self, msg: &[u8], mut sig: &[u8]) -> bool {
        // The message itself should be a valid checkpoint.
        let Ok(checkpoint) = Checkpoint::from_bytes(msg) else {
            return false;
        };
        // timestamped_signature.timestamp
        let Ok(sig_timestamp) = sig.read_u64::<BigEndian>() else {
            return false;
        };
        // timestamped_signature.signature
        let sig_bytes: [u8; ed25519_dalek::SIGNATURE_LENGTH] = match sig.try_into() {
            Ok(ok) => ok,
            Err(_) => return false,
        };

        // Construct message to be signed from <https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md#signed-message>.
        let mut msg = format!("cosignature/v1\ntime {sig_timestamp}\n").into_bytes();
        msg.extend(checkpoint.to_bytes());
        self.verifying_key
            .verify(&msg, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .is_ok()
    }

    fn extract_timestamp_millis(&self, mut sig: &[u8]) -> Result<Option<u64>, NoteError> {
        // The timestamp is the first 8 bytes of the signature, and is in seconds.
        let ts = sig
            .read_u64::<BigEndian>()
            .map_err(|_| NoteError::Timestamp)?;
        Ok(Some(ts * 1000))
    }
}

#[cfg(test)]
mod tests {

    use crate::{open_checkpoint, record_hash, TreeWithTimestamp};

    use super::*;
    use rand::{rngs::OsRng, TryRngCore};
    use signed_note::VerifierList;

    #[test]
    fn test_cosignature_v1_sign_verify() {
        let mut rng = OsRng.unwrap_err();

        let origin = "example.com/origin";
        let timestamp = 100;
        let tree_size = 4;

        // Make a tree head and sign it
        let tree = TreeWithTimestamp::new(tree_size, record_hash(b"hello world"), timestamp);
        let signer = {
            let sk = Ed25519SigningKey::generate(&mut rng);
            let name = KeyName::new("my-signer".into()).unwrap();
            CosignatureV1CheckpointSigner::new(name, sk)
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
