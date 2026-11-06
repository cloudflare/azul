// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause
use base64::prelude::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use ed25519_dalek::{
    Signer as Ed25519Signer, SigningKey as Ed25519SigningKey, Verifier as Ed25519Verifier,
    VerifyingKey as Ed25519VerifyingKey,
};
use signed_note::{KeyName, NoteError, NoteSignature, NoteVerifier, SignatureType};

use tlog_checkpoint::{CheckpointSigner, CheckpointText, UnixTimestampMillis};

/// Implementation of [`CheckpointSigner`] that produces a timestamped Ed25519 cosignature/v1 (alg 0x04 from <c2sp.org/signed-note>).
pub struct CosignatureV1CheckpointSigner {
    v: CosignatureV1NoteVerifier,
    k: Ed25519SigningKey,
}

impl CosignatureV1CheckpointSigner {
    /// Returns a new `CosignatureV1CheckpointSigner`.
    #[must_use]
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
        timestamp: UnixTimestampMillis,
        checkpoint: &CheckpointText,
    ) -> Result<NoteSignature, NoteError> {
        // Timestamp is in seconds.
        let timestamp_unix_secs = timestamp / 1000;
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
    #[must_use]
    pub fn new(name: KeyName, verifying_key: Ed25519VerifyingKey) -> Self {
        let id = signed_note::compute_key_id(
            &name,
            &[SignatureType::CosignatureV1 as u8],
            verifying_key.to_bytes().as_slice(),
        );
        Self {
            name,
            id,
            verifying_key,
        }
    }

    /// Construct a new verifier from an encoded verifier key.
    ///
    /// # Errors
    ///
    /// Returns a [`NoteError`] if `vkey` is malformed or otherwise invalid.
    pub fn new_from_encoded_key(vkey: &str) -> Result<Self, NoteError> {
        let (name, vkey) = vkey.split_once('+').ok_or(NoteError::Format)?;
        let name = KeyName::new(name.into()).map_err(|_| NoteError::Format)?;
        let (id16, key64) = vkey.split_once('+').ok_or(NoteError::Format)?;

        let id = u32::from_str_radix(id16, 16).map_err(|_| NoteError::Format)?;
        let key = BASE64_STANDARD
            .decode(key64)
            .map_err(|_| NoteError::Format)?;

        if id16.len() != 8 || key.is_empty() {
            return Err(NoteError::Format);
        }

        if id != signed_note::compute_key_id(&name, &key[0..1], &key[1..]) {
            return Err(NoteError::Id);
        }

        if !matches!(
            SignatureType::try_from(key[0]),
            Ok(SignatureType::CosignatureV1)
        ) {
            return Err(NoteError::Alg);
        }
        let key_bytes: &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH] =
            &key[1..].try_into().map_err(|_| NoteError::Format)?;
        let verifying_key =
            Ed25519VerifyingKey::from_bytes(key_bytes).map_err(|_| NoteError::Format)?;
        Ok(Self::new(name, verifying_key))
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
        let Ok(checkpoint) = CheckpointText::from_bytes(msg) else {
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

    use tlog_checkpoint::{TreeWithTimestamp, open_checkpoint};
    use tlog_core::record_hash;

    use super::*;
    use signed_note::VerifierList;

    #[test]
    fn test_cosignature_v1_sign_verify() {
        let origin = "example.com/origin";
        let timestamp = 100;
        let tree_size = 4;

        // Make a tree head and sign it
        let tree = TreeWithTimestamp::new(tree_size, record_hash(b"hello world"), timestamp);
        let signer = {
            let sk = Ed25519SigningKey::generate(&mut rand::rng());
            let name = KeyName::new("my-signer".into()).unwrap();
            CosignatureV1CheckpointSigner::new(name, sk)
        };
        let checkpoint = tree
            .sign(origin, &[], &[&signer], &mut rand::rng())
            .unwrap();

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

    #[test]
    fn new_from_encoded_key_verifies_checkpoint() {
        use signed_note::Note;

        let name = KeyName::new("log.example/origin".into()).unwrap();
        let sk = Ed25519SigningKey::generate(&mut rand::rng());
        let pk = sk.verifying_key().to_bytes();
        let signer = CosignatureV1CheckpointSigner::new(name.clone(), sk);
        let id = signed_note::compute_key_id(&name, &[0x04], pk.as_slice());
        let key = [&[0x04], pk.as_slice()].concat();
        let vkey = format!(
            "log.example/origin+{id:08x}+{}",
            BASE64_STANDARD.encode(key)
        );
        let parsed = CosignatureV1NoteVerifier::new_from_encoded_key(&vkey).unwrap();
        assert_eq!(parsed.name(), &name);
        assert_eq!(parsed.key_id(), signer.verifier().key_id());

        let cp_text =
            CheckpointText::new("log.example/origin", 42, tlog_core::Hash([0x55; 32]), &[])
                .unwrap();
        let sig = signer.sign(1_700_000_000_000, &cp_text).unwrap();
        let note = Note::new(&cp_text.to_bytes(), &[sig]).unwrap();
        let (verified, _) = note
            .verify(&VerifierList::new(vec![Box::new(parsed)]))
            .unwrap();
        assert_eq!(verified.len(), 1);
    }
}
