// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause
use crate::{compute_key_id, KeyName, NoteError, NoteSigner, NoteVerifier, SignatureType};
use base64::prelude::*;
use ed25519_dalek::{
    Signer as Ed25519Signer, SigningKey as Ed25519SigningKey, Verifier as Ed25519Verifier,
    VerifyingKey as Ed25519VerifyingKey,
};
use rand_core::CryptoRngCore;

/// [`Ed25519NoteVerifier`] is the verifier for the ordinary (non-timestamped) Ed25519 signature type defined in <https://c2sp.org/signed-note>.
#[derive(Clone)]
pub struct Ed25519NoteVerifier {
    pub(crate) name: KeyName,
    pub(crate) id: u32,
    pub(crate) verifying_key: Ed25519VerifyingKey,
}

impl NoteVerifier for Ed25519NoteVerifier {
    fn name(&self) -> &KeyName {
        &self.name
    }

    fn key_id(&self) -> u32 {
        self.id
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let sig_bytes: [u8; ed25519_dalek::SIGNATURE_LENGTH] = match sig.try_into() {
            Ok(ok) => ok,
            Err(_) => return false,
        };
        self.verifying_key
            .verify(msg, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .is_ok()
    }

    fn extract_timestamp_millis(&self, _sig: &[u8]) -> Result<Option<u64>, NoteError> {
        // Ed25519NoteVerifier (alg type 0x01) has no timestamp in the signature
        Ok(None)
    }
}

impl Ed25519NoteVerifier {
    pub fn new(name: KeyName, verifying_key: Ed25519VerifyingKey) -> Self {
        let id = {
            let pubkey = [
                &[SignatureType::Ed25519 as u8],
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
    /// Construct a new [Verifier] from an encoded verifier key.
    ///
    /// # Errors
    ///
    /// Returns a [`NoteError`] if `vkey` is malformed or otherwise invalid.
    pub fn new_from_encoded_key(vkey: &str) -> Result<Self, NoteError> {
        let (name, vkey) = vkey.split_once('+').ok_or(NoteError::Format)?;
        let Ok(name) = KeyName::new(name.into()) else {
            return Err(NoteError::Format);
        };
        let (id16, key64) = vkey.split_once('+').ok_or(NoteError::Format)?;

        let id = u32::from_str_radix(id16, 16).map_err(|_| NoteError::Format)?;
        let key = BASE64_STANDARD
            .decode(key64)
            .map_err(|_| NoteError::Format)?;

        if id16.len() != 8 || key.is_empty() {
            return Err(NoteError::Format);
        }

        if id != compute_key_id(&name, &key) {
            return Err(NoteError::Id);
        }

        let alg = key[0];
        let key = &key[1..];
        match SignatureType::try_from(alg) {
            Ok(SignatureType::Ed25519) => {
                let key_bytes: &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH] =
                    &key.try_into().map_err(|_| NoteError::Format)?;
                let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(key_bytes)
                    .map_err(|_| NoteError::Format)?;
                Ok(Self {
                    name,
                    id,
                    verifying_key,
                })
            }
            _ => Err(NoteError::Alg),
        }
    }
}

/// [`Ed25519NoteSigner`] is the signer for the ordinary (non-timestamped) Ed25519 signature type
#[derive(Clone)]
pub struct Ed25519NoteSigner {
    pub(crate) name: KeyName,
    pub(crate) id: u32,
    pub(crate) signing_key: Ed25519SigningKey,
}

impl NoteSigner for Ed25519NoteSigner {
    fn name(&self) -> &KeyName {
        &self.name
    }
    fn key_id(&self) -> u32 {
        self.id
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
        let sig = self.signing_key.try_sign(msg)?;
        Ok(sig.to_vec())
    }
}

impl Ed25519NoteSigner {
    pub fn new(name: KeyName, signing_key: Ed25519SigningKey) -> Self {
        let id = {
            let pubkey = [
                &[SignatureType::Ed25519 as u8],
                signing_key.verifying_key().to_bytes().as_slice(),
            ]
            .concat();
            compute_key_id(&name, &pubkey)
        };
        Self {
            name,
            id,
            signing_key,
        }
    }
    /// Construct a new [Signer] from an encoded signer key.
    ///
    /// # Errors
    ///
    /// Returns a [`NoteError`] if `skey` is malformed or otherwise invalid.
    pub fn new_from_encoded_key(skey: &str) -> Result<Self, NoteError> {
        let (priv1, skey) = skey.split_once('+').ok_or(NoteError::Format)?;
        let (priv2, skey) = skey.split_once('+').ok_or(NoteError::Format)?;
        let (name, skey) = skey.split_once('+').ok_or(NoteError::Format)?;
        let (id16, key64) = skey.split_once('+').ok_or(NoteError::Format)?;

        let Ok(name) = KeyName::new(name.into()) else {
            return Err(NoteError::Format);
        };

        let id = u32::from_str_radix(id16, 16).map_err(|_| NoteError::Format)?;
        let key = BASE64_STANDARD
            .decode(key64)
            .map_err(|_| NoteError::Format)?;

        if priv1 != "PRIVATE" || priv2 != "KEY" || id16.len() != 8 || key.is_empty() {
            return Err(NoteError::Format);
        }

        // Note: id is the hash of the public key and we have the private key.
        let alg = key[0];
        let key = &key[1..];
        match SignatureType::try_from(alg) {
            Ok(SignatureType::Ed25519) => {
                let signing_key =
                    ed25519_dalek::SigningKey::try_from(key).map_err(|_| NoteError::Format)?;

                let pubkey = [
                    &[SignatureType::Ed25519 as u8],
                    ed25519_dalek::VerifyingKey::from(&signing_key)
                        .to_bytes()
                        .as_slice(),
                ]
                .concat();

                // Must verify id after deriving public key.
                if id != compute_key_id(&name, &pubkey) {
                    return Err(NoteError::Id);
                }

                Ok(Self {
                    name,
                    id,
                    signing_key,
                })
            }
            _ => Err(NoteError::Alg),
        }
    }
}

/// Generates a signer and verifier key pair for a named server.
/// The signer key skey is private and must be kept secret.
pub fn generate_encoded_ed25519_key<R: CryptoRngCore + ?Sized>(
    csprng: &mut R,
    name: &KeyName,
) -> (String, String) {
    let signing_key = ed25519_dalek::SigningKey::generate(csprng);

    let pubkey = [
        &[SignatureType::Ed25519 as u8],
        signing_key.verifying_key().to_bytes().as_slice(),
    ]
    .concat();
    let privkey = [
        &[SignatureType::Ed25519 as u8],
        signing_key.to_bytes().as_slice(),
    ]
    .concat();
    let skey = format!(
        "PRIVATE+KEY+{}+{:08x}+{}",
        name,
        compute_key_id(name, &pubkey),
        BASE64_STANDARD.encode(privkey)
    );
    let vkey = new_encoded_ed25519_verifier_key(name, &signing_key.verifying_key());

    (skey, vkey)
}

/// Returns an encoded verifier key using the given name and Ed25519 public key.
pub fn new_encoded_ed25519_verifier_key(
    name: &KeyName,
    key: &ed25519_dalek::VerifyingKey,
) -> String {
    let pubkey = [&[SignatureType::Ed25519 as u8], key.to_bytes().as_slice()].concat();
    format!(
        "{}+{:08x}+{}",
        name,
        compute_key_id(name, &pubkey),
        BASE64_STANDARD.encode(&pubkey)
    )
}
