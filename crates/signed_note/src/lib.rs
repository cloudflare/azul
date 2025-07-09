// Ported from "mod" (https://pkg.go.dev/golang.org/x/mod)
// Copyright 2009 The Go Authors
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause
//
// This ports code from the original Go project "mod" and adapts it to Rust idioms.
//
// Modifications and Rust implementation Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! This crate defines notes as specified by the [C2SP signed-note](https://c2sp.org/signed-note) specification.
//!
//! This file contains code ported from the original project [note](https://pkg.go.dev/golang.org/x/mod/sumdb/note).
//!
//! References:
//! - [note](https://cs.opensource.google/go/x/mod/+/refs/tags/v0.21.0:sumdb/note/)
//!
//! # Signed Note
//!
//! A note is text signed by one or more server keys ([spec](https://c2sp.org/signed-note#note)).
//! The text should be ignored unless the note is signed by a trusted server key and the signature
//! has been verified using the server's public key.
//!
//! A server's public key is identified by a name, typically the "host[/path]" giving the base URL
//! of the server's transparency log.  The syntactic restrictions on a name are that it be
//! non-empty, well-formed UTF-8 containing neither Unicode spaces nor plus (U+002B).
//!
//! A server signs texts using public key cryptography.  A given server may have multiple public
//! keys, each identified by a 32-bit ID of the public key.  The [`key_id`] function computes the
//! key ID as RECOMMENDED by the [spec](https://c2sp.org/signed-note#signatures).
//! ```text
//! key ID = SHA-256(key name || 0x0A || signature type || public key)[:4]
//! ```
//!
//! A [`Note`] represents a text with one or more signatures.  An implementation can reject a note
//! with too many signatures (for example, more than 100 signatures).
//!
//! The [`Note::from_bytes`] function parses a message and validates that the text and signatures are
//! syntactically valid, and returns a Note.
//!
//! The [`Note::new`] function accepts a text and an existing list of signatures and returns a Note.
//!
//! A [Signature] represents a signature on a note, verified or not
//! ([spec](https://c2sp.org/signed-note.md#signatures)).
//!
//! The [`Signature::from_bytes`] function parses a note signature line and ensures that it is
//! syntactically valid, returning a Signature.
//!
//! The [`Signature::to_bytes`] function encodes a signature for inclusion in a note.
//!
//! ## Verifying Notes
//!
//! A [`Verifier`] allows verification of signatures by one server public key.  It can report the
//! name of the server and the uint32 ID of the key, and it can verify a purported signature by
//! that key.
//!
//! The standard implementation of a Verifier is constructed by [`Ed25519NoteVerifier::new`] starting
//! from a verifier key, which is a plain text string of the form `<name>+<id>+<keydata>`.
//!
//! A [`Verifiers`] allows looking up a Verifier by the combination of server name and key ID.
//!
//! The standard implementation of a Verifiers is constructed by [`VerifierList`] from a list of
//! known verifiers.
//!
//! The [`Note::verify`] function attempts to verify the signatures on a note using the provided
//! Verifiers, and returns the verified and unverified signatures.
//!
//! ## Signing Notes
//!
//! A [`Signer`] allows signing a text with a given key. It can report the name of the server and the
//! ID of the key and can sign a raw text using that key.
//!
//! The standard implementation of a Signer is constructed by [`Ed25519NoteSigner::new`] starting from
//! an encoded signer key, which is a plain text string of the form
//! `PRIVATE+KEY+<name>+<id>+<keydata>`.  Anyone with an encoded signer key can sign messages using
//! that key, so it must be kept secret. The encoding begins with the literal text `PRIVATE+KEY` to
//! avoid confusion with the public server key. This format is not required by the C2SP spec.
//!
//! The [`Note::add_sigs`] function adds new signatures to the note from the provided list of
//! Signers.
//!
//! ## Signed Note Format
//!
//! A signed note consists of a text ending in newline (U+000A), followed by a blank line (only a
//! newline), followed by one or more signature lines of this form: em dash (U+2014), space
//! (U+0020), server name, space, base64-encoded signature, newline
//! ([spec](https://c2sp.org/signed-note#format)).
//!
//! Signed notes must be valid UTF-8 and must not contain any ASCII control characters (those below
//! U+0020) other than newline.
//!
//! A signature is a base64 encoding of 4+n bytes.
//!
//! The first four bytes in the signature are the uint32 key ID stored in big-endian order.
//!
//! The remaining n bytes are the result of using the specified key to sign the note text
//! (including the final newline but not the separating blank line).
//!
//! The [`Note::to_bytes`] function encodes a note into signed note format.
//!
//! ## Generating Keys
//!
//! There is only one key type, Ed25519 with algorithm identifier 1.  New key types may be
//! introduced in the future as needed, although doing so will require deploying the new algorithms
//! to all clients before starting to depend on them for signatures.
//!
//! The [`generate_key`] function generates and returns a new signer and corresponding verifier.
//!
//! ## Example
//!
//! Here is a well-formed signed note:
//! ```text
//! If you think cryptography is the answer to your problem,
//! then you don't know what your problem is
//! — PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=
//! ```
//!
//! It can be constructed and displayed using:
//!
//! ```
//! use signed_note::{Note, Ed25519NoteSigner};
//!
//! let skey = "PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz";
//! let text = "If you think cryptography is the answer to your problem,\n\
//!             then you don't know what your problem is.\n";
//!
//! let signer = Ed25519NoteSigner::new(skey).unwrap();
//! let mut n = Note::new(text.as_bytes(), &[]).unwrap();
//! n.add_sigs(&[&signer]).unwrap();
//!
//! let want = "If you think cryptography is the answer to your problem,\n\
//!             then you don't know what your problem is.\n\
//!             \n\
//!             — PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n";
//!
//! assert_eq!(&n.to_bytes(), want.as_bytes());
//! ```
//!
//! The note's text is two lines, including the final newline, and the text is purportedly signed
//! by a server named "`PeterNeumann`". (Although server names are canonically base URLs, the only
//! syntactic requirement is that they not contain spaces or newlines).
//!
//! If [`Note::verify`] is given access to a [`Verifiers`] including the [`Verifier`] for this key, then
//! it will succeed at verifying the encoded message and returning the parsed [`Note`]:
//!
//! ```
//! use signed_note::{Note, Ed25519NoteVerifier, VerifierList};
//!
//! let vkey = "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW";
//! let msg = "If you think cryptography is the answer to your problem,\n\
//!            then you don't know what your problem is.\n\
//!            \n\
//!            — PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n";
//!
//! let verifier = Ed25519NoteVerifier::new(vkey).unwrap();
//! let n = Note::from_bytes(msg.as_bytes()).unwrap();
//! let (verified_sigs, _) = n.verify(&VerifierList::new(vec![Box::new(verifier.clone())])).unwrap();
//!
//! let got = format!("{} ({:08x}):\n{}", verified_sigs[0].name(), verified_sigs[0].id(), std::str::from_utf8(n.text()).unwrap());
//! let want = "PeterNeumann (c74f20a3):\n\
//!             If you think cryptography is the answer to your problem,\n\
//!             then you don't know what your problem is.\n";
//! assert_eq!(want, got);
//! ```
//!
//! You can add your own signature to this message by re-signing the note, which will produce a
//! doubly-signed message.
//!
//! ### Sign and add signatures
//! ```
//! use signed_note::{Note, Ed25519NoteSigner, Ed25519NoteVerifier, VerifierList};
//!
//! let vkey = "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW";
//! let msg = "If you think cryptography is the answer to your problem,\n\
//!            then you don't know what your problem is.\n\
//!            \n\
//!            — PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n";
//! let text = "If you think cryptography is the answer to your problem,\n\
//!             then you don't know what your problem is.\n";
//!
//! let mut n = Note::from_bytes(msg.as_bytes()).unwrap();
//!
//! let verifier = Ed25519NoteVerifier::new(vkey).unwrap();
//! let (verified_sigs, unverified_sigs) = n.verify(&VerifierList::new(vec![Box::new(verifier.clone())])).unwrap();
//! assert_eq!(verified_sigs.len(), 1);
//! assert!(unverified_sigs.is_empty());
//!
//! struct ZeroRng;
//!
//! impl rand_core::RngCore for ZeroRng {
//!     fn next_u32(&mut self) -> u32 {
//!         0
//!     }
//!
//!     fn next_u64(&mut self) -> u64 {
//!         0
//!     }
//!
//!     fn fill_bytes(&mut self, dest: &mut [u8]) {
//!         for byte in dest.iter_mut() {
//!             *byte = 0;
//!         }
//!     }
//!
//!     fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
//!         self.fill_bytes(dest);
//!         Ok(())
//!     }
//! }
//!
//! impl rand_core::CryptoRng for ZeroRng {}
//!
//! let (skey, _) = signed_note::generate_key(&mut ZeroRng{}, "EnochRoot");
//! let signer = Ed25519NoteSigner::new(&skey).unwrap();
//! n.add_sigs(&[&signer]).unwrap();
//!
//! let got = n.to_bytes();
//!
//! let want = "If you think cryptography is the answer to your problem,\n\
//!            then you don't know what your problem is.\n\
//!            \n\
//!            — PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n\
//!            — EnochRoot rwz+eBzmZa0SO3NbfRGzPCpDckykFXSdeX+MNtCOXm2/5n2tiOHp+vAF1aGrQ5ovTG01oOTGwnWLox33WWd1RvMc+QQ=\n";
//!
//! assert_eq!(got, want.as_bytes());
//! ```

use base64::prelude::*;
use ed25519_dalek::{
    Signer as Ed25519Signer, SigningKey as Ed25519SigningKey, Verifier as Ed25519Verifier,
    VerifyingKey as Ed25519VerifyingKey,
};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use thiserror::Error;

const MAX_NOTE_SIZE: usize = 1_000_000;
const MAX_NOTE_SIGNATURES: usize = 100;

/// A Verifier verifies messages signed with a specific key.
pub trait NoteVerifier {
    /// Returns the server name associated with the key.
    /// The name must be non-empty and not have any Unicode spaces or pluses.
    fn name(&self) -> &str;

    /// Returns the key ID.
    fn key_id(&self) -> u32;

    /// Reports whether sig is a valid signature of msg.
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool;

    /// Extracts a Unix timestamp in milliseconds from the given signature bytes, if defined.
    ///
    /// # Errors
    ///
    /// Errors if the signature is malformed.
    fn extract_timestamp_millis(&self, sig: &[u8]) -> Result<Option<u64>, VerificationError>;
}

/// A Signer signs messages using a specific key.
pub trait NoteSigner {
    /// Returns the server name associated with the key.
    /// The name must be non-empty and not have any Unicode spaces or pluses.
    fn name(&self) -> &str;

    /// Returns the key ID.
    fn key_id(&self) -> u32;

    /// Returns a signature for the Note. Uses the origin returned by `self.name()`.
    ///
    /// # Errors
    ///
    /// Returns a [`signature::Error`] if signing fails.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, signature::Error>;
}

/// Computes the key ID for the given server name and encoded public key
/// as RECOMMENDED at <https://c2sp.org/signed-note#signatures>.
pub fn key_id(name: &str, key: &[u8]) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(b"\n");
    hasher.update(key);
    let result = hasher.finalize();
    let mut u32_bytes = [0u8; 4];
    u32_bytes.copy_from_slice(&result[0..4]);

    u32::from_be_bytes(u32_bytes)
}

/// An error returned from the [`Ed25519NoteVerifier::new`] function when
/// constructing a [`Ed25519NoteVerifier`] from an encoded verifier key.
#[derive(Error, Debug)]
pub enum VerifierError {
    #[error("malformed verifier key")]
    Format,
    #[error("unknown verifier algorithm")]
    Alg,
    #[error("invalid verifier ID")]
    Id,
}

const ALG_ED25519: u8 = 1;

// Reports whether name is valid according to <https://c2sp.org/signed-note#format>.
// It must be non-empty and not have any Unicode spaces or pluses.
pub fn is_key_name_valid(name: &str) -> bool {
    !(name.is_empty() || name.chars().any(char::is_whitespace) || name.contains('+'))
}

/// [`Ed25519NoteVerifier`] is the verifier for the ordinary (non-timestamped) Ed25519 signature type
#[derive(Clone)]
pub struct Ed25519NoteVerifier {
    name: String,
    id: u32,
    verifying_key: Ed25519VerifyingKey,
}

impl NoteVerifier for Ed25519NoteVerifier {
    fn name(&self) -> &str {
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

    fn extract_timestamp_millis(&self, _sig: &[u8]) -> Result<Option<u64>, VerificationError> {
        // Ed25519NoteVerifier (alg type 0x01) has no timestamp in the signature
        Ok(None)
    }
}

impl Ed25519NoteVerifier {
    /// Construct a new [Verifier] from an encoded verifier key.
    ///
    /// # Errors
    ///
    /// Returns a [`VerifierError`] if `vkey` is malformed or otherwise invalid.
    pub fn new(vkey: &str) -> Result<Self, VerifierError> {
        let (name, vkey) = vkey.split_once('+').ok_or(VerifierError::Format)?;
        let (id16, key64) = vkey.split_once('+').ok_or(VerifierError::Format)?;

        let id = u32::from_str_radix(id16, 16).map_err(|_| VerifierError::Format)?;
        let key = BASE64_STANDARD
            .decode(key64)
            .map_err(|_| VerifierError::Format)?;

        if id16.len() != 8 || !is_key_name_valid(name) || key.is_empty() {
            return Err(VerifierError::Format);
        }

        if id != key_id(name, &key) {
            return Err(VerifierError::Id);
        }

        let alg = key[0];
        let key = &key[1..];
        match alg {
            ALG_ED25519 => {
                let key_bytes: &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH] =
                    &key.try_into().map_err(|_| VerifierError::Format)?;
                let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(key_bytes)
                    .map_err(|_| VerifierError::Format)?;
                Ok(Self {
                    name: name.to_owned(),
                    id,
                    verifying_key,
                })
            }
            _ => Err(VerifierError::Alg),
        }
    }
}

/// An error returned from the [`Ed25519NoteSigner::new`] function when
/// constructing a [`Ed25519NoteSigner`] from an encoded signer key.
#[derive(Error, Debug)]
pub enum SignerError {
    #[error("malformed verifier key")]
    Format,
    #[error("unknown verifier algorithm")]
    Alg,
    #[error("invalid verifier ID")]
    Id,
}

/// [`Ed25519NoteSigner`] is the signer for the ordinary (non-timestamped) Ed25519 signature type
#[derive(Clone)]
pub struct Ed25519NoteSigner {
    name: String,
    id: u32,
    signing_key: Ed25519SigningKey,
}

impl NoteSigner for Ed25519NoteSigner {
    fn name(&self) -> &str {
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
    /// Construct a new [Signer] from an encoded signer key.
    ///
    /// # Errors
    ///
    /// Returns a [`SignerError`] if `skey` is malformed or otherwise invalid.
    pub fn new(skey: &str) -> Result<Self, SignerError> {
        let (priv1, skey) = skey.split_once('+').ok_or(SignerError::Format)?;
        let (priv2, skey) = skey.split_once('+').ok_or(SignerError::Format)?;
        let (name, skey) = skey.split_once('+').ok_or(SignerError::Format)?;
        let (id16, key64) = skey.split_once('+').ok_or(SignerError::Format)?;

        let id = u32::from_str_radix(id16, 16).map_err(|_| SignerError::Format)?;
        let key = BASE64_STANDARD
            .decode(key64)
            .map_err(|_| SignerError::Format)?;

        if priv1 != "PRIVATE"
            || priv2 != "KEY"
            || id16.len() != 8
            || !is_key_name_valid(name)
            || key.is_empty()
        {
            return Err(SignerError::Format);
        }

        // Note: id is the hash of the public key and we have the private key.
        // Must verify id after deriving public key.

        let signer: Ed25519NoteSigner;
        let pubkey: Vec<u8>;

        let alg = key[0];
        let key = &key[1..];
        match alg {
            ALG_ED25519 => {
                let signing_key =
                    ed25519_dalek::SigningKey::try_from(key).map_err(|_| SignerError::Format)?;

                pubkey = [
                    &[ALG_ED25519],
                    ed25519_dalek::VerifyingKey::from(&signing_key)
                        .to_bytes()
                        .as_slice(),
                ]
                .concat();

                signer = Self {
                    name: name.to_owned(),
                    id,
                    signing_key,
                };
            }
            _ => {
                return Err(SignerError::Alg);
            }
        }

        if id != key_id(name, &pubkey) {
            return Err(SignerError::Id);
        }

        Ok(signer)
    }
}

/// Generates a signer and verifier key pair for a named server.
/// The signer key skey is private and must be kept secret.
pub fn generate_key<R: CryptoRngCore + ?Sized>(csprng: &mut R, name: &str) -> (String, String) {
    let signing_key = ed25519_dalek::SigningKey::generate(csprng);

    let pubkey = [
        &[ALG_ED25519],
        signing_key.verifying_key().to_bytes().as_slice(),
    ]
    .concat();
    let privkey = [&[ALG_ED25519], signing_key.to_bytes().as_slice()].concat();
    let skey = format!(
        "PRIVATE+KEY+{}+{:08x}+{}",
        name,
        key_id(name, &pubkey),
        BASE64_STANDARD.encode(privkey)
    );
    let vkey = new_ed25519_verifier_key(name, &signing_key.verifying_key());

    (skey, vkey)
}

/// Returns an encoded verifier key using the given name and Ed25519 public key.
pub fn new_ed25519_verifier_key(name: &str, key: &ed25519_dalek::VerifyingKey) -> String {
    let pubkey = [&[ALG_ED25519], key.to_bytes().as_slice()].concat();
    format!(
        "{}+{:08x}+{}",
        name,
        key_id(name, &pubkey),
        BASE64_STANDARD.encode(&pubkey)
    )
}

/// [`Verifiers`] is a collection of known verifier keys.
pub trait Verifiers {
    /// Returns the [`Verifier`] associated with the key identified by the name and
    /// id.
    ///
    /// # Errors
    ///
    /// If the (name, id) pair is unknown, return a [`VerificationError::UnknownKey`].
    fn verifier(&self, name: &str, id: u32) -> Result<&dyn NoteVerifier, VerificationError>;
}

type VerifierMap = HashMap<(String, u32), Vec<Box<dyn NoteVerifier>>>;

/// [`VerifierList`] is a [Verifiers] implementation that uses the given list of verifiers.
pub struct VerifierList {
    map: VerifierMap,
}

/// An error returned from a Verifier when verifying a signature.
#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("unknown key {name}+{id:08x}")]
    UnknownKey { name: String, id: u32 },
    #[error("ambiguous key {name}+{id:08x}")]
    AmbiguousKey { name: String, id: u32 },
    #[error("malformed timestamp")]
    Timestamp,
}

impl Verifiers for VerifierList {
    fn verifier(&self, name: &str, id: u32) -> Result<&dyn NoteVerifier, VerificationError> {
        match self.map.get(&(name.to_owned(), id)) {
            Some(verifiers) => {
                if verifiers.len() > 1 {
                    return Err(VerificationError::AmbiguousKey {
                        name: name.to_owned(),
                        id,
                    });
                }
                Ok(&*verifiers[0])
            }
            None => Err(VerificationError::UnknownKey {
                name: name.to_owned(),
                id,
            }),
        }
    }
}

impl VerifierList {
    /// Returns a [Verifiers] implementation that uses the given list of verifiers.
    pub fn new(list: Vec<Box<dyn NoteVerifier>>) -> Self {
        let mut map: VerifierMap = HashMap::new();
        for verifier in list {
            map.entry((verifier.name().to_owned(), verifier.key_id()))
                .or_default()
                .push(verifier);
        }
        VerifierList { map }
    }

    /// The set of all key IDs in this verifier list
    pub fn key_ids(&self) -> BTreeSet<u32> {
        self.map.keys().map(|(_name, id)| *id).collect()
    }
}

/// A Note is a text and signatures.
#[derive(Debug, PartialEq)]
pub struct Note {
    /// Text of note. Guaranteed to be well-formed.
    text: Vec<u8>,
    /// Signatures on note. Guaranteed to be well-formed.
    sigs: Vec<NoteSignature>,
}

/// A `NoteSignature` is a single signature found in a note.
#[derive(Debug, PartialEq, Clone)]
pub struct NoteSignature {
    /// Name for the key that generated the signature.
    name: String,
    /// Key ID for the key that generated the signature.
    id: u32,
    /// The signature bytes.
    sig: Vec<u8>,
}

impl NoteSignature {
    /// Returns a new signature from the given name and base64-encoded signature string.
    ///
    /// # Errors
    ///
    /// Returns [`NoteError::MalformedNote`] if the name is invalid according to [`is_key_name_valid`].
    ///
    pub fn new(name: String, id: u32, sig: Vec<u8>) -> Result<Self, NoteError> {
        if !is_key_name_valid(&name) {
            return Err(NoteError::MalformedNote);
        }
        Ok(Self { name, id, sig })
    }

    /// Parse a signature line into a [Signature].
    ///
    /// # Errors
    ///
    /// Returns a [`NoteError`] if the note is malformed.
    ///
    /// # Panics
    ///
    /// Panics if slice conversion fails, which should never happen.
    pub fn from_bytes(line: &[u8]) -> Result<Self, NoteError> {
        let line = std::str::from_utf8(line).map_err(|_| NoteError::MalformedNote)?;
        let line = line.strip_prefix("— ").ok_or(NoteError::MalformedNote)?;
        let (name, b64) = line.split_once(' ').ok_or(NoteError::MalformedNote)?;
        let sig = BASE64_STANDARD
            .decode(b64)
            .map_err(|_| NoteError::MalformedNote)?;
        if b64.is_empty() || sig.len() < 5 {
            return Err(NoteError::MalformedNote);
        }
        let id = u32::from_be_bytes(sig[..4].try_into().unwrap());
        let sig = &sig[4..];
        NoteSignature::new(name.to_owned(), id, sig.to_owned())
    }

    /// Return a signature's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return a signature's key ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Return the signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.sig
    }

    /// Encode a signature for inclusion in a note.
    pub fn to_bytes(&self) -> Vec<u8> {
        let hbuf = self.id.to_be_bytes();
        let base64 = BASE64_STANDARD.encode([&hbuf, self.sig.as_slice()].concat());
        format!("— {} {}\n", self.name, base64).into()
    }
}

/// An error returned for issues parsing, verifying, or adding signatures to notes.
#[derive(Error, Debug)]
pub enum NoteError {
    #[error("malformed note")]
    MalformedNote,
    #[error("invalid signer")]
    InvalidSigner,
    #[error("invalid signature for key {name}+{id:08x}")]
    InvalidSignature { name: String, id: u32 },
    #[error("verifier name or id doesn't match signature")]
    MismatchedVerifier,
    #[error("note has no verifiable signatures")]
    UnverifiedNote,
    #[error(transparent)]
    VerificationError(#[from] VerificationError),
    #[error(transparent)]
    SignatureError(#[from] signature::Error),
}

impl Note {
    /// Returns a new note, ensuring that the text is well-formed, and
    /// appending the provided signatures.
    ///
    /// # Errors
    ///
    /// Returns a [`NoteError::MalformedNote`] if the text is larger than
    /// we're willing to parse, cannot be decoded as UTF-8, or contains
    /// any non-newline ASCII control characters.
    pub fn new(text: &[u8], existing_sigs: &[NoteSignature]) -> Result<Self, NoteError> {
        // Set some upper limit on what we're willing to process.
        if text.len() > MAX_NOTE_SIZE {
            return Err(NoteError::MalformedNote);
        }
        // Must have valid UTF-8 with no non-newline ASCII control characters.
        let text_str = std::str::from_utf8(text).map_err(|_| NoteError::MalformedNote)?;
        for ch in text_str.chars() {
            // Validation checks
            if ch < '\u{0020}' && ch != '\n' {
                return Err(NoteError::MalformedNote);
            }
        }
        if !text_str.ends_with('\n') {
            return Err(NoteError::MalformedNote);
        }

        Ok(Self {
            text: text.to_owned(),
            sigs: existing_sigs.into(),
        })
    }

    /// Parses the message msg into a note, returning a [`NoteError`] if any of the text or signatures are malformed.
    ///
    /// # Errors
    ///
    /// Returns a [`NoteError::MalformedNote`] if the message is larger than
    /// we're willing to parse, cannot be decoded as UTF-8, contains
    /// any non-newline ASCII control characters, or is otherwise invalid.
    pub fn from_bytes(msg: &[u8]) -> Result<Self, NoteError> {
        // Set some upper limit on what we're willing to process.
        if msg.len() > MAX_NOTE_SIZE {
            return Err(NoteError::MalformedNote);
        }
        // Must have valid UTF-8 (implied by &str type) with no non-newline ASCII control characters.
        let msg_str = std::str::from_utf8(msg).map_err(|_| NoteError::MalformedNote)?;
        for ch in msg_str.chars() {
            // Validation checks
            if ch < '\u{0020}' && ch != '\n' {
                return Err(NoteError::MalformedNote);
            }
        }

        // Must end with signature block preceded by blank line.
        let (text, sigs) = msg_str
            .rsplit_once("\n\n")
            .ok_or(NoteError::MalformedNote)?;

        // Add back the newline at the end of the text block.
        let text = format!("{text}\n");

        let sigs = sigs.strip_suffix("\n").ok_or(NoteError::MalformedNote)?;

        let mut parsed_sigs: Vec<NoteSignature> = Vec::new();
        let mut num_sig = 0;

        for line in sigs.split('\n') {
            let sig = NoteSignature::from_bytes(line.as_bytes())?;
            num_sig += 1;
            if num_sig > MAX_NOTE_SIGNATURES {
                return Err(NoteError::MalformedNote);
            }
            parsed_sigs.push(sig);
        }

        Self::new(text.as_bytes(), &parsed_sigs)
    }

    /// Checks signatures on the note for those from known verifiers.
    ///
    /// For each signature in the message, [`Note::verify`] calls known.verifier to find a verifier.
    /// If known.verifier returns a verifier and the verifier accepts the signature,
    /// [`Note::verify`] includes the signature in the returned list of verified signatures.
    /// If known.verifier returns a [`VerificationError::UnknownKey`],
    /// [`Note::verify`] includes the signature in the returned list of unverified signatures.
    ///
    /// # Errors
    ///
    /// If known.verifier returns a verifier but the verifier rejects the signature,
    /// [`Note::verify`] returns a [`NoteError::InvalidSignature`].
    /// If known.verifier returns any other error, [`Note::verify`] returns that error.
    ///
    /// If no known verifier has signed an otherwise valid note,
    /// [`Note::verify`] returns an [`NoteError::UnverifiedNote`].
    pub fn verify(
        &self,
        known: &impl Verifiers,
    ) -> Result<(Vec<NoteSignature>, Vec<NoteSignature>), NoteError> {
        let mut verified_sigs = Vec::new();
        let mut unverified_sigs = Vec::new();
        let mut seen = BTreeSet::new();
        let mut seen_unverified = BTreeSet::new();
        for sig in &self.sigs {
            match known.verifier(&sig.name, sig.id) {
                Ok(verifier) => {
                    if verifier.name() != sig.name || verifier.key_id() != sig.id {
                        return Err(NoteError::MismatchedVerifier);
                    }
                    if seen.contains(&(&sig.name, sig.id)) {
                        continue;
                    }
                    seen.insert((&sig.name, sig.id));
                    if !verifier.verify(&self.text, &sig.sig) {
                        return Err(NoteError::InvalidSignature {
                            name: sig.name.clone(),
                            id: sig.id,
                        });
                    }
                    verified_sigs.push(sig.clone());
                }
                Err(VerificationError::UnknownKey { name: _, id: _ }) => {
                    // Drop repeated identical unverified signatures.
                    if seen_unverified.contains(&sig.to_bytes()) {
                        continue;
                    }
                    seen_unverified.insert(sig.to_bytes());
                    unverified_sigs.push(sig.clone());
                }
                Err(e) => return Err(e.into()),
            }
        }
        if verified_sigs.is_empty() {
            return Err(NoteError::UnverifiedNote);
        }
        Ok((verified_sigs, unverified_sigs))
    }

    /// Signs the note with the given signers. The new signatures from
    /// signers are listed in the encoded message after the existing
    /// signatures already present in n.sigs. If any signer uses the same key
    /// as an existing signature, the existing signature is removed.
    ///
    /// # Errors
    ///
    /// Returns an error if any signers have invalid names.
    /// Names must be non-empty and not have any Unicode spaces or pluses.
    pub fn add_sigs(&mut self, signers: &[&dyn NoteSigner]) -> Result<(), NoteError> {
        // Prepare signatures and populate 'have' set.
        let mut new_sigs = Vec::new();
        let mut have = BTreeSet::new();
        for s in signers {
            let name = s.name();
            let id = s.key_id();
            have.insert((name, id));
            if !is_key_name_valid(name) {
                return Err(NoteError::InvalidSigner);
            }
            let sig = s.sign(&self.text)?;
            new_sigs.push(NoteSignature::new(name.to_owned(), id, sig)?);
        }

        // Remove existing signatures that have been replaced by new ones.
        self.sigs.retain(|sig| !have.contains(&(&sig.name, sig.id)));

        // Add new signatures at the end.
        self.sigs.extend(new_sigs);

        Ok(())
    }

    /// Returns a well-formed signed note.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.text.clone();
        buf.push(b'\n');
        for sig in &self.sigs {
            buf.extend(&sig.to_bytes());
        }
        buf
    }

    /// Returns the note's text.
    pub fn text(&self) -> &[u8] {
        &self.text
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use rand::rngs::OsRng;
    static NAME: &str = "EnochRoot";

    fn test_signer_and_verifier(name: &str, signer: &dyn NoteSigner, verifier: &dyn NoteVerifier) {
        assert_eq!(&name, &signer.name());
        assert_eq!(&name, &verifier.name());
        assert_eq!(signer.key_id(), verifier.key_id());

        let msg: &[u8] = b"hi";
        let sig = signer.sign(msg).unwrap();
        assert!(verifier.verify(msg, &sig));
    }

    #[test]
    fn test_generate_key() {
        let (skey, vkey) = generate_key(&mut OsRng, NAME);

        let signer = Ed25519NoteSigner::new(&skey).unwrap();
        let verifier = Ed25519NoteVerifier::new(&vkey).unwrap();

        test_signer_and_verifier(NAME, &signer, &verifier);
    }

    #[test]
    fn test_from_ed25519() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);

        let pubkey = [
            &[ALG_ED25519],
            signing_key.verifying_key().to_bytes().as_slice(),
        ]
        .concat();
        let id = key_id(NAME, &pubkey);

        let vkey = new_ed25519_verifier_key(NAME, &signing_key.verifying_key());
        let verifier = Ed25519NoteVerifier::new(&vkey).unwrap();

        let signer = Ed25519NoteSigner {
            name: NAME.to_owned(),
            id,
            signing_key,
        };

        test_signer_and_verifier(NAME, &signer, &verifier);
    }

    struct BadSigner {
        s: Box<dyn NoteSigner>,
    }

    impl NoteSigner for BadSigner {
        fn name(&self) -> &'static str {
            "bad name"
        }
        fn key_id(&self) -> u32 {
            self.s.key_id()
        }
        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
            self.s.sign(msg)
        }
    }

    struct ErrSigner {
        s: Box<dyn NoteSigner>,
    }

    impl NoteSigner for ErrSigner {
        fn name(&self) -> &str {
            self.s.name()
        }
        fn key_id(&self) -> u32 {
            self.s.key_id()
        }
        fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
            Err(signature::Error::new())
        }
    }

    #[test]
    fn test_sign() {
        let skey = "PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz";
        let text = b"If you think cryptography is the answer to your problem,\n\
                    then you don't know what your problem is.\n";

        let signer = Ed25519NoteSigner::new(skey).unwrap();

        let mut n = Note::new(text, &[]).unwrap();
        n.add_sigs(&[&signer]).unwrap();
        let want = "If you think cryptography is the answer to your problem,\n\
                    then you don't know what your problem is.\n\
                    \n\
                    — PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n";

        assert_eq!(n.to_bytes(), want.as_bytes());

        // Check that existing signature is replaced by new one.
        let mut n = Note::new(
            text,
            &[NoteSignature::new("PeterNeumann".into(), 0xc74f_20a3, vec![]).unwrap()],
        )
        .unwrap();
        n.add_sigs(&[&signer]).unwrap();
        assert_eq!(n.to_bytes(), want.as_bytes());

        // Check various bad inputs.

        // Attempt to create note without terminating newline.
        let err = Note::new(b"abc", &[]).unwrap_err();
        assert!(matches!(err, NoteError::MalformedNote));

        // Attempt to create signature with bad name.
        let err = NoteSignature::new("a+b".into(), 0, vec![]).unwrap_err();
        assert!(matches!(err, NoteError::MalformedNote));

        // Attempt to sign with bad signer.
        let err = Note::new(text, &[])
            .unwrap()
            .add_sigs(&[&BadSigner {
                s: Box::new(signer.clone()),
            }])
            .unwrap_err();
        assert!(matches!(err, NoteError::InvalidSigner));

        let err = Note::new(text, &[])
            .unwrap()
            .add_sigs(&[&ErrSigner {
                s: Box::new(signer.clone()),
            }])
            .unwrap_err();
        assert!(matches!(err, NoteError::SignatureError(_)));
    }

    struct FixedVerifier {
        v: Box<dyn NoteVerifier>,
    }

    impl Verifiers for FixedVerifier {
        fn verifier(&self, _name: &str, _id: u32) -> Result<&dyn NoteVerifier, VerificationError> {
            Ok(&*self.v)
        }
    }

    #[test]
    fn test_open() {
        let peter_key = "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW";
        let peter_verifier = Ed25519NoteVerifier::new(peter_key).unwrap();

        let enoch_key = "EnochRoot+af0cfe78+ATtqJ7zOtqQtYqOo0CpvDXNlMhV3HeJDpjrASKGLWdop";
        let enoch_verifier = Ed25519NoteVerifier::new(enoch_key).unwrap();

        let text = "If you think cryptography is the answer to your problem,\n\
                    then you don't know what your problem is.\n";
        let peter_sig = "— PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n";
        let enoch_sig = "— EnochRoot rwz+eBzmZa0SO3NbfRGzPCpDckykFXSdeX+MNtCOXm2/5n2tiOHp+vAF1aGrQ5ovTG01oOTGwnWLox33WWd1RvMc+QQ=\n";

        let peter = NoteSignature::from_bytes(peter_sig.trim_end().as_bytes()).unwrap();
        let enoch = NoteSignature::from_bytes(enoch_sig.trim_end().as_bytes()).unwrap();

        // Check one signature verified, one not.
        let n = Note::from_bytes(format!("{text}\n{peter_sig}{enoch_sig}").as_bytes()).unwrap();
        let (verified_sigs, unverified_sigs) = n
            .verify(&VerifierList::new(vec![Box::new(peter_verifier.clone())]))
            .unwrap();
        assert_eq!(n.text(), text.as_bytes());
        assert_eq!(verified_sigs, vec![peter.clone()]);
        assert_eq!(unverified_sigs, vec![enoch.clone()]);

        // Check both verified.
        let (verified_sigs, unverified_sigs) = n
            .verify(&VerifierList::new(vec![
                Box::new(peter_verifier.clone()),
                Box::new(enoch_verifier.clone()),
            ]))
            .unwrap();
        assert_eq!(verified_sigs, vec![peter.clone(), enoch.clone()]);
        assert!(unverified_sigs.is_empty());

        // Check both unverified.
        let err = n.verify(&VerifierList::new(vec![])).unwrap_err();
        assert!(matches!(err, NoteError::UnverifiedNote));

        // Check duplicated verifier.
        let err = Note::from_bytes(format!("{text}\n{enoch_sig}").as_bytes())
            .unwrap()
            .verify(&VerifierList::new(vec![
                Box::new(enoch_verifier.clone()),
                Box::new(peter_verifier.clone()),
                Box::new(enoch_verifier.clone()),
            ]))
            .unwrap_err();
        assert_eq!(err.to_string(), "ambiguous key EnochRoot+af0cfe78");

        // Check unused duplicated verifier.
        let _ = Note::from_bytes(format!("{text}\n{peter_sig}").as_bytes())
            .unwrap()
            .verify(&VerifierList::new(vec![
                Box::new(enoch_verifier.clone()),
                Box::new(peter_verifier.clone()),
                Box::new(enoch_verifier.clone()),
            ]))
            .unwrap();

        // Check too many signatures.
        let err = Note::from_bytes(format!("{}\n{}", text, peter_sig.repeat(101)).as_bytes())
            .unwrap_err();
        assert!(matches!(err, NoteError::MalformedNote));

        // Invalid signature.
        let invalid_sig = format!("{}ABCD{}", &peter_sig[..60], &peter_sig[60..]);
        let err = Note::from_bytes(format!("{text}\n{invalid_sig}").as_bytes())
            .unwrap()
            .verify(&VerifierList::new(vec![Box::new(peter_verifier.clone())]))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid signature for key PeterNeumann+c74f20a3"
        );

        // Duplicated verified and unverified signatures.
        let enoch_abcd = NoteSignature::from_bytes("— EnochRoot rwz+eBzmZa0SO3NbfRGzPCpDckykFXSdeX+MNtCOXm2/5nABCD2tiOHp+vAF1aGrQ5ovTG01oOTGwnWLox33WWd1RvMc+QQ="
            .as_bytes(),
        )
        .unwrap();
        let sigs = format!(
            "{peter_sig}{peter_sig}{peter_sig}{enoch_sig}{}ABCD{}",
            &enoch_sig[..60],
            &enoch_sig[60..]
        );
        let n = Note::from_bytes(format!("{text}\n{sigs}").as_bytes()).unwrap();
        let (verified_sigs, unverified_sigs) = n
            .verify(&VerifierList::new(vec![Box::new(peter_verifier.clone())]))
            .unwrap();
        assert_eq!(verified_sigs, vec![peter.clone()]);
        assert_eq!(unverified_sigs, vec![enoch.clone(), enoch_abcd.clone()]);

        // Invalid encoded message syntax.
        let bad_msgs: Vec<Vec<u8>> = vec![
            text.as_bytes().to_vec(),
            format!("\n{text}").as_bytes().to_vec(),
            format!("{text}\n{}", &peter_sig[..peter_sig.len() - 1]).as_bytes().to_vec(),
            format!("\x01{text}\n{peter_sig}").as_bytes().to_vec(),
            [&[0xff], format!("{text}\n{peter_sig}").as_bytes()].concat(),
            format!("{text}\n— Bad Name x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=").as_bytes().to_vec(),
        ];

        for msg in bad_msgs {
            let err = Note::from_bytes(&msg).unwrap_err();
            assert!(matches!(err, NoteError::MalformedNote));
        }

        // Verifiers returns a Verifier for the wrong name or ID.
        let misnamed_sig = peter_sig.replace("PeterNeumann", "CarmenSandiego");
        let err = Note::from_bytes(format!("{text}\n{misnamed_sig}").as_bytes())
            .unwrap()
            .verify(&FixedVerifier {
                v: Box::new(peter_verifier.clone()),
            })
            .unwrap_err();
        assert!(matches!(err, NoteError::MismatchedVerifier));

        let wrong_id = peter_sig.replace("x08g", "xxxx");
        let err = Note::from_bytes(format!("{text}\n{wrong_id}").as_bytes())
            .unwrap()
            .verify(&FixedVerifier {
                v: Box::new(peter_verifier.clone()),
            })
            .unwrap_err();
        assert!(matches!(err, NoteError::MismatchedVerifier));
    }
}
