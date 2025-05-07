use base64::prelude::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature as EcdsaSignature, SigningKey as EcdsaSigningKey,
        VerifyingKey as EcdsaVerifyingKey,
    },
    pkcs8::EncodePublicKey,
};
use rand::{seq::SliceRandom, Rng};
use sha2::{Digest, Sha256};
use signed_note::{
    Note, NoteError as SignedNoteError, Signature as NoteSignature, Signer as NoteSigner,
    StandardVerifier, Verifier as NoteVerifier, VerifierError, VerifierList,
};
use std::io::Cursor;
use thiserror::Error;
use tlog_tiles::{Checkpoint, Hash};

use crate::{ReadLengthPrefixedBytesExt, TreeWithTimestamp, UnixTimestamp};

impl TreeWithTimestamp {
    /// Signs the tree and returns a [checkpoint](c2sp.org/tlog-checkpoint).
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    ///
    /// # Panics
    ///
    /// Panics if writing to the internal buffer fails, which should never happen.
    pub fn sign(
        &self,
        origin: &str,
        signing_key: &EcdsaSigningKey,
        witness_key: &Ed25519SigningKey,
        rng: &mut impl Rng,
    ) -> Result<Vec<u8>, CheckpointError> {
        let sth_bytes = serialize_sth_signature_input(self.time(), self.size(), self.hash());

        let tree_head_signature = sign(signing_key, &sth_bytes);

        // struct {
        //     uint64 timestamp;
        //     TreeHeadSignature signature;
        // } RFC6962NoteSignature;
        let mut sig = Vec::new();
        sig.write_u64::<BigEndian>(self.time()).unwrap();
        sig.extend_from_slice(&tree_head_signature);

        let v = RFC6962Verifier::new(origin, signing_key.verifying_key())?;
        let rs = InjectedSigner { v, sig };
        let ws = Ed25519Signer::new(origin, witness_key)?;

        // Randomize the order to enforce forward-compatible client behavior.
        let signers: &[&dyn NoteSigner] = if rng.gen_bool(0.5) {
            &[&rs, &ws]
        } else {
            &[&ws, &rs]
        };

        let Ok(checkpoint) = Checkpoint::new(origin, self.size(), *self.hash(), "") else {
            return Err(CheckpointError::Malformed);
        };
        let mut signed_note =
            Note::new(&checkpoint.to_bytes(), &gen_grease_signatures(origin, rng))?;
        signed_note.add_sigs(signers)?;

        Ok(signed_note.to_bytes())
    }
}

/// Implementation of [`NoteSigner`] that uses a precomputed signature.
struct InjectedSigner {
    v: RFC6962Verifier,
    sig: Vec<u8>,
}

impl NoteSigner for InjectedSigner {
    fn name(&self) -> &str {
        self.v.name()
    }
    fn key_id(&self) -> u32 {
        self.v.key_id()
    }
    fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
        Ok(self.sig.clone())
    }
}

/// Implementation of [`NoteSigner`] that signs with a Ed25519 key.
struct Ed25519Signer<'a> {
    v: Box<dyn NoteVerifier>,
    k: &'a Ed25519SigningKey,
}

impl<'a> Ed25519Signer<'a> {
    /// Returns a new `Ed25519Signer`.
    fn new(name: &str, k: &'a Ed25519SigningKey) -> Result<Self, VerifierError> {
        let vk = signed_note::new_ed25519_verifier_key(name, &k.verifying_key());
        let v = StandardVerifier::new(&vk)?;
        Ok(Self { v: Box::new(v), k })
    }
}

impl NoteSigner for Ed25519Signer<'_> {
    fn name(&self) -> &str {
        self.v.name()
    }
    fn key_id(&self) -> u32 {
        self.v.key_id()
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
        let sig = self.k.try_sign(msg)?;
        Ok(sig.to_vec())
    }
}

/// An error returned when opening or signing a checkpoint.
#[derive(Error, Debug)]
pub enum CheckpointError {
    #[error("missing verifier signature")]
    MissingVerifierSignature,
    #[error("malformed")]
    Malformed,
    #[error("timestamp is after current time")]
    InvalidTimestamp,
    #[error("checkpoint origin does not match")]
    OriginMismatch,
    #[error("unexpected extension")]
    UnexpectedExtension,
    #[error(transparent)]
    VerifierError(#[from] VerifierError),
    #[error(transparent)]
    NoteError(#[from] SignedNoteError),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

/// Open and verify a serialized checkpoint encoded as a [note](c2sp.org/signed-note), returning a [Checkpoint] and its timestamp.
///
/// # Errors
///
/// Returns an error if the checkpoint cannot be successfully opened and verified.
pub fn open_checkpoint(
    origin: &str,
    rfc6962_vkey: &EcdsaVerifyingKey,
    witness_vkey: &Ed25519VerifyingKey,
    current_time: UnixTimestamp,
    b: &[u8],
) -> Result<(Checkpoint, UnixTimestamp), CheckpointError> {
    let v1 = RFC6962Verifier::new(origin, rfc6962_vkey)?;
    let vk = signed_note::new_ed25519_verifier_key(origin, witness_vkey);
    let v2 = StandardVerifier::new(&vk)?;
    let n = Note::from_bytes(b)?;
    let (verified_sigs, _) = n.verify(&VerifierList::new(vec![
        Box::new(v1.clone()),
        Box::new(v2.clone()),
    ]))?;

    let mut timestamp: UnixTimestamp = 0;
    let mut v1_found = false;
    let mut v2_found = false;
    for sig in &verified_sigs {
        match sig.id() {
            h if h == v1.key_id() => {
                v1_found = true;
                timestamp = rfc6962_signature_timestamp(sig)?;
            }
            h if h == v2.key_id() => {
                v2_found = true;
            }
            _ => {}
        }
    }
    if !v1_found || !v2_found {
        return Err(CheckpointError::MissingVerifierSignature);
    }
    let Ok(checkpoint) = Checkpoint::from_bytes(n.text()) else {
        return Err(CheckpointError::Malformed);
    };
    if current_time < timestamp {
        return Err(CheckpointError::InvalidTimestamp);
    }
    if checkpoint.origin() != origin {
        return Err(CheckpointError::OriginMismatch);
    }
    if !checkpoint.extension().is_empty() {
        return Err(CheckpointError::UnexpectedExtension);
    }

    Ok((checkpoint, timestamp))
}

/// [`RFC6962Verifier`] is a [`NoteVerifier`] implementation
/// that verifies a RFC 6962 `TreeHeadSignature` formatted
/// according to <c2sp.org/static-ct-api>.
#[derive(Clone)]
pub struct RFC6962Verifier {
    name: String,
    id: u32,
    verifying_key: EcdsaVerifyingKey,
}

impl RFC6962Verifier {
    /// Returns a new [`RFC6962Verifier`] with the given name and verifying key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key name is invalid or if there are encoding issues.
    pub fn new(name: &str, verifying_key: &EcdsaVerifyingKey) -> Result<Self, VerifierError> {
        if !signed_note::is_key_name_valid(name) {
            return Err(VerifierError::Format);
        }

        let pkix = verifying_key
            .to_public_key_der()
            .map_err(|_| VerifierError::Format)?
            .to_vec();
        let key_id = Sha256::digest(&pkix).to_vec();

        let id = signed_note::key_id(
            name,
            &[0x05]
                .iter()
                .chain(key_id.iter())
                .copied()
                .collect::<Vec<_>>(),
        );

        Ok(Self {
            name: name.to_string(),
            id,
            verifying_key: *verifying_key,
        })
    }
}

impl NoteVerifier for RFC6962Verifier {
    fn name(&self) -> &str {
        &self.name
    }
    fn key_id(&self) -> u32 {
        self.id
    }
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let Ok(checkpoint) = Checkpoint::from_bytes(msg) else {
            return false;
        };
        if !checkpoint.extension().is_empty() {
            return false;
        }
        let mut s = Cursor::new(sig);
        let Ok(timestamp) = s.read_u64::<BigEndian>() else {
            return false;
        };
        let Ok(hash_alg) = s.read_u8() else {
            return false;
        };
        if hash_alg != 4 {
            return false;
        }
        let Ok(sig_alg) = s.read_u8() else {
            return false;
        };
        // Only support ECDSA
        if sig_alg != 3 {
            return false;
        }
        let Ok(signature) = s.read_length_prefixed(2) else {
            return false;
        };
        if s.position() != s.get_ref().len() as u64 {
            return false;
        }

        let sth_bytes =
            serialize_sth_signature_input(timestamp, checkpoint.size(), checkpoint.hash());

        let Ok(sig) = EcdsaSignature::from_der(&signature) else {
            return false;
        };

        self.verifying_key.verify(&sth_bytes, &sig).is_ok()
    }
}

/// Produces an encoded digitally-signed signature as defined in RFC 5246.
///
/// We use deterministic RFC 6979 ECDSA signatures so that when fetching a
/// previous SCT's timestamp and index from the deduplication cache, the new SCT
/// we produce is identical.
///
/// # Panics
///
/// Panics if writing to an internal buffer fails, which should never happen.
pub fn sign(signing_key: &EcdsaSigningKey, msg: &[u8]) -> Vec<u8> {
    let sig: EcdsaSignature = signing_key.sign(msg);
    let sig_der = sig.to_der();
    let sig_bytes = sig_der.as_bytes();

    // https://datatracker.ietf.org/doc/html/rfc5246#section-4.7
    let mut digitally_signed = Vec::new();
    digitally_signed.push(4); // hash = sha256
    digitally_signed.push(3); // signature = ecdsa
    digitally_signed
        .write_u16::<BigEndian>(u16::try_from(sig_bytes.len() & 0xFFFF).unwrap())
        .unwrap();
    digitally_signed.extend_from_slice(sig_bytes);

    digitally_signed
}

/// Produces unverifiable but otherwise correct signatures.
/// Clients MUST ignore unknown signatures, and including some "grease" ones
/// ensures they do.
fn gen_grease_signatures(origin: &str, rng: &mut impl Rng) -> Vec<NoteSignature> {
    let mut g1 = vec![0u8; 5 + rng.gen_range(0..100)];
    rng.fill(&mut g1[..]);

    let mut g2 = vec![0u8; 5 + rng.gen_range(0..100)];
    let mut hasher = Sha256::new();
    hasher.update(b"grease\n");
    hasher.update([rng.gen()]);
    let h = hasher.finalize();
    g2[..4].copy_from_slice(&h[..4]);
    rng.fill(&mut g2[4..]);

    let mut signatures = vec![
        NoteSignature::from_bytes(
            format!(
                "— {name} {signature}",
                name = "grease.invalid",
                signature = BASE64_STANDARD.encode(&g1)
            )
            .as_bytes(),
        )
        .unwrap(),
        NoteSignature::from_bytes(
            format!(
                "— {name} {signature}",
                name = origin,
                signature = BASE64_STANDARD.encode(&g2)
            )
            .as_bytes(),
        )
        .unwrap(),
    ];

    signatures.shuffle(rng);

    signatures
}

/// Reads the timestamp from a `RFC6962NoteSignature`.
/// A `RFC6962NoteSignature` (<https://c2sp.org/static-ct-api#checkpoints>) is structured as follows:
/// ```text
/// struct {
///     uint64 timestamp;
///     TreeHeadSignature signature;
/// } RFC6962NoteSignature;
/// ```
///
/// # Errors
///
/// Returns an error if the note signature is not at least eight bytes long.
pub fn rfc6962_signature_timestamp(sig: &NoteSignature) -> Result<u64, std::io::Error> {
    let timestamp = sig.signature().read_u64::<BigEndian>()?;
    Ok(timestamp)
}

/// Serializes the passed in STH parameters into the correct format for signing
/// according to <https://datatracker.ietf.org/doc/html/rfc6962#section-3.5>.
/// ```text
/// digitally-signed struct {
///     Version version;
///     SignatureType signature_type = tree_hash;
///     uint64 timestamp;
///     uint64 tree_size;
///     opaque sha256_root_hash[32];
/// } TreeHeadSignature;
/// ```
///
/// # Panics
///
/// Panics if writing to the internal buffer fails, which should never happen.
fn serialize_sth_signature_input(timestamp: u64, tree_size: u64, root_hash: &Hash) -> Vec<u8> {
    let mut buffer = Vec::new();

    buffer.write_u8(0).unwrap(); // version = 0 (v1)
    buffer.write_u8(1).unwrap(); // signature_type = 1 (tree_hash)
    buffer.write_u64::<BigEndian>(timestamp).unwrap();
    buffer.write_u64::<BigEndian>(tree_size).unwrap();
    buffer.extend(root_hash.0);

    buffer
}
