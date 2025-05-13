// Ported from "sunlight" (https://github.com/FiloSottile/sunlight)
// Copyright 2023 The Sunlight Authors
// Licensed under ISC License found in the LICENSE file or at https://opensource.org/license/isc-license-txt
//
// This ports code from the original Go project "sunlight" and adapts it to Rust idioms.
//
// Modifications and Rust implementation Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Provides support for the [Static CT API](https://c2sp.org/static-ct-api) wire format.
//!
//! This file contains code ported from the original project [sunlight](https://github.com/FiloSottile/sunlight).
//!
//! References:
//! - [tile.go](https://github.com/FiloSottile/sunlight/blob/36be227ff4599ac11afe3cec37a5febcd61da16a/tile.go)
//! - [extensions.go](https://github.com/FiloSottile/sunlight/blob/36be227ff4599ac11afe3cec37a5febcd61da16a/extensions.go)
//! - [checkpoint.go](https://github.com/FiloSottile/sunlight/blob/36be227ff4599ac11afe3cec37a5febcd61da16a/checkpoint.go)
//!
//! # Examples
//!
//! ## Opening and verifying a checkpoint
//! ```
//! use base64::prelude::*;
//! use p256::{pkcs8::DecodePublicKey, ecdsa::VerifyingKey as EcdsaVerifyingKey};
//! use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;
//!
//! let checkpoint: &str = "static-ct-dev.cloudflareresearch.com/logs/dev2024h2b
//! 5
//! YsndMEZccH1fI4kviHLu/Z1Ye3MgKkDwUHluUAOYuoY=
//!
//! — grease.invalid DLzQSDHFSzQAoz8nHm/h+UEP9JGkNhwVb9IP1sW3lvI+zQ==
//! — static-ct-dev.cloudflareresearch.com/logs/dev2024h2b sFXEux8xfyu4r8oNjISiP7KHW+We4qeOjAtSpKFgGUiD9agTzD81XyNWGMw=
//! — static-ct-dev.cloudflareresearch.com/logs/dev2024h2b 30nmRgAAAZSU01GqBAMASDBGAiEAps+yrlD9GB9pxdNomlfgABvNTI+NGlMFEsiJTynTkqwCIQDcxRtu9jY1gjLV1S+W55rCrr2yvl1PqSPY2UWh3dZ+eQ==
//! — static-ct-dev.cloudflareresearch.com/logs/dev2024h2b P6OcbFTzjZ8KFH9Oi3qOwgVdtJI5XiPcCbtLDeB/GrpzhtvSIZKAq8QgmAL5YwW6wFgpcp4PYuAhbQQ87R1S2nVAqAM=
//! ";
//!
//! // Log verification key from `curl <submission_url>/metadata | jq -r ".key"`
//! let rfc6962_vkey = &BASE64_STANDARD.decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAES4yrL7jarwxEdSWrJp35uef789UYLma/F0x7bfBpW2KWnN5yuDE5XgeOAKeWM3RpycCZF2xRGAp2iHFCa4PtqA==").unwrap();
//! let rfc6962_vkey = &EcdsaVerifyingKey::from_public_key_der(rfc6962_vkey).unwrap();
//!
//! // Witness verification key from `curl <submission_url>/metadata | jq -r ".witness_key"`.
//! let witness_vkey = &BASE64_STANDARD.decode("MCowBQYDK2VwAyEARN4KXLGKQrfUUGU1zwbFvEN1AckVY76d4CnuNRc20vI=").unwrap();
//! let witness_vkey = &Ed25519VerifyingKey::from_public_key_der(witness_vkey).unwrap();
//!
//! // Timestamp to use for verification, which must be at least as recent as the timestamp of the checkpoint.
//! let now: u64 = 1_737_664_860_920;
//!
//! let (_checkpoint, _timestamp) = static_ct_api::open_checkpoint(
//!   "static-ct-dev.cloudflareresearch.com/logs/dev2024h2b",
//!   rfc6962_vkey,
//!   witness_vkey,
//!   now,
//!   checkpoint.as_bytes(),
//! ).unwrap();
//! ```
//!
//! ## Verifying only the log signature on a checkpoint
//!
//! ```
//! use base64::prelude::*;
//! use p256::{pkcs8::DecodePublicKey, ecdsa::VerifyingKey as EcdsaVerifyingKey};
//! use signed_note::{Note, Verifier, VerifierList};
//! use static_ct_api::RFC6962Verifier;
//!
//!
//! let checkpoint: &str = "willow.ct.letsencrypt.org/2025h1b
//! 1237717073
//! pT/KC9MSHoRK2rHkeyfTSXfxolR2ja4JqhdymK9pnlo=
//!
//! — grease.invalid 6PiRCcvuZmG719Q08yWtEVT7C6ncT1s8R1xtzvX/reoSPKtuXROhW7Se59Kiwa7i98c/AM8tH4EElmqOQnJcF4cxRlbI9FY=
//! — willow.ct.letsencrypt.org/2025h1b kgUpF33pGg==
//! — willow.ct.letsencrypt.org/2025h1b ilIWIZPYgLHq/TqbHb14ff7ydbJ3VTODZcRE5VVYXTc3RduKQdVTwHV+Uv6NAEq9qBmjeXXw5QePKXNfDK747p2VOgo=
//! — willow.ct.letsencrypt.org/2025h1b GYcbuAAAAZSU2PMJBAMASDBGAiEAhNc5t31Sx4HmBDN4bh366ApPb1Ag1S1zn1XN02ibJNYCIQCKGun1fU1tcgMpWPu3918Rk6OBuoSjt7wdBag1cKsQ+g==
//! ";
//!
//! // Log verification key from https://willow.ct.letsencrypt.org/.
//! let rfc6962_vkey = &BASE64_STANDARD.decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbNmWXyYsF2pohGOAiNELea6UL4/XioI3w6ChE5Udlos0HUqM7KOHIP9qBuWCVs6VAdtDXrvanmxKq52Whh2+2w==").unwrap();
//! let rfc6962_vkey = &EcdsaVerifyingKey::from_public_key_der(rfc6962_vkey).unwrap();
//!
//! let verifier = RFC6962Verifier::new("willow.ct.letsencrypt.org/2025h1b", rfc6962_vkey).unwrap();
//! let n = Note::from_bytes(checkpoint.as_bytes()).unwrap();
//! let (verified_sigs, _) = n.verify(&VerifierList::new(vec![
//!     Box::new(verifier.clone()),
//! ])).unwrap();
//!
//! assert_eq!(verified_sigs.len(), 1);
//! assert!(verified_sigs.iter().any(|sig| {
//!   sig.id() == verifier.key_id()
//! }));
//! ```

use crate::AddChainResponse;
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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signed_note::{
    Note, NoteError as SignedNoteError, Signature as NoteSignature, Signer as NoteSigner,
    StandardVerifier, Verifier as NoteVerifier, VerifierError, VerifierList,
};
use std::io::{Cursor, Read, Write};
use thiserror::Error;
use tlog_tiles::{Checkpoint, Error as TlogError, Hash, HashReader, Tile};

/// Unix timestamp, measured since the epoch (January 1, 1970, 00:00),
/// ignoring leap seconds, in milliseconds.
/// This can be unsigned as we never deal with negative timestamps.
pub type UnixTimestamp = u64;

/// Fixed tile height for [static-ct-api](https://c2sp.org/static-ct-api#merkle-tree).
pub const TILE_HEIGHT: u8 = 8;

/// Fixed tile width for [static-ct-api](https://c2sp.org/static-ct-api#merkle-tree).
pub const TILE_WIDTH: u32 = 1 << TILE_HEIGHT;

const PATH_BASE: u64 = 1000;
/// [`tile_path`] returns a tile coordinate path describing `t`, according to <c2sp.org/static-ct-api>.
/// It differs from [`tlog_tiles::Tile::path`] in that it doesn't include an explicit tile height.
///
/// # Panics
///
/// Panics if `t.h` is not [`TILE_HEIGHT`].
pub fn tile_path(t: &Tile) -> String {
    assert_eq!(
        t.height(),
        TILE_HEIGHT,
        "unexpected tile height {}",
        t.height()
    );
    let mut n = t.level_index();
    let mut n_str = format!("{:03}", n % PATH_BASE);
    while n >= PATH_BASE {
        n /= PATH_BASE;
        n_str = format!("x{:03}/{}", n % PATH_BASE, n_str);
    }
    let p_str = if t.width() == 1 << t.height() {
        String::new()
    } else {
        format!(".p/{}", t.width())
    };
    let l_str = if t.is_data() {
        "data".to_string()
    } else {
        format!("{}", t.level())
    };
    format!("tile/{l_str}/{n_str}{p_str}")
}

/// Calculates the log ID from a verifying key.
///
/// # Errors
///
/// Returns an error if decoding the verifying key fails.
pub fn log_id_from_key(vkey: &EcdsaVerifyingKey) -> Result<[u8; 32], x509_verify::spki::Error> {
    let pkix = vkey.to_public_key_der()?;
    Ok(Sha256::digest(&pkix).into())
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct LogEntry {
    /// Either the `TimestampedEntry.signed_entry`, or the
    /// `PreCert.tbs_certificate` for Precertificates.
    /// It must be at most 2^24-1 bytes long.
    pub certificate: Vec<u8>,

    /// True if `LogEntryType` is `precert_entry`. Otherwise, the
    /// following three fields are zero and ignored.
    pub is_precert: bool,

    /// The `PreCert.issuer_key_hash`.
    pub issuer_key_hash: [u8; 32],

    /// The SHA-256 hashes of the certificates in the
    /// `X509ChainEntry.certificate_chain` or
    /// `PrecertChainEntry.precertificate_chain`.
    pub chain_fingerprints: Vec<[u8; 32]>,

    /// The `PrecertChainEntry.pre_certificate`.
    /// It must be at most 2^24-1 bytes long.
    pub pre_certificate: Vec<u8>,

    /// The zero-based index of the leaf in the log.
    /// It must be between 0 and 2^40-1.
    pub leaf_index: u64,

    /// The `TimestampedEntry.timestamp`.
    pub timestamp: UnixTimestamp,
}

pub type LookupKey = [u8; 16];

impl LogEntry {
    /// Returns a marshaled RFC 6962 `TimestampedEntry`.
    fn marshal_timestamped_entry(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.write_u64::<BigEndian>(self.timestamp).unwrap();
        if self.is_precert {
            buffer.write_u16::<BigEndian>(1).unwrap(); // entry_type = precert_entry
            buffer.extend_from_slice(&self.issuer_key_hash);
        } else {
            buffer.write_u16::<BigEndian>(0).unwrap(); // entry_type = x509_entry
        }
        write_length_prefixed(&mut buffer, &self.certificate, 3).unwrap();
        write_length_prefixed(
            &mut buffer,
            &Extensions {
                leaf_index: self.leaf_index,
            }
            .to_bytes(),
            2,
        )
        .unwrap();

        buffer
    }

    /// Returns a marshaled [RFC 6962 `MerkleTreeLeaf`](https://datatracker.ietf.org/doc/html/rfc6962#section-3.4).
    ///
    /// # Panics
    ///
    /// Panics if writing to the internal buffer fails, which should never happen.
    pub fn merkle_tree_leaf(&self) -> Vec<u8> {
        let mut buffer = vec![
            0, // version = v1 (0)
            0, // leaf_type = timestamped_entry (0)
        ];
        buffer.extend(self.marshal_timestamped_entry());

        buffer
    }

    /// Returns a marshaled [static-ct-api `TileLeaf`](https://c2sp.org/static-ct-api#log-entries).
    ///
    /// # Panics
    ///
    /// Panics if writing to the internal buffer fails, which should never happen.
    pub fn tile_leaf(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(self.marshal_timestamped_entry());
        if self.is_precert {
            write_length_prefixed(&mut buffer, &self.pre_certificate, 3).unwrap();
        }
        write_length_prefixed(&mut buffer, &self.chain_fingerprints.concat(), 2).unwrap();

        buffer
    }

    /// Compute the cache key for a log entry.
    ///
    /// # Panics
    ///
    /// Panics if there are errors writing to an internal buffer.
    pub fn lookup_key(&self) -> LookupKey {
        let mut buffer = Vec::new();
        if self.is_precert {
            // Add entry type = 1 (precert_entry)
            buffer.write_u16::<BigEndian>(1).unwrap();

            // Add issuer key hash
            buffer.extend_from_slice(&self.issuer_key_hash);
        } else {
            // Add entry type = 0 (x509_entry)
            buffer.write_u16::<BigEndian>(0).unwrap();
        }
        // Add certificate with a 24-bit length prefix
        write_length_prefixed(&mut buffer, &self.certificate, 3).unwrap();

        // Compute the SHA-256 hash of the buffer
        let hash = Sha256::digest(&buffer);

        // Return the first 16 bytes of the hash as the lookup key.
        let mut cache_hash = [0u8; 16];
        cache_hash.copy_from_slice(&hash[..16]);

        cache_hash
    }
}

/// A log entry that is ready to be serialized.
pub struct ValidatedChain {
    pub certificate: Vec<u8>,
    pub is_precert: bool,
    pub issuer_key_hash: [u8; 32],
    pub issuers: Vec<Vec<u8>>,
    pub pre_certificate: Vec<u8>,
}

/// An iterator over the contents of a data tile.
pub struct TileIterator {
    s: Cursor<Vec<u8>>,
    size: usize,
    count: usize,
}

impl std::iter::Iterator for TileIterator {
    type Item = Result<LogEntry, TileParseError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.count == self.size {
            return None;
        }
        self.count += 1;
        Some(self.parse_next())
    }
}

#[derive(Error, Debug)]
pub enum TileParseError {
    #[error("unknown type")]
    UnknownType,
    #[error("unexpected extension type")]
    UnexpectedExtension,
    #[error("trailing data")]
    TrailingData,
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

impl TileIterator {
    /// Returns a new [`TileIterator`], which always attempts to parse exactly
    /// 'size' entries before terminating.
    pub fn new(tile: Vec<u8>, size: usize) -> Self {
        Self {
            s: Cursor::new(tile),
            size,
            count: 0,
        }
    }

    /// Parse the next [`LogEntry`] from the internal buffer.
    fn parse_next(&mut self) -> Result<LogEntry, TileParseError> {
        // https://c2sp.org/static-ct-api#log-entries
        // struct {
        //     TimestampedEntry timestamped_entry;
        //     select (entry_type) {
        //         case x509_entry: Empty;
        //         case precert_entry: ASN.1Cert pre_certificate;
        //     };
        //     Fingerprint certificate_chain<0..2^16-1>;
        // } TileLeaf;
        //
        // opaque Fingerprint[32];

        let mut entry = LogEntry {
            timestamp: self.s.read_u64::<BigEndian>()?,
            ..Default::default()
        };
        let entry_type = self.s.read_u16::<BigEndian>()?;
        let extensions: Vec<u8>;
        let fingerprints: Vec<u8>;

        match entry_type {
            0 => {
                entry.certificate = read_length_prefixed(&mut self.s, 3)?;
                extensions = read_length_prefixed(&mut self.s, 2)?;
                fingerprints = read_length_prefixed(&mut self.s, 2)?;
            }
            1 => {
                entry.is_precert = true;
                self.s.read_exact(&mut entry.issuer_key_hash)?;
                entry.certificate = read_length_prefixed(&mut self.s, 3)?;
                extensions = read_length_prefixed(&mut self.s, 2)?;
                entry.pre_certificate = read_length_prefixed(&mut self.s, 3)?;
                fingerprints = read_length_prefixed(&mut self.s, 2)?;
            }
            _ => {
                return Err(TileParseError::UnknownType);
            }
        }

        let mut extensions = Cursor::new(extensions);
        if extensions.read_u8()? != 0 {
            return Err(TileParseError::UnexpectedExtension);
        }
        let extension_data = read_length_prefixed(&mut extensions, 2)?;
        entry.leaf_index = Cursor::new(&extension_data).read_uint::<BigEndian>(5)?;
        if extensions.position() != extensions.get_ref().len() as u64 {
            return Err(TileParseError::TrailingData);
        }

        let mut fingerprints = Cursor::new(fingerprints);
        while fingerprints.position() != fingerprints.get_ref().len() as u64 {
            let mut f = [0; 32];
            fingerprints.read_exact(&mut f)?;
            entry.chain_fingerprints.push(f);
        }

        Ok(entry)
    }
}

/// A transparency log tree with a timestamp.
#[derive(Default, Debug)]
pub struct TreeWithTimestamp {
    size: u64,
    hash: Hash,
    time: UnixTimestamp,
}

impl TreeWithTimestamp {
    /// Returns a new tree with the given hash.
    pub fn new(size: u64, hash: Hash, time: UnixTimestamp) -> Self {
        Self { size, hash, time }
    }

    /// Calculates the tree hash by reading tiles from the reader.
    ///
    /// # Errors
    ///
    /// Returns an error if unable to compute the tree hash.
    ///
    pub fn from_hash_reader<R: HashReader>(
        size: u64,
        r: &R,
        time: UnixTimestamp,
    ) -> Result<TreeWithTimestamp, TlogError> {
        let hash = tlog_tiles::tree_hash(size, r)?;
        Ok(Self { size, hash, time })
    }

    /// Returns the size of the tree.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the root hash of the tree.
    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    /// Returns the timestamp of the tree.
    pub fn time(&self) -> UnixTimestamp {
        self.time
    }

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
        let sth_bytes = serialize_sth_signature_input(self.time, self.size, &self.hash);

        let tree_head_signature = sign(signing_key, &sth_bytes);

        // struct {
        //     uint64 timestamp;
        //     TreeHeadSignature signature;
        // } RFC6962NoteSignature;
        let mut sig = Vec::new();
        sig.write_u64::<BigEndian>(self.time).unwrap();
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

        let Ok(checkpoint) = Checkpoint::new(origin, self.size, self.hash, "") else {
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

/// The `CTExtensions` field of `SignedCertificateTimestamp` and
/// `TimestampedEntry`, according to c2sp.org/static-ct-api.
#[derive(Default)]
pub struct Extensions {
    pub leaf_index: u64,
}

/// An error returned when opening a checkpoint.
#[derive(Error, Debug)]
pub enum ExtensionError {
    #[error("invalid length")]
    InvalidLength,
    #[error("trailing data")]
    TrailingData,
    #[error("missing leaf_index extension")]
    MissingLeafIndex,
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

impl Extensions {
    /// Marshals extensions for inclusion in an add-(pre-)chain response.
    ///
    /// # Panics
    ///
    /// Panics if writing to the internal buffer fails, which should never happen.
    pub fn to_bytes(&self) -> Vec<u8> {
        // https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#sct-extension
        // enum {
        //     leaf_index(0), (255)
        // } ExtensionType;
        //
        // struct {
        //     ExtensionType extension_type;
        //     opaque extension_data<0..2^16-1>;
        // } Extension;
        //
        // Extension CTExtensions<0..2^16-1>;
        //
        // uint8 uint40[5];
        // uint40 leaf_index;

        let mut buffer = Vec::new();
        buffer.write_u8(0).unwrap(); // extension_type = leaf_index
        buffer.write_u16::<BigEndian>(5).unwrap();
        buffer.write_uint::<BigEndian>(self.leaf_index, 5).unwrap();

        buffer
    }

    /// Parse a `CTExtensions` field, ignoring unknown extensions.
    ///
    /// # Errors
    ///
    /// Returns an error if the `leaf_index` extension is missing
    /// or the extension is otherwise malformed.
    pub fn from_bytes(ext_bytes: &[u8]) -> Result<Self, ExtensionError> {
        let mut cursor = Cursor::new(ext_bytes);
        let mut e = Extensions::default();

        while cursor.position() < ext_bytes.len() as u64 {
            let extension_type = cursor.read_u8()?;
            let length = cursor.read_u16::<BigEndian>()? as usize;

            if cursor.position() + length as u64 > ext_bytes.len() as u64 {
                return Err(ExtensionError::InvalidLength);
            }

            let mut extension = vec![0; length];
            cursor.read_exact(&mut extension)?;

            if extension_type == 0 {
                let mut extension_cursor = Cursor::new(&extension);
                e.leaf_index = extension_cursor.read_uint::<BigEndian>(5)?;

                if extension_cursor.position() != extension.len() as u64 {
                    return Err(ExtensionError::TrailingData);
                }

                return Ok(e);
            }
        }

        Err(ExtensionError::MissingLeafIndex)
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
        let Ok(signature) = read_length_prefixed(&mut s, 2) else {
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

/// Returns a signed add-[pre-]chain response with the `LeafIndex` extension.
///
/// # Panics
///
/// Panics if there are encoding issues with the provided signing key.
pub fn signed_certificate_timestamp(
    signing_key: &EcdsaSigningKey,
    entry: &LogEntry,
) -> AddChainResponse {
    let mut buffer = vec![
        0, // sct_version = v1 (0)
        0, // signature_type = certificate_timestamp (0)
    ];
    buffer.extend(entry.marshal_timestamped_entry());
    let signature = sign(signing_key, &buffer);
    let id = log_id_from_key(signing_key.verifying_key())
        .unwrap()
        .to_vec();

    AddChainResponse {
        sct_version: 0, // sct_version = v1 (0)
        id,
        timestamp: entry.timestamp,
        extensions: Extensions {
            leaf_index: entry.leaf_index,
        }
        .to_bytes(),
        signature,
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

/// Read a length-prefixed value from the passed in reader.
fn read_length_prefixed<R: Read>(
    reader: &mut R,
    length_bytes: usize,
) -> Result<Vec<u8>, std::io::Error> {
    let length = reader.read_uint::<BigEndian>(length_bytes)?;
    let mut buffer = vec![0; usize::try_from(length).unwrap()];
    reader.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// Write length-prefixed data to the passed in writer.
fn write_length_prefixed<W: Write>(
    writer: &mut W,
    data: &[u8],
    length_bytes: usize,
) -> Result<usize, std::io::Error> {
    writer.write_uint::<BigEndian>(data.len() as u64, length_bytes)?;
    writer.write(data)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse_extensions() {
        let ext = Extensions { leaf_index: 123 };
        let buf = ext.to_bytes();
        let ext2 = Extensions::from_bytes(&buf).unwrap();
        assert_eq!(ext.leaf_index, ext2.leaf_index);
    }
}
