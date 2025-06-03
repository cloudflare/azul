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
//! use signed_note::{StandardVerifier, VerifierList};
//! use static_ct_api::RFC6962Verifier;
//!
//! let origin: &str = "static-ct-dev.cloudflareresearch.com/logs/dev2024h2b";
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
//! let rfc6962_verifier = {
//!     let vkey_bytes = &BASE64_STANDARD.decode(
//!         "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAES4yrL7jarwxEdSWrJp35uef789UYLma/F0x7bfBpW2KWnN5yuDE5XgeOAKeWM3RpycCZF2xRGAp2iHFCa4PtqA=="
//!     ).unwrap();
//!     let ecdsa_vkey = EcdsaVerifyingKey::from_public_key_der(vkey_bytes).unwrap();
//!     RFC6962Verifier::new(origin, &ecdsa_vkey).unwrap()
//! };
//!
//! // Witness verification key from `curl <submission_url>/metadata | jq -r ".witness_key"`.
//! let witness_verifier = {
//!     let vkey_bytes = &BASE64_STANDARD.decode(
//!         "MCowBQYDK2VwAyEARN4KXLGKQrfUUGU1zwbFvEN1AckVY76d4CnuNRc20vI="
//!     ).unwrap();
//!     let ed25519_vkey = Ed25519VerifyingKey::from_public_key_der(vkey_bytes).unwrap();
//!     let ed25519_verifier = signed_note::new_ed25519_verifier_key(origin, &ed25519_vkey);
//!     StandardVerifier::new(&ed25519_verifier).unwrap()
//! };
//!
//! // Timestamp to use for verification, which must be at least as recent as the timestamp of the checkpoint.
//! let now: u64 = 1_737_664_860_920;
//!
//! // Make a list of the verifiers that MUST apear on the checkpoint, and load the checkpoint
//! let verifiers = VerifierList::new(vec![Box::new(rfc6962_verifier), Box::new(witness_verifier)]);
//! let (_checkpoint, _timestamp) = static_ct_api::open_checkpoint(
//!   "static-ct-dev.cloudflareresearch.com/logs/dev2024h2b",
//!   &verifiers,
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

use crate::{AddChainResponse, StaticCTError};
use base64::prelude::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use length_prefixed::{ReadLengthPrefixedBytesExt, WriteLengthPrefixedBytesExt};
use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature as EcdsaSignature, SigningKey as EcdsaSigningKey,
        VerifyingKey as EcdsaVerifyingKey,
    },
    pkcs8::EncodePublicKey,
};
use rand::{seq::SliceRandom, Rng};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signed_note::{
    Note, NoteError, Signature as NoteSignature, SignerError, StandardVerifier, VerificationError,
    Verifier as NoteVerifier, VerifierError, VerifierList, Verifiers,
};
use std::{
    io::{Cursor, Read},
    marker::PhantomData,
};
use tlog_tiles::{Checkpoint, CheckpointSigner, Hash, HashReader};

/// Unix timestamp, measured since the epoch (January 1, 1970, 00:00),
/// ignoring leap seconds, in milliseconds.
/// This can be unsigned as we never deal with negative timestamps.
pub type UnixTimestamp = u64;

/// Calculates the log ID from a verifying key.
///
/// # Errors
///
/// Returns an error if decoding the verifying key fails.
///
/// # Panics
///
/// Panics if decoding the verifying key fails.
pub fn log_id_from_key(vkey: &EcdsaVerifyingKey) -> Result<[u8; 32], StaticCTError> {
    let pkix = vkey.to_public_key_der()?;
    Ok(Sha256::digest(&pkix).into())
}

pub type LookupKey = [u8; 16];

/// The functionality exposed by any data type that can be included in a Merkle tree
pub trait PendingLogEntryTrait: core::fmt::Debug + Serialize + DeserializeOwned {
    /// The lookup key belonging to this pending log entry
    fn lookup_key(&self) -> LookupKey;

    /// The labels this objects wants to be used when it appears in Prometheus logging messages
    fn logging_labels(&self) -> Vec<String>;

    /// The canonical byte representation of this object. Only used by [`GenericLogEntry`].
    fn as_bytes(&self) -> &[u8];
}

pub trait LogEntryTrait: core::fmt::Debug + Sized {
    /// The pending version of this log entry. Usually the same thing but doesn't have a timestamp or tree index
    type Pending: PendingLogEntryTrait;

    /// The error type for [`Self::parse_from_tile_entry`]
    type ParseError: std::error::Error + Send + Sync + 'static;

    fn new(pending: Self::Pending, timestamp: UnixTimestamp, leaf_index: u64) -> Self;

    /// Returns the underlying pending entry
    fn inner(&self) -> &Self::Pending;

    /// Returns a marshaled [RFC 6962 `MerkleTreeLeaf`](https://datatracker.ietf.org/doc/html/rfc6962#section-3.4).
    fn merkle_tree_leaf(&self) -> Vec<u8>;

    /// Returns a marshaled [static-ct-api `TileLeaf`](https://c2sp.org/static-ct-api#log-entries).
    fn tile_leaf(&self) -> Vec<u8>;

    /// Attempts to parse a `LogEntry` from a cursor into a tile. The position of the cursor is
    /// expected to be the beginning of an entry. On success, returns a log entry.
    ///
    /// # Errors
    ///
    /// Errors if the log entry cannot be parsed from the cursor.
    fn parse_from_tile_entry(cur: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, Self::ParseError>;
}

impl PendingLogEntryTrait for StaticCTPendingLogEntry {
    /// Compute the cache key for a pending log entry.
    ///
    /// # Panics
    ///
    /// Panics if writing to an internal buffer fails, which should never happen.
    fn lookup_key(&self) -> LookupKey {
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
        buffer.write_length_prefixed(&self.certificate, 3).unwrap();

        // Compute the SHA-256 hash of the buffer
        let hash = Sha256::digest(&buffer);

        // Return the first 16 bytes of the hash as the lookup key.
        let mut cache_hash = [0u8; 16];
        cache_hash.copy_from_slice(&hash[..16]);

        cache_hash
    }

    fn logging_labels(&self) -> Vec<String> {
        if self.is_precert {
            vec!["add-pre-chain".to_string()]
        } else {
            vec!["add-chain".to_string()]
        }
    }

    /// We don't have a canonical representation. Eg the type of the length prefix depends on
    /// whether this is a precert. This is never used with `GenericLogEntry` so we can just not
    /// implement it.
    fn as_bytes(&self) -> &[u8] {
        unimplemented!()
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, Default, PartialEq)]
pub struct StaticCTPendingLogEntry {
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
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct StaticCTLogEntry {
    /// The pending entry that preceded this log entry
    pub inner: StaticCTPendingLogEntry,

    /// The zero-based index of the leaf in the log.
    /// It must be between 0 and 2^40-1.
    pub leaf_index: u64,

    /// The `TimestampedEntry.timestamp`.
    pub timestamp: UnixTimestamp,
}

impl StaticCTLogEntry {
    /// Returns a marshaled RFC 6962 `TimestampedEntry`.
    fn marshal_timestamped_entry(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.write_u64::<BigEndian>(self.timestamp).unwrap();
        if self.inner.is_precert {
            buffer.write_u16::<BigEndian>(1).unwrap(); // entry_type = precert_entry
            buffer.extend_from_slice(&self.inner.issuer_key_hash);
        } else {
            buffer.write_u16::<BigEndian>(0).unwrap(); // entry_type = x509_entry
        }
        buffer
            .write_length_prefixed(&self.inner.certificate, 3)
            .unwrap();
        buffer
            .write_length_prefixed(
                &Extensions {
                    leaf_index: self.leaf_index,
                }
                .to_bytes(),
                2,
            )
            .unwrap();

        buffer
    }
}

impl LogEntryTrait for StaticCTLogEntry {
    type Pending = StaticCTPendingLogEntry;

    // The error type for parse_from_tile_entry
    type ParseError = StaticCTError;

    fn new(pending: StaticCTPendingLogEntry, timestamp: u64, leaf_index: u64) -> Self {
        StaticCTLogEntry {
            inner: pending,
            timestamp,
            leaf_index,
        }
    }

    fn inner(&self) -> &StaticCTPendingLogEntry {
        &self.inner
    }

    /// Returns a marshaled [RFC 6962 `MerkleTreeLeaf`](https://datatracker.ietf.org/doc/html/rfc6962#section-3.4).
    ///
    /// # Panics
    ///
    /// Panics if writing to the internal buffer fails, which should never happen.
    fn merkle_tree_leaf(&self) -> Vec<u8> {
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
    fn tile_leaf(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(self.marshal_timestamped_entry());
        if self.inner.is_precert {
            buffer
                .write_length_prefixed(&self.inner.pre_certificate, 3)
                .unwrap();
        }
        buffer
            .write_length_prefixed(&self.inner.chain_fingerprints.concat(), 2)
            .unwrap();

        buffer
    }

    /// Attempts to parse a `LogEntry` from a cursor into a tile. The position of the cursor is
    /// expected to be the beginning of an entry. On success, returns a log entry
    fn parse_from_tile_entry(cur: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, StaticCTError> {
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

        let mut entry = StaticCTLogEntry {
            timestamp: cur.read_u64::<BigEndian>()?,
            ..Default::default()
        };
        let entry_type = cur.read_u16::<BigEndian>()?;
        let extensions: Vec<u8>;
        let fingerprints: Vec<u8>;

        match entry_type {
            0 => {
                entry.inner.certificate = cur.read_length_prefixed(3)?;
                extensions = cur.read_length_prefixed(2)?;
                fingerprints = cur.read_length_prefixed(2)?;
            }
            1 => {
                entry.inner.is_precert = true;
                cur.read_exact(&mut entry.inner.issuer_key_hash)?;
                entry.inner.certificate = cur.read_length_prefixed(3)?;
                extensions = cur.read_length_prefixed(2)?;
                entry.inner.pre_certificate = cur.read_length_prefixed(3)?;
                fingerprints = cur.read_length_prefixed(2)?;
            }
            _ => {
                return Err(StaticCTError::UnknownType);
            }
        }

        let mut extensions = Cursor::new(extensions);
        if extensions.read_u8()? != 0 {
            return Err(StaticCTError::UnexpectedExtension);
        }
        let extension_data = extensions.read_length_prefixed(2)?;
        entry.leaf_index = Cursor::new(&extension_data).read_uint::<BigEndian>(5)?;
        if extensions.position() != extensions.get_ref().len() as u64 {
            return Err(StaticCTError::TrailingData);
        }

        let mut fingerprints = Cursor::new(fingerprints);
        while fingerprints.position() != fingerprints.get_ref().len() as u64 {
            let mut f = [0; 32];
            fingerprints.read_exact(&mut f)?;
            entry.inner.chain_fingerprints.push(f);
        }

        Ok(entry)
    }
}

/* TODO: Uncomment this once the static CT types are implemented
/// A generic log entry compatible with the [tlog-tiles spec](https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md)
#[derive(Debug)]
struct GenericLogEntry<E: PendingLogEntryTrait>(E);

impl<E: PendingLogEntryTrait> LogEntryTrait<E> for GenericLogEntry<E> {
    fn new(pending: E, _: UnixTimestamp, _: u64) -> Self {
        GenericLogEntry(pending)
    }

    fn inner(&self) -> &E {
        &self.0
    }

    /// Returns a marshaled [RFC 6962 `MerkleTreeLeaf`](https://datatracker.ietf.org/doc/html/rfc6962#section-3.4).
    ///
    /// # Panics
    ///
    /// Panics if writing to the internal buffer fails, which should never happen.
    fn merkle_tree_leaf(&self) -> Vec<u8> {
        record_hash(self.0.as_bytes()).0.to_vec()
    }

    /// Returns a marshaled [static-ct-api `TileLeaf`](https://c2sp.org/static-ct-api#log-entries).
    ///
    /// # Panics
    ///
    /// Panics if writing to the internal buffer fails, which should never happen.
    fn tile_leaf(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.write_length_prefixed(self.0.as_bytes(), 2).unwrap();

        buf
    }
}
*/

/// A log entry that is ready to be serialized.
pub struct ValidatedChain {
    pub certificate: Vec<u8>,
    pub is_precert: bool,
    pub issuer_key_hash: [u8; 32],
    pub issuers: Vec<Vec<u8>>,
    pub pre_certificate: Vec<u8>,
}

/// An iterator over log entries in a data tile.
pub struct TileIterator<L: LogEntryTrait> {
    s: Cursor<Vec<u8>>,
    size: usize,
    count: usize,
    _marker: PhantomData<L>,
}

impl<L: LogEntryTrait> std::iter::Iterator for TileIterator<L> {
    type Item = Result<L, L::ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == self.size {
            return None;
        }
        self.count += 1;
        Some(self.parse_next())
    }
}

impl<L: LogEntryTrait> TileIterator<L> {
    /// Returns a new [`TileIterator`], which always attempts to parse exactly
    /// 'size' entries before terminating.
    pub fn new(tile: Vec<u8>, size: usize) -> Self {
        Self {
            s: Cursor::new(tile),
            size,
            count: 0,
            _marker: PhantomData,
        }
    }

    /// Parse the next [`LogEntry`] from the internal buffer.
    fn parse_next(&mut self) -> Result<L, L::ParseError> {
        L::parse_from_tile_entry(&mut self.s)
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
    ) -> Result<TreeWithTimestamp, StaticCTError> {
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
        signers: &[&dyn CheckpointSigner],
        rng: &mut impl Rng,
    ) -> Result<Vec<u8>, StaticCTError> {
        // Shuffle the signer order
        let mut signers = signers.to_vec();
        signers.shuffle(rng);

        // Construct the checkpoint with no extension lines
        let Ok(checkpoint) = Checkpoint::new(origin, self.size, self.hash, "") else {
            return Err(StaticCTError::Malformed);
        };
        // Sign the checkpoint with the given signers
        let sigs = signers
            .iter()
            .map(|s| s.sign(self.time, &checkpoint))
            .collect::<Result<Vec<_>, NoteError>>()?;
        // Generate some fake signatures as grease
        let grease_sigs = gen_grease_signatures(origin, rng);

        // Make a new signed note from the checkpoint and serialize it
        let signed_note = Note::new(&checkpoint.to_bytes(), &[grease_sigs, sigs].concat())?;
        Ok(signed_note.to_bytes())
    }
}

/// Implementation of [`NoteSigner`] that signs with a Ed25519 key.
#[cfg_attr(test, derive(Clone))]
pub struct StandardEd25519CheckpointSigner {
    v: StandardVerifier,
    k: Ed25519SigningKey,
}

impl StandardEd25519CheckpointSigner {
    /// Returns a new `Ed25519Signer`.
    ///
    /// # Errors
    ///
    /// Errors if a verifier cannot be created from the provided signing key.
    pub fn new(name: &str, k: Ed25519SigningKey) -> Result<Self, StaticCTError> {
        let vk = signed_note::new_ed25519_verifier_key(name, &k.verifying_key());
        // Checks if the key name is valid
        let v = StandardVerifier::new(&vk)?;
        Ok(Self { v, k })
    }
}

impl CheckpointSigner for StandardEd25519CheckpointSigner {
    fn name(&self) -> &str {
        self.v.name()
    }

    fn key_id(&self) -> u32 {
        self.v.key_id()
    }

    fn sign(
        &self,
        _timestamp_unix_millis: u64,
        checkpoint: &Checkpoint,
    ) -> Result<NoteSignature, NoteError> {
        let msg = checkpoint.to_bytes();
        // Ed25519 signing cannot fail
        let sig = self.k.try_sign(&msg).unwrap();

        // Return the note signature. We can unwrap() here because the only cause for error is if
        // the name is invalid, which is checked in the constructor
        Ok(NoteSignature::new(self.name().to_string(), self.key_id(), sig.to_vec()).unwrap())
    }

    fn verifier(&self) -> Box<dyn NoteVerifier> {
        let vk = signed_note::new_ed25519_verifier_key(self.name(), &self.k.verifying_key());
        // We can unwrap because it only fails on an invalid key name, but this was checked in the constructor
        Box::new(StandardVerifier::new(&vk).unwrap())
    }
}

/// The `CTExtensions` field of `SignedCertificateTimestamp` and
/// `TimestampedEntry`, according to c2sp.org/static-ct-api.
#[derive(Default)]
pub struct Extensions {
    pub leaf_index: u64,
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
    pub fn from_bytes(ext_bytes: &[u8]) -> Result<Self, StaticCTError> {
        let mut cursor = Cursor::new(ext_bytes);
        let mut e = Extensions::default();

        while cursor.position() < ext_bytes.len() as u64 {
            let extension_type = cursor.read_u8()?;
            let length = cursor.read_u16::<BigEndian>()? as usize;

            if cursor.position() + length as u64 > ext_bytes.len() as u64 {
                return Err(StaticCTError::InvalidLength);
            }

            let mut extension = vec![0; length];
            cursor.read_exact(&mut extension)?;

            if extension_type == 0 {
                let mut extension_cursor = Cursor::new(&extension);
                e.leaf_index = extension_cursor.read_uint::<BigEndian>(5)?;

                if extension_cursor.position() != extension.len() as u64 {
                    return Err(StaticCTError::TrailingData);
                }

                return Ok(e);
            }
        }

        Err(StaticCTError::MissingLeafIndex)
    }
}

/// Open and verify a serialized checkpoint encoded as a [note](c2sp.org/signed-note), returning a
/// [Checkpoint] and the latest timestamp of any of its cosignatures (if defined).
///
/// # Errors
///
/// Returns an error if the checkpoint cannot be successfully opened and verified.
pub fn open_checkpoint(
    origin: &str,
    verifiers: &VerifierList,
    current_time: UnixTimestamp,
    b: &[u8],
) -> Result<(Checkpoint, Option<UnixTimestamp>), StaticCTError> {
    let n = Note::from_bytes(b)?;
    let (verified_sigs, _) = n.verify(verifiers)?;

    // Go through the signatures and make sure we find all the key IDs in our verifiers list
    let mut key_ids_to_observe = verifiers.key_ids();
    // The latest timestamp of the signatures in the note. We use this to check that nothing was signed in the future
    let mut latest_timestamp: Option<UnixTimestamp> = None;
    for sig in &verified_sigs {
        // Fetch the verifier for this signature, if it's here
        let verif = match verifiers.verifier(sig.name(), sig.id()) {
            Ok(v) => {
                // We've now observed this key ID. Remove it from the list
                key_ids_to_observe.remove(&sig.id());
                v
            }
            Err(_) => continue,
        };

        // Extract the timestamp if it's in the sig, and update the latest running timestamp
        let sig_timestamp = verif.extract_timestamp_millis(sig.signature())?;
        if let Some(t) = sig_timestamp {
            latest_timestamp = Some(core::cmp::max(latest_timestamp.unwrap_or(0), t));
        }
    }

    // If we didn't see all the verifiers we wanted to see, error
    if !key_ids_to_observe.is_empty() {
        return Err(StaticCTError::MissingVerifierSignature);
    }
    let Ok(checkpoint) = Checkpoint::from_bytes(n.text()) else {
        return Err(StaticCTError::Malformed);
    };
    if current_time < latest_timestamp.unwrap_or(0) {
        return Err(StaticCTError::InvalidTimestamp);
    }
    if checkpoint.origin() != origin {
        return Err(StaticCTError::OriginMismatch);
    }
    if !checkpoint.extension().is_empty() {
        return Err(StaticCTError::UnexpectedExtension);
    }

    Ok((checkpoint, latest_timestamp))
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
        let key_id = Sha256::digest(&pkix);

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

    fn extract_timestamp_millis(&self, mut sig: &[u8]) -> Result<Option<u64>, VerificationError> {
        // In a static-ct signed tree head, the timestamp is the first 8 bytes of the sig
        //   https://github.com/C2SP/C2SP/blob/efb68c16664309a68120e37528fa1c046dd1ac09/static-ct-api.md#checkpoints
        // and it's in milliseconds
        //   https://www.rfc-editor.org/rfc/rfc6962.html#section-3.2
        let ts = sig
            .read_u64::<BigEndian>()
            .map_err(|_| VerificationError::Timestamp)?;
        Ok(Some(ts))
    }
}

/// Returns a signed add-[pre-]chain response with the `LeafIndex` extension.
///
/// # Errors
///
/// Errors if there are encoding issues with the provided signing key.
pub fn signed_certificate_timestamp(
    signing_key: &EcdsaSigningKey,
    entry: &StaticCTLogEntry,
) -> Result<AddChainResponse, StaticCTError> {
    let mut buffer = vec![
        0, // sct_version = v1 (0)
        0, // signature_type = certificate_timestamp (0)
    ];
    buffer.extend(entry.marshal_timestamped_entry());
    let signature = sign(signing_key, &buffer);
    let id = log_id_from_key(signing_key.verifying_key())?.to_vec();

    Ok(AddChainResponse {
        sct_version: 0, // sct_version = v1 (0)
        id,
        timestamp: entry.timestamp,
        extensions: Extensions {
            leaf_index: entry.leaf_index,
        }
        .to_bytes(),
        signature,
    })
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

    // Format the tree head signature per https://datatracker.ietf.org/doc/html/rfc5246#section-4.7
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
/// Panics if writing to an internal buffer fails, which should never happen.
fn serialize_sth_signature_input(timestamp: u64, tree_size: u64, root_hash: &Hash) -> Vec<u8> {
    let mut buffer = Vec::new();

    buffer.write_u8(0).unwrap(); // version = 0 (v1)
    buffer.write_u8(1).unwrap(); // signature_type = 1 (tree_hash)
    buffer.write_u64::<BigEndian>(timestamp).unwrap();
    buffer.write_u64::<BigEndian>(tree_size).unwrap();
    buffer.extend(root_hash.0);

    buffer
}

/// A static-ct-style checkpoint signer. This is different from, e.g., a tlog-cosignature signer.
/// This produces an encoded digitally-signed signature as defined in RFC 5246.
///
/// We use deterministic RFC 6979 ECDSA signatures so that when fetching a previous SCT's timestamp
/// and index from the deduplication cache, the new SCT we produce is identical.
#[cfg_attr(test, derive(Clone))]
pub struct StaticCTCheckpointSigner {
    name: String,
    id: u32,
    signing_key: EcdsaSigningKey,
}

impl StaticCTCheckpointSigner {
    /// Returns a new signer for signing static-ct-api checkpoints.
    ///
    /// # Errors
    ///
    /// Errors if the provided name is invalid.
    pub fn new(name: &str, signing_key: EcdsaSigningKey) -> Result<Self, SignerError> {
        // Reuse the verifier code. This compute the correct key ID
        let vk = signing_key.verifying_key();
        // This checks if the name is invalid. If it is, it returns VerifierError::Format. That's
        // actually all it returns on error, so the map_err isn't losing any info.
        let verifier = RFC6962Verifier::new(name, vk).map_err(|_| SignerError::Format)?;

        Ok(Self {
            name: name.to_owned(),
            id: verifier.id,
            signing_key,
        })
    }
}

impl CheckpointSigner for StaticCTCheckpointSigner {
    fn name(&self) -> &str {
        &self.name
    }

    fn key_id(&self) -> u32 {
        self.id
    }

    /// Produces a signature over the given checkpoint using the method described in static-ct.
    /// Namely, compute the RFC 6962 [signed tree head](https://www.rfc-editor.org/rfc/rfc6962.html#section-3.5),
    /// then prepend the timestamp.
    fn sign(
        &self,
        timestamp_unix_millis: u64,
        checkpoint: &Checkpoint,
    ) -> Result<NoteSignature, NoteError> {
        // RFC 6962-type signatures do not sign extension lines. If this checkpoint has extension lines, this is an error.
        if !checkpoint.extension().is_empty() {
            return Err(NoteError::MalformedNote);
        }

        // Produce the bytestring that will be signed
        let tree_head_bytes = {
            let mut buffer = Vec::new();

            buffer.write_u8(0).unwrap(); // version = 0 (v1)
            buffer.write_u8(1).unwrap(); // signature_type = 1 (tree_hash)
            buffer
                .write_u64::<BigEndian>(timestamp_unix_millis)
                .unwrap();
            buffer.write_u64::<BigEndian>(checkpoint.size()).unwrap();
            buffer.extend(checkpoint.hash().0);

            buffer
        };

        // Sign the string
        let tree_head_sig = sign(&self.signing_key, &tree_head_bytes);

        // Now format the final signature
        // struct {
        //     uint64 timestamp;
        //     TreeHeadSignature signature;
        // } RFC6962NoteSignature;
        let mut note_sig = Vec::new();
        note_sig
            .write_u64::<BigEndian>(timestamp_unix_millis)
            .unwrap();
        note_sig.extend_from_slice(&tree_head_sig);

        // Return the note signature. We can unwrap() here because the only cause for error is if
        // the name is invalid, which is checked in the constructor
        Ok(NoteSignature::new(self.name.clone(), self.id, note_sig).unwrap())
    }

    fn verifier(&self) -> Box<dyn NoteVerifier> {
        // We can unwrap because it only fails on an invalid key name, but this was checked in the constructor
        Box::new(RFC6962Verifier::new(&self.name, self.signing_key.verifying_key()).unwrap())
    }
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
