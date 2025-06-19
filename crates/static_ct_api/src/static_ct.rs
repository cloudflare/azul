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
//! use signed_note::{Ed25519NoteVerifier, VerifierList};
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
//!     Ed25519NoteVerifier::new(&ed25519_verifier).unwrap()
//! };
//!
//! // Timestamp to use for verification, which must be at least as recent as the timestamp of the checkpoint.
//! let now: u64 = 1_737_664_860_920;
//!
//! // Make a list of the verifiers that MUST apear on the checkpoint, and load the checkpoint
//! let verifiers = VerifierList::new(vec![Box::new(rfc6962_verifier), Box::new(witness_verifier)]);
//! let (_checkpoint, _timestamp) = tlog_tiles::open_checkpoint(
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
//! use signed_note::{Note, NoteVerifier, VerifierList};
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
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use length_prefixed::{ReadLengthPrefixedBytesExt, WriteLengthPrefixedBytesExt};
use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature as EcdsaSignature, SigningKey as EcdsaSigningKey,
        VerifyingKey as EcdsaVerifyingKey,
    },
    pkcs8::EncodePublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signed_note::{
    NoteError, NoteVerifier, Signature as NoteSignature, SignerError, VerificationError,
    VerifierError,
};
use std::io::Read;
use tlog_tiles::{
    Checkpoint, CheckpointSigner, Hash, LeafIndex, LogEntry, LookupKey, PathElem, PendingLogEntry,
    SequenceMetadata, UnixTimestamp,
};

#[repr(u16)]
enum EntryType {
    X509Entry = 0,
    PrecertEntry = 1,
}

impl TryFrom<u16> for EntryType {
    type Error = ();

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(EntryType::X509Entry),
            1 => Ok(EntryType::PrecertEntry),
            _ => Err(()),
        }
    }
}

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

impl PendingLogEntry for StaticCTPendingLogEntry {
    /// The data tile path in static-ct-api is 'data'.
    const DATA_TILE_PATH: PathElem = PathElem::Data;

    /// No auxiliary data tile published in static-ct-api. (Rather, the
    /// auxiliary `chain_fingerprints` is included in the data tile directly.)
    const AUX_TILE_PATH: Option<PathElem> = None;

    /// Unused in static-ct-api.
    fn aux_entry(&self) -> &[u8] {
        unimplemented!()
    }

    /// Compute the cache key for a pending log entry.
    ///
    /// # Panics
    ///
    /// Panics if writing to an internal buffer fails, which should never happen.
    fn lookup_key(&self) -> LookupKey {
        let mut buffer = Vec::new();
        if let Some(precert_data) = &self.precert_opt {
            // Add entry type
            buffer
                .write_u16::<BigEndian>(EntryType::PrecertEntry as u16)
                .unwrap();

            // Add issuer key hash
            buffer.extend_from_slice(&precert_data.issuer_key_hash);
        } else {
            // Add entry type
            buffer
                .write_u16::<BigEndian>(EntryType::X509Entry as u16)
                .unwrap();
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
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct PrecertData {
    /// The `PreCert.issuer_key_hash`.
    pub issuer_key_hash: [u8; 32],

    /// The `PrecertChainEntry.pre_certificate`.
    /// It must be at most 2^24-1 bytes long.
    pub pre_certificate: Vec<u8>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct StaticCTPendingLogEntry {
    /// Either the `TimestampedEntry.signed_entry`, or the
    /// `PreCert.tbs_certificate` for Precertificates.
    /// It must be at most 2^24-1 bytes long.
    pub certificate: Vec<u8>,

    /// If populated, this entry is a precertificate.
    pub precert_opt: Option<PrecertData>,

    /// The SHA-256 hashes of the certificates in the
    /// `X509ChainEntry.certificate_chain` or
    /// `PrecertChainEntry.precertificate_chain`.
    pub chain_fingerprints: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StaticCTLogEntry {
    /// The pending entry that preceded this log entry
    pub inner: StaticCTPendingLogEntry,

    /// The zero-based index of the leaf in the log.
    /// It must be between 0 and 2^40-1.
    pub leaf_index: LeafIndex,

    /// The `TimestampedEntry.timestamp`.
    pub timestamp: UnixTimestamp,
}

impl StaticCTLogEntry {
    /// Returns a marshaled RFC 6962 `TimestampedEntry`.
    fn marshal_timestamped_entry(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.write_u64::<BigEndian>(self.timestamp).unwrap();
        if let Some(precert_data) = &self.inner.precert_opt {
            buffer
                .write_u16::<BigEndian>(EntryType::PrecertEntry as u16)
                .unwrap();
            buffer.extend_from_slice(&precert_data.issuer_key_hash);
        } else {
            buffer
                .write_u16::<BigEndian>(EntryType::X509Entry as u16)
                .unwrap();
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

impl LogEntry for StaticCTLogEntry {
    const REQUIRE_CHECKPOINT_TIMESTAMP: bool = true;
    type Pending = StaticCTPendingLogEntry;
    type ParseError = StaticCTError;

    fn initial_entry() -> Option<Self::Pending> {
        None
    }

    fn new(pending: StaticCTPendingLogEntry, metadata: SequenceMetadata) -> Self {
        StaticCTLogEntry {
            inner: pending,
            leaf_index: metadata.0,
            timestamp: metadata.1,
        }
    }

    /// Returns the Merkle tree leaf hash of a [RFC 6962 `MerkleTreeLeaf`](https://datatracker.ietf.org/doc/html/rfc6962#section-3.4).
    ///
    /// # Panics
    ///
    /// Panics if writing to the internal buffer fails, which should never happen.
    fn merkle_tree_leaf(&self) -> Hash {
        tlog_tiles::record_hash(
            &[
                &[
                    0, // version = v1 (0)
                    0, // leaf_type = timestamped_entry (0)
                ],
                self.marshal_timestamped_entry().as_slice(),
            ]
            .concat(),
        )
    }

    /// Returns a marshaled [static-ct-api `TileLeaf`](https://c2sp.org/static-ct-api#log-entries).
    ///
    /// # Panics
    ///
    /// Panics if writing to the internal buffer fails, which should never happen.
    fn to_data_tile_entry(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(self.marshal_timestamped_entry());
        if let Some(precert_data) = &self.inner.precert_opt {
            buffer
                .write_length_prefixed(&precert_data.pre_certificate, 3)
                .unwrap();
        }
        buffer
            .write_length_prefixed(&self.inner.chain_fingerprints.concat(), 2)
            .unwrap();

        buffer
    }

    /// Attempts to parse a `LogEntry` from a reader into a tile. The position
    /// of the reader is expected to be the beginning of an entry. On success,
    /// returns a log entry.
    fn parse_from_tile_entry<R: Read>(input: &mut R) -> Result<Self, StaticCTError> {
        // Parse a TileLeaf from the input, defined at
        // https://c2sp.org/static-ct-api#log-entries:
        //
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
        //
        // We also need these definitions from
        // https://datatracker.ietf.org/doc/html/rfc6962#section-3.4:
        //
        // struct {
        //     uint64 timestamp;
        //     LogEntryType entry_type;
        //     select(entry_type) {
        //         case x509_entry: ASN.1Cert;
        //         case precert_entry: PreCert;
        //     } signed_entry;
        //     CtExtensions extensions;
        // } TimestampedEntry;
        //
        // opaque ASN.1Cert<1..2^24-1>;
        //
        // struct {
        //   opaque issuer_key_hash[32];
        //   TBSCertificate tbs_certificate;
        // } PreCert;
        //
        // opaque TBSCertificate<1..2^24-1>
        //
        // enum {
        // 	 leaf_index(0), (255)
        // } ExtensionType;
        //
        // struct {
        // 	 ExtensionType extension_type;
        // 	 opaque extension_data<0..2^16-1>;
        // } Extension;
        //
        // Extension CtExtensions<0..2^16-1>;

        let timestamp = input.read_u64::<BigEndian>()?;
        let entry_type = input.read_u16::<BigEndian>()?;
        let mut precert_opt = match EntryType::try_from(entry_type) {
            Ok(EntryType::X509Entry) => None,
            Ok(EntryType::PrecertEntry) => Some(PrecertData {
                issuer_key_hash: [0; 32],
                pre_certificate: Vec::new(),
            }),
            Err(()) => {
                return Err(StaticCTError::UnknownType);
            }
        };
        if let Some(precert_data) = precert_opt.as_mut() {
            input.read_exact(&mut precert_data.issuer_key_hash)?;
        }
        let certificate = input.read_length_prefixed(3)?;
        let leaf_index = Extensions::from_bytes(&input.read_length_prefixed(2)?)?.leaf_index;
        if let Some(precert_data) = precert_opt.as_mut() {
            precert_data.pre_certificate = input.read_length_prefixed(3)?;
        }
        let chain_fingerprints = input
            .read_length_prefixed(2)?
            .chunks(32)
            .map(<[u8; 32]>::try_from)
            .collect::<Result<_, _>>()
            .map_err(|_| StaticCTError::TrailingData)?;

        Ok(StaticCTLogEntry {
            inner: StaticCTPendingLogEntry {
                certificate,
                precert_opt,
                chain_fingerprints,
            },
            leaf_index,
            timestamp,
        })
    }
}

/// The `CTExtensions` field of `SignedCertificateTimestamp` and
/// `TimestampedEntry`, according to c2sp.org/static-ct-api.
pub struct Extensions {
    pub leaf_index: u64,
}

impl Extensions {
    const EXT_TYPE_LEAF_INDEX: u8 = 0;
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
        buffer.write_u8(Self::EXT_TYPE_LEAF_INDEX).unwrap();
        buffer.write_u16::<BigEndian>(5).unwrap();
        buffer.write_uint::<BigEndian>(self.leaf_index, 5).unwrap();

        buffer
    }

    /// Parse a `CTExtensions` field from the input buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the `leaf_index` extension is missing, if there are
    /// unexpected extensions, or the extension is otherwise malformed.
    pub fn from_bytes(mut input: &[u8]) -> Result<Self, StaticCTError> {
        let mut leaf_index_opt = None;
        while !input.is_empty() {
            let extension_type = input.read_u8()?;
            let extension_data = input.read_length_prefixed(2)?;
            if extension_type == Self::EXT_TYPE_LEAF_INDEX {
                if leaf_index_opt.is_some() || extension_data.len() != 5 {
                    return Err(StaticCTError::Malformed);
                }
                leaf_index_opt = Some((&extension_data[..]).read_uint::<BigEndian>(5)?);
            } else {
                return Err(StaticCTError::UnexpectedExtension);
            }
        }
        if let Some(leaf_index) = leaf_index_opt {
            Ok(Extensions { leaf_index })
        } else {
            Err(StaticCTError::MissingLeafIndex)
        }
    }
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

    fn verify(&self, msg: &[u8], mut sig: &[u8]) -> bool {
        let Ok(checkpoint) = Checkpoint::from_bytes(msg) else {
            return false;
        };
        if !checkpoint.extension().is_empty() {
            return false;
        }
        let Ok(timestamp) = sig.read_u64::<BigEndian>() else {
            return false;
        };
        let Ok(hash_alg) = sig.read_u8() else {
            return false;
        };
        if hash_alg != 4 {
            return false;
        }
        let Ok(sig_alg) = sig.read_u8() else {
            return false;
        };
        // Only support ECDSA
        if sig_alg != 3 {
            return false;
        }
        let Ok(signature_der) = sig.read_length_prefixed(2) else {
            return false;
        };
        if !sig.is_empty() {
            return false;
        }

        let sth_bytes =
            serialize_sth_signature_input(timestamp, checkpoint.size(), checkpoint.hash());

        let Ok(signature) = EcdsaSignature::from_der(&signature_der) else {
            return false;
        };

        self.verifying_key.verify(&sth_bytes, &signature).is_ok()
    }

    fn extract_timestamp_millis(
        &self,
        mut sig: &[u8],
    ) -> Result<Option<UnixTimestamp>, VerificationError> {
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
        timestamp_unix_millis: UnixTimestamp,
        checkpoint: &Checkpoint,
    ) -> Result<NoteSignature, NoteError> {
        // RFC 6962-type signatures do not sign extension lines. If this checkpoint has extension lines, this is an error.
        if !checkpoint.extension().is_empty() {
            return Err(NoteError::MalformedNote);
        }

        // Produce the bytestring that will be signed
        let tree_head_bytes = serialize_sth_signature_input(
            timestamp_unix_millis,
            checkpoint.size(),
            checkpoint.hash(),
        );

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
    fn test_parse_tile_entry() {
        let inner = StaticCTPendingLogEntry {
            certificate: vec![1; 100],
            precert_opt: None,
            chain_fingerprints: vec![[0; 32], [1; 32], [2; 32]],
        };
        let entry = StaticCTLogEntry::new(inner, (123, 456));
        let tile: Vec<u8> = (0..5).flat_map(|_| entry.to_data_tile_entry()).collect();
        let mut tile_reader: &[u8] = tile.as_ref();

        for _ in 0..5 {
            let parsed_entry = StaticCTLogEntry::parse_from_tile_entry(&mut tile_reader).unwrap();
            assert_eq!(entry, parsed_entry);
        }
    }

    #[test]
    fn test_parse_extensions() {
        let ext = Extensions { leaf_index: 123 };
        let buf = ext.to_bytes();
        let ext2 = Extensions::from_bytes(&buf).unwrap();
        assert_eq!(ext.leaf_index, ext2.leaf_index);
    }
}
