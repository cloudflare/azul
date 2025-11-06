// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

mod cosigner;
mod landmark;
mod relative_oid;
pub use cosigner::*;
pub use landmark::*;
pub use relative_oid::*;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use der::{
    asn1::{BitString, OctetString},
    oid::{db::rfc5280, ObjectIdentifier},
    Any, Decode, Encode, Sequence, ValueOrd,
};
use length_prefixed::WriteLengthPrefixedBytesExt;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    io::Read,
    num::ParseIntError,
};
use thiserror::Error;
use tlog_tiles::{
    Hash, LeafIndex, LogEntry, PathElem, PendingLogEntry, Proof, SequenceMetadata, Subtree,
    TlogError, TlogTilesLogEntry, TlogTilesPendingLogEntry, UnixTimestamp,
};
use x509_cert::{
    certificate::Version,
    ext::{
        pkix::{ExtendedKeyUsage, KeyUsage, KeyUsages},
        Extension, Extensions,
    },
    name::{Name, RdnSequence},
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifier, SubjectPublicKeyInfo},
    time::Validity,
    Certificate, TbsCertificate,
};
use x509_util::{validate_chain_lax, CertPool, ValidationOptions};

// The OID to use for experimentaion. Eventually, we'll switch to "1.3.6.1.5.5.7.TBD1.TBD2"
// as described in <https://www.ietf.org/archive/id/draft-davidben-tls-merkle-tree-certs-05.html#name-log-ids>.
pub const ID_RDNA_TRUSTANCHOR_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.44363.47.1");

// The OID to use for experimentaion. Eventually, we'll switch to "1.3.6.1.5.5.7.6.TBD"
// as described in <https://www.ietf.org/archive/id/draft-davidben-tls-merkle-tree-certs-05.html#name-certificate-format>.
pub const ID_ALG_MTCPROOF: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.44363.47.0");

// MTCSignature from <https://www.ietf.org/archive/id/draft-davidben-tls-merkle-tree-certs-05.html#name-certificate-format>.
struct MtcSignature {
    cosigner_id: TrustAnchorID,
    signature: Vec<u8>,
}

impl MtcSignature {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer
            .write_length_prefixed(self.cosigner_id.as_bytes(), 1)
            .unwrap();
        buffer.write_length_prefixed(&self.signature, 2).unwrap();
        buffer
    }
}

// MTCProof from <https://www.ietf.org/archive/id/draft-davidben-tls-merkle-tree-certs-05.html#name-certificate-format>.
struct MtcProof {
    start: u64,
    end: u64,
    inclusion_proof: Proof,
    signatures: Vec<MtcSignature>,
}

impl MtcProof {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.write_u64::<BigEndian>(self.start).unwrap();
        buffer.write_u64::<BigEndian>(self.end).unwrap();
        buffer
            .write_length_prefixed(
                &self
                    .inclusion_proof
                    .iter()
                    .flat_map(|h| h.0.to_vec())
                    .collect::<Vec<u8>>(),
                2,
            )
            .unwrap();
        buffer
            .write_length_prefixed(
                &self
                    .signatures
                    .iter()
                    .flat_map(MtcSignature::to_bytes)
                    .collect::<Vec<u8>>(),
                2,
            )
            .unwrap();
        buffer
    }
}

/// Add-entry request. Chain is a certificate from which to bootstrap the
/// request in the same format as RFC6962 add-chain requests.
#[serde_as]
#[derive(Deserialize)]
pub struct AddEntryRequest {
    #[serde_as(as = "Vec<Base64>")]
    pub chain: Vec<Vec<u8>>,
}

/// Add-entry response.
#[serde_as]
#[derive(Serialize)]
pub struct AddEntryResponse {
    /// The index of the entry in the log.
    pub leaf_index: LeafIndex,

    /// The time at which the entry was added to the log.
    pub timestamp: UnixTimestamp,

    /// The validity period of the certificate.
    pub not_before: UnixTimestamp,
    pub not_after: UnixTimestamp,
}

/// Get-roots response. This is in the same format as the RFC 6962 get-roots
/// response, which is the base64 encoding of the DER-encoded certificate bytes.
#[serde_as]
#[derive(Serialize)]
pub struct GetRootsResponse {
    #[serde_as(as = "Vec<Base64>")]
    pub certificates: Vec<Vec<u8>>,
}

/// A wrapper around `TlogTilesPendingLogEntry` that supports auxiliary bootstrap data.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct BootstrapMtcPendingLogEntry {
    /// The serialized bootstrap chain.
    pub bootstrap: Vec<u8>,

    /// An encoded `MerkleTreeCertEntry` wrapped in a generic `TlogTilesPendingLogEntry`.
    pub entry: TlogTilesPendingLogEntry,
}

impl PendingLogEntry for BootstrapMtcPendingLogEntry {
    /// MTC uses the same data tile path as tlog-tiles, 'entries'.
    const DATA_TILE_PATH: PathElem = TlogTilesPendingLogEntry::DATA_TILE_PATH;

    /// MTC publishes unauthenticated bootstrap data at 'bootstrap'.
    const AUX_TILE_PATH: Option<PathElem> = Some(PathElem::Custom("bootstrap"));

    /// Returns the serialized bootstrap data.
    fn aux_entry(&self) -> &[u8] {
        &self.bootstrap
    }

    fn lookup_key(&self) -> tlog_tiles::LookupKey {
        self.entry.lookup_key()
    }
}

/// A wrapper around `TlogTilesLogEntry` that supports customizations for MTCs like the initial log entry.
#[derive(Debug, Clone, PartialEq)]
pub struct BootstrapMtcLogEntry(TlogTilesLogEntry);

impl LogEntry for BootstrapMtcLogEntry {
    const REQUIRE_CHECKPOINT_TIMESTAMP: bool = false;
    type Pending = BootstrapMtcPendingLogEntry;
    type ParseError = MtcError;

    fn initial_entry() -> Option<Self::Pending> {
        Some(Self::Pending {
            bootstrap: vec![0, 0, 0], // u24 length prefix for empty bootstrap data
            entry: TlogTilesPendingLogEntry {
                data: MerkleTreeCertEntry::NullEntry.encode().unwrap(),
            },
        })
    }

    fn new(pending: Self::Pending, metadata: SequenceMetadata) -> Self {
        Self(TlogTilesLogEntry::new(pending.entry, metadata))
    }

    fn merkle_tree_leaf(&self) -> Hash {
        self.0.merkle_tree_leaf()
    }

    fn to_data_tile_entry(&self) -> Vec<u8> {
        self.0.to_data_tile_entry()
    }

    fn parse_from_tile_entry<R: Read>(input: &mut R) -> Result<Self, Self::ParseError> {
        Ok(Self(TlogTilesLogEntry::parse_from_tile_entry(input)?))
    }
}

/// Return the serialized DER-encoded bytes of a signatureless certificate.
///
/// # Errors
///
/// Will return an error if the hash of `spki` does not match that in the log
/// entry, or if there are any serialization errors.
pub fn serialize_signatureless_cert(
    log_entry: &BootstrapMtcLogEntry,
    leaf_index: LeafIndex,
    spki_der: &[u8],
    subtree: &Subtree,
    inclusion_proof: Proof,
) -> Result<Vec<u8>, MtcError> {
    let entry = match MerkleTreeCertEntry::decode(&log_entry.0.inner.data)? {
        MerkleTreeCertEntry::TbsCertEntry(entry) => entry,
        MerkleTreeCertEntry::NullEntry => {
            return Err(MtcError::Dynamic("no tbs cert entry for null entry".into()))
        }
    };
    let spki: SubjectPublicKeyInfo<Any, BitString> = SubjectPublicKeyInfo::from_der(spki_der)?;
    let spki_hash = OctetString::new(Sha256::digest(spki_der).as_slice())?;
    if spki_hash != entry.subject_public_key_info_hash {
        return Err(MtcError::Dynamic("spki hash mismatch".to_string()));
    }
    let signature_algorithm = AlgorithmIdentifier {
        oid: ID_ALG_MTCPROOF,
        parameters: None,
    };

    let tbs_certificate = TbsCertificate {
        version: entry.version,
        serial_number: SerialNumber::new(&leaf_index.to_be_bytes())?,
        signature: signature_algorithm.clone(),
        issuer: entry.issuer,
        validity: entry.validity,
        subject: entry.subject,
        subject_public_key_info: spki,
        issuer_unique_id: entry.issuer_unique_id,
        subject_unique_id: entry.subject_unique_id,
        extensions: entry.extensions,
    };
    let certificate = Certificate {
        tbs_certificate,
        signature_algorithm,
        signature: BitString::from_bytes(
            &MtcProof {
                start: subtree.lo(),
                end: subtree.hi(),
                inclusion_proof,
                signatures: Vec::new(),
            }
            .to_bytes(),
        )?,
    };
    Ok(certificate.to_der()?)
}

#[derive(Debug, Error)]
pub enum MtcError {
    #[error(transparent)]
    Tlog(#[from] TlogError),
    #[error(transparent)]
    Der(#[from] der::Error),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    Validation(#[from] x509_util::ValidationError),
    #[error(transparent)]
    Fmt(#[from] std::fmt::Error),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    ParseInt(#[from] ParseIntError),
    #[error("mtc: {0}")]
    Dynamic(String),
}

#[repr(u16)]
pub enum MerkleTreeCertEntryType {
    NullEntry = 0x0000,
    TbsCertEntry = 0x0001,
}

impl TryFrom<u16> for MerkleTreeCertEntryType {
    type Error = MtcError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(MerkleTreeCertEntryType::NullEntry),
            0x0001 => Ok(MerkleTreeCertEntryType::TbsCertEntry),
            _ => Err(MtcError::Dynamic("unknown entry type".into())),
        }
    }
}

/// A `MerkleTreeCertEntry` as defined in
/// <https://www.ietf.org/archive/id/draft-davidben-tls-merkle-tree-certs-05.html#name-log-entries>.
/// The `NullEntry` type is used as the first element in the tree so that the
/// serial number for each subsequent `TbsCertEntry` in the tree corresponds to
/// its index in the tree.
#[allow(clippy::large_enum_variant)]
#[derive(PartialEq, Debug)]
pub enum MerkleTreeCertEntry {
    NullEntry,
    TbsCertEntry(TbsCertificateLogEntry),
}

impl MerkleTreeCertEntry {
    /// Encode entry to bytes.
    ///
    /// # Errors
    ///
    /// Will return an error if there are issues encoding the entry.
    pub fn encode(&self) -> Result<Vec<u8>, MtcError> {
        match &self {
            Self::NullEntry => Ok((MerkleTreeCertEntryType::NullEntry as u16)
                .to_be_bytes()
                .to_vec()),
            Self::TbsCertEntry(tbs_cert_entry) => Ok([
                (MerkleTreeCertEntryType::TbsCertEntry as u16)
                    .to_be_bytes()
                    .to_vec(),
                tbs_cert_entry.to_der()?,
            ]
            .concat()),
        }
    }

    /// Decode entry from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry cannot be decoded.
    pub fn decode(mut data: &[u8]) -> Result<Self, MtcError> {
        match MerkleTreeCertEntryType::try_from(data.read_u16::<BigEndian>()?)? {
            MerkleTreeCertEntryType::NullEntry => {
                if data.is_empty() {
                    Ok(Self::NullEntry)
                } else {
                    Err(MtcError::Dynamic(
                        "data for null entry must be empty".into(),
                    ))
                }
            }
            MerkleTreeCertEntryType::TbsCertEntry => {
                let tbs_cert_entry = TbsCertificateLogEntry::from_der(data)?;
                Ok(Self::TbsCertEntry(tbs_cert_entry))
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct TbsCertificateLogEntry {
    /// The certificate version
    ///
    /// Note that this value defaults to Version 1 per the RFC. However,
    /// fields such as `issuer_unique_id`, `subject_unique_id` and `extensions`
    /// require later versions. Care should be taken in order to ensure
    /// standards compliance.
    #[asn1(context_specific = "0", default = "Default::default")]
    pub version: Version,
    pub issuer: Name,
    pub validity: Validity,
    pub subject: Name,
    pub subject_public_key_info_hash: OctetString,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub issuer_unique_id: Option<BitString>,
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub subject_unique_id: Option<BitString>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub extensions: Option<Extensions>,
}

// Validate and filter extended key usage extension.
fn filter_ext_key_usage(extension: &mut Extension) -> Result<(), MtcError> {
    let mut eku = ExtendedKeyUsage::from_der(extension.extn_value.as_bytes())?;
    // Require ip-kp-serverAuth, filter id-kp-clientAuth, and disallow everything else.
    // <https://cabforum.org/working-groups/server/baseline-requirements/requirements/#712710-subscriber-certificate-extended-key-usage>
    let mut is_err = false;
    eku.0.retain(|usage| match *usage {
        rfc5280::ID_KP_SERVER_AUTH => true,
        rfc5280::ID_KP_CLIENT_AUTH => false,
        _ => {
            is_err = true;
            false
        }
    });
    if is_err {
        return Err(MtcError::Dynamic("unexpected key usage".into()));
    }
    if eku.0.is_empty() {
        return Err(MtcError::Dynamic(
            "key usage missing id-kp-serverAuth".into(),
        ));
    }
    extension.extn_value = OctetString::new(eku.to_der()?)?;
    Ok(())
}

// Validate and filter key usage extension.
fn filter_key_usage(extension: &mut Extension) -> Result<(), MtcError> {
    let mut ku = KeyUsage::from_der(extension.extn_value.as_bytes())?;
    // Require digital_signature, allow key_encipherment, and filter everything else.
    ku.0 &= KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment;
    if !ku.0.contains(KeyUsages::DigitalSignature) {
        return Err(MtcError::Dynamic(
            "key usage missing DigitalSignature".into(),
        ));
    }
    extension.extn_value = OctetString::new(ku.to_der()?)?;
    Ok(())
}

// Validate and filter extensions.
//
// # Errors
//
// Will return an error if there are any duplicate extensions, or if there are
// any critical extensions that cannot be filtered out.
fn filter_extensions(extensions: &mut Vec<Extension>) -> Result<(), MtcError> {
    let mut result = Ok(());
    let mut oids = BTreeSet::new();
    extensions.retain_mut(|extension| {
        if oids.contains(&extension.extn_id) {
            result = Err(MtcError::Dynamic("duplicate extension".into()));
            return false;
        }
        oids.insert(extension.extn_id);

        match extension.extn_id {
            rfc5280::ID_CE_EXT_KEY_USAGE => {
                if let Err(e) = filter_ext_key_usage(extension) {
                    result = Err(e);
                }
                true
            }
            rfc5280::ID_CE_SUBJECT_ALT_NAME => true,
            rfc5280::ID_CE_KEY_USAGE => {
                if let Err(e) = filter_key_usage(extension) {
                    result = Err(e);
                }
                true
            }
            rfc5280::ID_PE_AUTHORITY_INFO_ACCESS
            | rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER
            | rfc5280::ID_CE_CRL_DISTRIBUTION_POINTS
            | rfc5280::ID_CE_CERTIFICATE_POLICIES
            | rfc5280::ID_CE_BASIC_CONSTRAINTS => false,
            id => {
                if extension.critical {
                    result = Err(MtcError::Dynamic(format!(
                        "unsupported critical extension {id}"
                    )));
                }
                false
            }
        }
    });
    result
}

/// Convert a `TbsCertificate` to a `TbsCertificateLogEntry` with the provided
/// issuer and validity.
///
/// # Errors
///
/// Errors if the bootstrap certificate contains unsupported fields or
/// extensions.
pub fn tbs_cert_to_log_entry(
    bootstrap: TbsCertificate,
    issuer: RdnSequence,
    validity: Validity,
) -> Result<TbsCertificateLogEntry, MtcError> {
    if bootstrap.version != Version::V3 {
        return Err(MtcError::Dynamic("bootstrap version must be v3".into()));
    }
    if validity
        .not_before
        .to_unix_duration()
        .lt(&bootstrap.validity.not_before.to_unix_duration())
    {
        return Err(MtcError::Dynamic(
            "entry not_before must not be less than bootstrap not_before".into(),
        ));
    }
    if validity
        .not_after
        .to_unix_duration()
        .gt(&bootstrap.validity.not_after.to_unix_duration())
    {
        return Err(MtcError::Dynamic(
            "entry not_after must not be greater than bootstrap not_after".into(),
        ));
    }

    let extensions = if let Some(mut bootstrap_extensions) = bootstrap.extensions {
        filter_extensions(&mut bootstrap_extensions)?;
        Some(bootstrap_extensions)
    } else {
        None
    };

    Ok(TbsCertificateLogEntry {
        version: bootstrap.version,
        issuer,
        validity,
        subject: bootstrap.subject,
        subject_public_key_info_hash: OctetString::new(
            Sha256::digest(bootstrap.subject_public_key_info.to_der()?).as_slice(),
        )?,
        issuer_unique_id: bootstrap.issuer_unique_id,
        subject_unique_id: bootstrap.subject_unique_id,
        extensions,
    })
}

/// Check that a bootstrap certificate covers a log entry.
///
/// # Errors
///
/// Returns an error if either certificate is invalid, or if the bootstrap
/// certificate doesn't cover the log entry.
#[allow(clippy::too_many_lines)]
pub fn validate_correspondence(
    log_entry: &TbsCertificateLogEntry,
    raw_chain: &[Vec<u8>],
    roots: &CertPool,
) -> Result<(), MtcError> {
    // We will run ordinary chain validation on the given chain. After, we will do additional
    // validation, expressed in the below closure.
    let validator_hook = |leaf: Certificate,
                          chain_certs: Vec<&Certificate>,
                          _chain_fingerprints: Vec<[u8; 32]>,
                          _found_root_idx: Option<usize>|
     -> Result<(), MtcError> {
        let bootstrap = leaf.tbs_certificate.clone();

        if !(log_entry.version == bootstrap.version && log_entry.version == Version::V3) {
            return Err(MtcError::Dynamic(
                "entry and bootstrap versions must be v3".into(),
            ));
        }
        // Make sure the validity is contained within the validity of every cert in
        // the chain.
        for cert in core::iter::once(&leaf).chain(chain_certs) {
            if log_entry.validity.not_before.to_unix_duration().lt(&cert
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration())
            {
                return Err(MtcError::Dynamic(
                    "entry not_before must not be less than bootstrap chain cert not_before".into(),
                ));
            }
            if log_entry.validity.not_after.to_unix_duration().gt(&cert
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration())
            {
                return Err(MtcError::Dynamic(
                    "entry not_after must not be greater than bootstrap chain cert not_after"
                        .into(),
                ));
            }
        }
        if log_entry.subject != bootstrap.subject {
            return Err(MtcError::Dynamic(
                "entry subject must match bootstrap subject".into(),
            ));
        }
        if log_entry.subject_public_key_info_hash
            != OctetString::new(
                Sha256::digest(bootstrap.subject_public_key_info.to_der()?).as_slice(),
            )?
        {
            return Err(MtcError::Dynamic(
                "entry spki hash must match hash of bootstrap spki".into(),
            ));
        }
        if log_entry.issuer_unique_id != bootstrap.issuer_unique_id {
            return Err(MtcError::Dynamic(
                "entry issuer unique ID must match bootstrap issuer unique ID".into(),
            ));
        }
        if log_entry.subject_unique_id != bootstrap.subject_unique_id {
            return Err(MtcError::Dynamic(
                "entry subject unique ID must match bootstrap subject unique ID".into(),
            ));
        }

        let (log_entry_extensions, mut bootstrap_extensions) =
            match (&log_entry.extensions, bootstrap.extensions) {
                // If no extensions in either entry or bootstrap, we're done.
                (None, None) => return Ok(()),
                // If mismatched, that's an error.
                (Some(_), None) | (None, Some(_)) => {
                    return Err(MtcError::Dynamic("mismatched extensions".into()))
                }
                // Otherwise both the log entry and bootstrap cert have
                // extensions. Check them below.
                (Some(log_ext), Some(boot_ext)) => (log_ext, boot_ext),
            };

        // Check and filter bootstrap extensions.
        filter_extensions(&mut bootstrap_extensions)?;

        // Make sure the filtered bootstrap extensions cover those of the log entry.
        if log_entry_extensions.len() != bootstrap_extensions.len() {
            return Err(MtcError::Dynamic(
                "bootstrap extension lengths differ".into(),
            ));
        }

        let bootstrap_extensions_map = bootstrap_extensions
            .into_iter()
            .map(|extn| (extn.extn_id, extn))
            .collect::<HashMap<_, _>>();
        for extension in log_entry_extensions {
            match extension.extn_id {
                id @ (rfc5280::ID_CE_EXT_KEY_USAGE
                | rfc5280::ID_CE_SUBJECT_ALT_NAME
                | rfc5280::ID_CE_KEY_USAGE) => {
                    if let Some(bootstrap_extension) = bootstrap_extensions_map.get(&id) {
                        // This currently checks for strict equality, but
                        // could be relaxed somewhat, for example to allow a
                        // bootstrap cert with the key usage
                        // DigitalSignature+KeyEncipherment to cover a log
                        // entry with only the DigitalSignature key usage.
                        if extension != bootstrap_extension {
                            return Err(MtcError::Dynamic(format!(
                                "boostrap extension mismatch {id}"
                            )));
                        }
                    } else {
                        return Err(MtcError::Dynamic(format!(
                            "bootstrap missing extension {id}"
                        )));
                    }
                }
                id => {
                    return Err(MtcError::Dynamic(format!(
                        "log entry has unsupported extension {id}"
                    )))
                }
            }
        }
        Ok(())
    };

    // Run the validation logic with the above validation hook. We do
    // not give `validate_chain_lax` a window for the `not_after` validity,
    // since validity is checked within the validator hook.
    validate_chain_lax(
        raw_chain,
        roots,
        &ValidationOptions {
            stop_on_first_trusted_cert: true,
            not_after_start: None,
            not_after_end: None,
        },
        validator_hook,
    )
    .map_err(|e| match e {
        x509_util::HookOrValidationError::Validation(ve) => ve.into(),
        x509_util::HookOrValidationError::Hook(he) => he,
    })
}

/// Parse and validate a bootstrap chain, returning a pending log entry.
///
/// # Arguments
///
/// * `raw_chain` - The 'bootstrap' chain of certificates submitted to the
///   `add-entry` endpoint. Each entry must sign the previous entry, and the
///   chain must start with a leaf certificate and end with a certificate that
///   is a trusted root or is signed by a trusted root.
/// * `roots` - A certificate pool containing the trusted roots.
/// * `issuer` - The issuer name of the Merkle Tree CA, to replace the issuer in
///   the bootstrap certificate.
/// * `validity` - A bound on the maximum validity period for the returned
///   Merkle Tree log entry, based on the Merkle Tree CA's parameters. This
///   bound is further adjusted to ensure that it is covered by the bootstrap
///   chain.
///
/// # Returns
///
/// Returns a pending Merkle Tree log entry derived from the bootstrap chain and
/// other provided parameters and the inferred root, if a root had to be
/// inferred.
///
/// # Errors
///
/// Returns an error if the chain is invalid.
pub fn validate_chain(
    raw_chain: &[Vec<u8>],
    roots: &CertPool,
    issuer: RdnSequence,
    validity: &mut Validity,
) -> Result<(BootstrapMtcPendingLogEntry, Option<usize>), MtcError> {
    // We will run the ordinary chain validation on our input, but we have some post-processing we
    // need to do too. Namely we need to adjust the validity period of the provided bootstrap cert,
    // and then construct a pending log entry. We do this in the validation hook.
    let validator_hook = |leaf: Certificate,
                          chain_certs: Vec<&Certificate>,
                          chain_fingerprints: Vec<[u8; 32]>,
                          found_root_idx: Option<usize>| {
        // Adjust the validity bound to the overlapping part of validity periods of
        // all certificates in the chain.
        for cert in std::iter::once(&leaf).chain(chain_certs) {
            if validity.not_before.to_unix_duration().lt(&cert
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration())
            {
                validity.not_before = cert.tbs_certificate.validity.not_before;
            }
            if validity.not_after.to_unix_duration().gt(&cert
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration())
            {
                validity.not_after = cert.tbs_certificate.validity.not_after;
            }
            // Check that we still have a non-empty validity period.
            if validity
                .not_after
                .to_unix_duration()
                .le(&validity.not_before.to_unix_duration())
            {
                // There is no remaining validity period.
                return Err(MtcError::Dynamic(
                    "overlap in validity with bootstrap chain must not be empty".into(),
                ));
            }
        }

        let mut bootstrap = Vec::new();
        // SAFETY: `validate_chain_lax` checks that `raw_chain` is non-empty. We
        // use `raw_chain[0]` here instead of `leaf` to avoid having to
        // re-encode it to DER format.
        bootstrap.write_length_prefixed(&raw_chain[0], 3)?;
        bootstrap.write_length_prefixed(&chain_fingerprints.concat(), 2)?;

        let mut bootstrap_tile_entry = Vec::new();
        bootstrap_tile_entry.write_length_prefixed(bootstrap.as_slice(), 3)?;

        let pending_entry = BootstrapMtcPendingLogEntry {
            bootstrap: bootstrap_tile_entry,
            entry: TlogTilesPendingLogEntry {
                data: MerkleTreeCertEntry::TbsCertEntry(tbs_cert_to_log_entry(
                    leaf.tbs_certificate,
                    issuer,
                    *validity,
                )?)
                .encode()?,
            },
        };
        Ok((pending_entry, found_root_idx))
    };

    // Run the validation and return the hook-constructed pending entry. We do
    // not give `validate_chain_lax` a window for the `not_after` validity,
    // since validity is checked within the validator hook.
    let pending_entry = validate_chain_lax(
        raw_chain,
        roots,
        &ValidationOptions {
            stop_on_first_trusted_cert: true,
            not_after_start: None,
            not_after_end: None,
        },
        validator_hook,
    );
    pending_entry.map_err(|e| match e {
        x509_util::HookOrValidationError::Validation(ve) => ve.into(),
        x509_util::HookOrValidationError::Hook(he) => he,
    })
}

#[cfg(test)]
mod tests {
    use der::asn1::UtcTime;
    use std::time::Duration;
    use x509_cert::{time::Time, Certificate};
    use x509_util::{build_chain, certs_to_bytes};

    use super::*;

    #[test]
    fn test_tbs_cert_to_log_entry() {
        let bootstrap_chain = build_chain!(
            "../../static_ct_api/tests/leaf-cert.pem",
            "../../static_ct_api/tests/fake-intermediate-with-name-constraints-cert.pem"
        );
        let raw_chain = certs_to_bytes(&bootstrap_chain).unwrap();

        let roots = CertPool::new(build_chain!(
            "../../static_ct_api/tests/fake-ca-cert.pem",
            "../../static_ct_api/tests/fake-root-ca-cert.pem",
            "../../static_ct_api/tests/ca-cert.pem",
            "../../static_ct_api/tests/real-precert-intermediate.pem"
        ))
        .unwrap();

        let validity = Validity {
            not_before: Time::UtcTime(
                UtcTime::from_unix_duration(Duration::from_secs(1_518_521_919)).unwrap(),
            ),
            not_after: Time::UtcTime(
                UtcTime::from_unix_duration(Duration::from_secs(1_743_161_919)).unwrap(),
            ),
        };

        let mut log_entry = {
            let bootstrap = &bootstrap_chain[0].tbs_certificate;
            let issuer = RdnSequence::default();
            tbs_cert_to_log_entry(bootstrap.clone(), issuer, validity).unwrap()
        };

        // Valid.
        validate_correspondence(&log_entry, &raw_chain, &roots).unwrap();

        // Put the extensions in a different order.
        log_entry
            .extensions
            .as_mut()
            .unwrap_or(&mut Vec::new())
            .sort_by(|a, b| b.extn_id.cmp(&a.extn_id));

        // Still valid.
        validate_correspondence(&log_entry, &raw_chain, &roots).unwrap();

        // Remove an extension.
        let ext = log_entry
            .extensions
            .as_mut()
            .unwrap_or(&mut Vec::new())
            .pop()
            .unwrap();

        // No longer valid.
        validate_correspondence(&log_entry, &raw_chain, &roots).unwrap_err();

        // Put it back.
        log_entry
            .extensions
            .as_mut()
            .unwrap_or(&mut Vec::new())
            .push(ext);

        // Valid again.
        validate_correspondence(&log_entry, &raw_chain, &roots).unwrap();

        // Increase the validity to outside the bootstrap's validity.
        log_entry.validity.not_after =
            Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(1_743_161_920)).unwrap());

        // No longer valid.
        validate_correspondence(&log_entry, &raw_chain, &roots).unwrap_err();
    }

    #[test]
    fn test_encode() {
        let certs =
            Certificate::load_pem_chain(include_bytes!("../../static_ct_api/tests/leaf-cert.pem"))
                .unwrap();
        let bootstrap = &certs[0].tbs_certificate;
        let issuer = RdnSequence::default();

        let validity = Validity {
            not_before: Time::UtcTime(
                UtcTime::from_unix_duration(Duration::from_secs(1_518_521_919)).unwrap(),
            ),
            not_after: Time::UtcTime(
                UtcTime::from_unix_duration(Duration::from_secs(1_743_161_919)).unwrap(),
            ),
        };

        let log_entry = tbs_cert_to_log_entry(bootstrap.clone(), issuer, validity).unwrap();
        let decoded = TbsCertificateLogEntry::from_der(&log_entry.to_der().unwrap()).unwrap();

        assert_eq!(log_entry, decoded);

        let merkle_tree_cert_entry = MerkleTreeCertEntry::TbsCertEntry(log_entry);
        let decoded =
            MerkleTreeCertEntry::decode(&merkle_tree_cert_entry.encode().unwrap()).unwrap();

        assert_eq!(merkle_tree_cert_entry, decoded);

        let null_entry = MerkleTreeCertEntry::NullEntry;
        assert_eq!(
            null_entry,
            MerkleTreeCertEntry::decode(&null_entry.encode().unwrap()).unwrap()
        );
    }
}
