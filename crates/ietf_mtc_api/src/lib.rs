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
    oid::{db::rfc5280::ID_CE_SUBJECT_ALT_NAME, ObjectIdentifier},
    Any, Decode, Encode, Reader,
};
use length_prefixed::WriteLengthPrefixedBytesExt;
use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as,
};
use sha2::{Digest, Sha256};
use std::{io::Read, num::ParseIntError};
use thiserror::Error;
use tlog_tiles::{
    Hash, LeafIndex, LogEntry, PathElem, PendingLogEntry, Proof, Subtree, TlogError,
    TlogTilesLogEntry, TlogTilesPendingLogEntry, UnixTimestamp,
};
use x509_cert::{
    certificate::Version,
    ext::{Extension, Extensions},
    name::{Name, RdnSequence},
    request::CertReq,
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned, SubjectPublicKeyInfo},
    time::Validity,
};

/// OID for Trust Anchor IDs, as specified in draft-ietf-plants-merkle-tree-certs-02.
///
/// The experimental value `1.3.6.1.4.1.44363.47.1` (Cloudflare's private OID arc)
/// is used until the IANA assignment from the draft is finalized.
pub const ID_RDNA_TRUSTANCHOR_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.44363.47.1");

/// OID for the MTC proof algorithm, used in the `signature_algorithm` field of
/// landmark certificates, as specified in draft-ietf-plants-merkle-tree-certs-02.
///
/// The experimental value `1.3.6.1.4.1.44363.47.0` is used until the IANA
/// assignment from the draft is finalized.
pub const ID_ALG_MTCPROOF: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.44363.47.0");

/// The draft version of the IETF MTC spec that this crate implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DraftVersion {
    #[default]
    Draft02,
}

/// Sequence metadata for IETF MTC log entries.
///
/// Extends the standard `(LeafIndex, UnixTimestamp)` with the previous and new
/// tree sizes, allowing the frontend to compute the exact subtree signature key
/// for a newly sequenced entry via `Subtree::split_interval(old, new)` without
/// enumerating candidates.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct IetfSequenceMetadata {
    /// The index of the sequenced entry in the Merkle tree.
    pub leaf_index: LeafIndex,
    /// The sequencing timestamp in milliseconds since Unix epoch.
    pub timestamp: UnixTimestamp,
    /// The tree size immediately before this batch was sequenced.
    pub old_tree_size: u64,
    /// The tree size immediately after this batch was sequenced.
    pub new_tree_size: u64,
}

// IetfMtcWorker is a new deployment with no existing DO storage, so serde_json
// serialization for the dedup cache ring buffer is fine.
generic_log_worker::impl_json_cache_serialize!(IetfSequenceMetadata);

// MTCSignature from draft-ietf-plants-merkle-tree-certs §6.1.
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

// MTCProof from draft-ietf-plants-merkle-tree-certs §6.1.
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

/// Add-entry request for the IETF MTC submission API.
///
/// The payload is a PKCS#10 Certificate Signing Request (CSR) in DER format,
/// base64url-encoded (no padding), matching the ACME `finalize` endpoint
/// format (RFC 8555 §7.4).  The server extracts the subject, SPKI, and SANs
/// from the CSR; the CSR signature is not verified (authentication is handled
/// at the transport layer).
///
/// The validity window is set server-side: `[now, now + max_certificate_lifetime_secs]`.
/// ACME order `notBefore`/`notAfter` fields are not currently supported.
#[serde_as]
#[derive(Deserialize, Debug)]
pub struct AddEntryRequest {
    /// Base64url-encoded (no padding) DER-encoded PKCS#10 CSR.
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub csr: Vec<u8>,
}

/// Add-entry response.
///
/// The DER-encoded standalone MTC certificate (§6.2) encodes all relevant
/// fields: the entry index is the certificate serial number, validity is in
/// the `TBSCertificate`, and the inclusion proof and cosignature are in the
/// `signatureValue`.
#[serde_as]
#[derive(Serialize)]
pub struct AddEntryResponse {
    /// DER-encoded standalone MTC certificate (§6.2), base64-encoded.
    #[serde_as(as = "Base64")]
    pub certificate: Vec<u8>,
}

/// A pending IETF MTC log entry.  Unlike the bootstrap variant, there is no
/// auxiliary tile — the entry is purely the `MerkleTreeCertEntry` data.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct IetfMtcPendingLogEntry {
    /// An encoded `MerkleTreeCertEntry` wrapped in a generic `TlogTilesPendingLogEntry`.
    pub entry: TlogTilesPendingLogEntry,
}

impl PendingLogEntry for IetfMtcPendingLogEntry {
    /// Uses the standard tlog-tiles data tile path.
    const DATA_TILE_PATH: PathElem = TlogTilesPendingLogEntry::DATA_TILE_PATH;

    /// No auxiliary tile.
    const AUX_TILE_PATH: Option<PathElem> = None;

    /// Unused in ietf-mtc-api.
    fn aux_entry(&self) -> &[u8] {
        unimplemented!()
    }

    fn lookup_key(&self) -> tlog_tiles::LookupKey {
        self.entry.lookup_key()
    }
}

/// A sequenced IETF MTC log entry.
#[derive(Debug, Clone, PartialEq)]
pub struct IetfMtcLogEntry(TlogTilesLogEntry);

impl LogEntry for IetfMtcLogEntry {
    const REQUIRE_CHECKPOINT_TIMESTAMP: bool = false;
    type Pending = IetfMtcPendingLogEntry;
    type ParseError = MtcError;
    type Metadata = IetfSequenceMetadata;

    fn make_metadata(
        leaf_index: LeafIndex,
        timestamp: UnixTimestamp,
        old_tree_size: u64,
        new_tree_size: u64,
    ) -> Self::Metadata {
        IetfSequenceMetadata {
            leaf_index,
            timestamp,
            old_tree_size,
            new_tree_size,
        }
    }

    fn initial_entry() -> Option<Self::Pending> {
        Some(Self::Pending {
            entry: TlogTilesPendingLogEntry {
                data: MerkleTreeCertEntry::NullEntry.encode().unwrap(),
            },
        })
    }

    fn new(pending: Self::Pending, metadata: Self::Metadata) -> Self {
        // Convert IetfSequenceMetadata to SequenceMetadata for TlogTilesLogEntry
        // (which only uses leaf_index and timestamp internally).
        Self(TlogTilesLogEntry::new(
            pending.entry,
            (metadata.leaf_index, metadata.timestamp),
        ))
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

/// Construct an `IetfMtcPendingLogEntry` from an `AddEntryRequest`.
///
/// Parses the DER-encoded PKCS#10 CSR in `req.csr`, extracting the subject,
/// `SubjectPublicKeyInfo`, and any `subjectAltName` extension request
/// attribute.  The CSR signature is not verified.
///
/// # Errors
///
/// Returns an error if the CSR cannot be parsed, contains unsupported fields,
/// or the resulting entry cannot be encoded.
pub fn build_pending_entry(
    req: &AddEntryRequest,
    issuer: &RdnSequence,
    validity: Validity,
) -> Result<IetfMtcPendingLogEntry, MtcError> {
    let csr =
        CertReq::from_der(&req.csr).map_err(|e| MtcError::Dynamic(format!("invalid CSR: {e}")))?;

    let subject = csr.info.subject;
    let spki_der = csr.info.public_key.to_der()?;
    let spki_hash = OctetString::new(&Sha256::digest(&spki_der)[..])?;

    // Extract the AlgorithmIdentifier from the SPKI (new field in plants-02).
    let spki_algorithm = csr.info.public_key.algorithm;

    // Extract SubjectAltName from the CSR's extensionRequest attribute (RFC 2985 §5.4.2).
    let extensions = extract_san_from_csr(&csr.info.attributes)?;

    // Convert RdnSequence → Name via DER round-trip (Name is a newtype over RdnSequence
    // in x509-cert 0.3; its inner field is pub(crate) so direct construction isn't possible).
    let issuer = Name::from_der(&issuer.to_der()?)?;

    let log_entry = TbsCertificateLogEntry {
        version: Version::V3,
        issuer,
        validity,
        subject,
        subject_public_key_info_algorithm: spki_algorithm,
        subject_public_key_info_hash: spki_hash,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions,
    };

    Ok(IetfMtcPendingLogEntry {
        entry: TlogTilesPendingLogEntry {
            data: MerkleTreeCertEntry::TbsCertEntry(log_entry).encode()?,
        },
    })
}

/// Extract a `SubjectAltName` extension from a CSR's `extensionRequest` attribute.
///
/// Returns `None` if no `extensionRequest` attribute is present or if it
/// contains no `subjectAltName` extension.  Returns an error if the attribute
/// is malformed.
fn extract_san_from_csr(
    attributes: &x509_cert::attr::Attributes,
) -> Result<Option<Extensions>, MtcError> {
    // OID for the PKCS#9 extensionRequest attribute (RFC 2985 §5.4.2 / RFC 5912).
    const ID_EXTENSION_REQ: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14");

    for attr in attributes.iter() {
        if attr.oid != ID_EXTENSION_REQ {
            continue;
        }
        // The extensionRequest attribute value is a SET containing a single
        // SEQUENCE OF Extension (i.e. the Extensions type).
        for val in attr.values.iter() {
            let exts = Extensions::from_der(&val.to_der()?)?;
            let san_exts: Vec<Extension> = exts
                .into_iter()
                .filter(|e| e.extn_id == ID_CE_SUBJECT_ALT_NAME)
                .collect();
            if !san_exts.is_empty() {
                return Ok(Some(Extensions::from(san_exts)));
            }
        }
    }
    Ok(None)
}

/// R2 key prefix for cached subtree signatures.
///
/// Each key has the form `{SUBTREE_SIG_KEY_PREFIX}/{lo}-{hi}` where `lo` and
/// `hi` are the zero-padded decimal endpoints of the signed subtree interval.
/// Zero-padding ensures lexicographic ordering matches numeric ordering.
pub const SUBTREE_SIG_KEY_PREFIX: &str = "subtree-sig";

/// Format a subtree signature R2 key for the interval `[lo, hi)`.
#[must_use]
pub fn subtree_sig_key(lo: u64, hi: u64) -> String {
    format!("{SUBTREE_SIG_KEY_PREFIX}/{lo:020}-{hi:020}")
}

/// A subtree cosignature cached in R2 by the sequencer.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedSubtree {
    /// The start (inclusive) of the subtree interval.
    pub lo: u64,
    /// The end (exclusive) of the subtree interval.
    pub hi: u64,
    /// SHA-256 Merkle hash of the subtree root.
    #[serde_as(as = "Base64")]
    pub hash: [u8; 32],
    /// SHA-256 hash of the full checkpoint tree at the time of signing.
    /// Required to fetch the correct hash tiles when computing inclusion proofs.
    #[serde_as(as = "Base64")]
    pub checkpoint_hash: [u8; 32],
    /// Tree size of the full checkpoint at the time of signing.
    pub checkpoint_size: u64,
    /// Raw cosignature bytes from `MtcCosigner::sign_subtree`.
    #[serde_as(as = "Base64")]
    pub signature: Vec<u8>,
    /// `TrustAnchorID` of the cosigner that produced `signature`.
    pub cosigner_id: String,
}

impl SignedSubtree {
    /// Return the subtree interval as a `Subtree`.
    ///
    /// # Errors
    ///
    /// Returns an error if `(lo, hi)` is not a valid subtree interval.
    pub fn as_subtree(&self) -> Result<Subtree, MtcError> {
        Subtree::new(self.lo, self.hi).map_err(|e| MtcError::Dynamic(e.to_string()))
    }

    /// Return true if `leaf_index` falls within `[lo, hi)`.
    #[must_use]
    pub fn contains(&self, leaf_index: LeafIndex) -> bool {
        self.lo <= leaf_index && leaf_index < self.hi
    }
}

/// Build `TBSCertificate` DER field-by-field.
///
/// `x509-cert` 0.3 makes all `TbsCertificateInner` fields private, so we cannot
/// use struct-literal construction from external crates.
fn encode_tbs_certificate_der(
    entry: &TbsCertificateLogEntry,
    leaf_index: LeafIndex,
    signature_algorithm: &AlgorithmIdentifier<Any>,
    spki: &SubjectPublicKeyInfo<Any, BitString>,
) -> Result<Vec<u8>, MtcError> {
    use der::{
        asn1::{ContextSpecific, ContextSpecificRef},
        Encode, TagMode, TagNumber,
    };

    let mut tbs_content = Vec::new();
    if entry.version != x509_cert::certificate::Version::V1 {
        ContextSpecific {
            tag_number: TagNumber(0),
            tag_mode: TagMode::Explicit,
            value: entry.version,
        }
        .encode_to_vec(&mut tbs_content)?;
    }
    SerialNumber::<x509_cert::certificate::Rfc5280>::new(&leaf_index.to_be_bytes())?
        .encode_to_vec(&mut tbs_content)?;
    signature_algorithm.encode_to_vec(&mut tbs_content)?;
    entry.issuer.encode_to_vec(&mut tbs_content)?;
    entry.validity.encode_to_vec(&mut tbs_content)?;
    entry.subject.encode_to_vec(&mut tbs_content)?;
    spki.encode_to_vec(&mut tbs_content)?;
    if let Some(uid) = &entry.issuer_unique_id {
        ContextSpecificRef {
            tag_number: TagNumber(1),
            tag_mode: TagMode::Implicit,
            value: uid,
        }
        .encode_to_vec(&mut tbs_content)?;
    }
    if let Some(uid) = &entry.subject_unique_id {
        ContextSpecificRef {
            tag_number: TagNumber(2),
            tag_mode: TagMode::Implicit,
            value: uid,
        }
        .encode_to_vec(&mut tbs_content)?;
    }
    if let Some(exts) = &entry.extensions {
        let mut exts_items = Vec::new();
        for ext in exts {
            exts_items.extend(ext.to_der()?);
        }
        let mut exts_seq = Vec::new();
        der::Header::new(der::Tag::Sequence, der::Length::try_from(exts_items.len())?)
            .encode_to_vec(&mut exts_seq)?;
        exts_seq.extend(exts_items);
        let exts_any = der::asn1::Any::from_der(&exts_seq)?;
        ContextSpecific {
            tag_number: TagNumber(3),
            tag_mode: TagMode::Explicit,
            value: exts_any,
        }
        .encode_to_vec(&mut tbs_content)?;
    }
    let mut tbs_der = Vec::new();
    der::Header::new(
        der::Tag::Sequence,
        der::Length::try_from(tbs_content.len())?,
    )
    .encode_to_vec(&mut tbs_der)?;
    tbs_der.extend(tbs_content);
    Ok(tbs_der)
}

/// Serialize a DER-encoded MTC certificate (draft-ietf-plants-merkle-tree-certs §6.1).
///
/// Pass an empty `cosignatures` slice for a landmark-relative certificate (§6.3)
/// or a non-empty slice for a standalone certificate (§6.2).
///
/// # Errors
///
/// Returns an error if the SPKI hash does not match the entry, or if there
/// are any serialization errors.
pub fn serialize_mtc_cert(
    log_entry: &IetfMtcLogEntry,
    leaf_index: LeafIndex,
    spki_der: &[u8],
    subtree: &Subtree,
    inclusion_proof: Proof,
    cosignatures: &[(TrustAnchorID, Vec<u8>)],
) -> Result<Vec<u8>, MtcError> {
    let entry = match MerkleTreeCertEntry::decode(&log_entry.0.inner.data)? {
        MerkleTreeCertEntry::TbsCertEntry(entry) => entry,
        MerkleTreeCertEntry::NullEntry => {
            return Err(MtcError::Dynamic("no tbs cert entry for null entry".into()))
        }
    };
    let spki: SubjectPublicKeyInfo<Any, BitString> = SubjectPublicKeyInfo::from_der(spki_der)?;
    let spki_hash = OctetString::new(&Sha256::digest(spki_der)[..])?;
    if spki_hash != entry.subject_public_key_info_hash {
        return Err(MtcError::Dynamic("spki hash mismatch".to_string()));
    }

    let signature_algorithm: AlgorithmIdentifier<Any> = AlgorithmIdentifier {
        oid: ID_ALG_MTCPROOF,
        parameters: None,
    };
    let tbs_der = encode_tbs_certificate_der(&entry, leaf_index, &signature_algorithm, &spki)?;

    // Build Certificate DER: SEQUENCE { tbs_der, signature_algorithm, signature }.
    let signatures = cosignatures
        .iter()
        .map(|(cosigner_id, sig)| MtcSignature {
            cosigner_id: cosigner_id.clone(),
            signature: sig.clone(),
        })
        .collect();
    let sig_bytes = MtcProof {
        start: subtree.lo(),
        end: subtree.hi(),
        inclusion_proof,
        signatures,
    }
    .to_bytes();
    let sig_bitstring = BitString::from_bytes(&sig_bytes)?;
    let mut cert_content = Vec::new();
    cert_content.extend(&tbs_der);
    signature_algorithm.encode_to_vec(&mut cert_content)?;
    sig_bitstring.encode_to_vec(&mut cert_content)?;
    let mut cert_der = Vec::new();
    der::Header::new(
        der::Tag::Sequence,
        der::Length::try_from(cert_content.len())?,
    )
    .encode_to_vec(&mut cert_der)?;
    cert_der.extend(cert_content);
    Ok(cert_der)
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

/// A `MerkleTreeCertEntry` as defined in draft-ietf-plants-merkle-tree-certs §5.3.
///
/// The `NullEntry` type is used as the first element in the tree so that the
/// serial number for each subsequent `TbsCertEntry` corresponds to its index.
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
            Self::TbsCertEntry(tbs_cert_entry) => {
                // plants-02: fields are written directly after the u16 type tag,
                // without an outer ASN.1 SEQUENCE wrapper (dropped in davidben-10).
                let mut out = (MerkleTreeCertEntryType::TbsCertEntry as u16)
                    .to_be_bytes()
                    .to_vec();
                out.extend(tbs_cert_entry.encode_fields()?);
                Ok(out)
            }
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
                // plants-02: the remaining bytes are raw field DER (no SEQUENCE wrapper).
                let tbs_cert_entry = TbsCertificateLogEntry::decode_fields(data)?;
                Ok(Self::TbsCertEntry(tbs_cert_entry))
            }
        }
    }
}

/// A `TBSCertificateLogEntry` as defined in draft-ietf-plants-merkle-tree-certs §5.3
/// (plants-02).
///
/// Differs from a standard `TBSCertificate` in that `subject_public_key_info`
/// is replaced by two separate fields:
/// - `subject_public_key_info_algorithm`: the `AlgorithmIdentifier` from the SPKI
///   (new in plants-02; not present in davidben-09)
/// - `subject_public_key_info_hash`: SHA-256 of the full DER-encoded SPKI
///
/// Unlike in davidben-09, the entry is **not** wrapped in an ASN.1 SEQUENCE —
/// the fields are encoded as raw concatenated DER values (the SEQUENCE wrapper
/// was dropped in davidben-10).  For this reason we implement `Encode`/`Decode`
/// manually rather than using `#[derive(Sequence)]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TbsCertificateLogEntry {
    pub version: Version,
    pub issuer: Name,
    pub validity: Validity,
    pub subject: Name,
    /// The `AlgorithmIdentifier` from the submitted SPKI (new in plants-02).
    pub subject_public_key_info_algorithm: AlgorithmIdentifierOwned,
    /// SHA-256 of the full DER-encoded `SubjectPublicKeyInfo`.
    pub subject_public_key_info_hash: OctetString,
    pub issuer_unique_id: Option<BitString>,
    pub subject_unique_id: Option<BitString>,
    pub extensions: Option<Extensions>,
}

impl TbsCertificateLogEntry {
    /// Encode all fields as raw concatenated DER (no outer SEQUENCE wrapper).
    ///
    /// # Errors
    ///
    /// Returns a `der::Error` if any field cannot be encoded.
    pub fn encode_fields(&self) -> der::Result<Vec<u8>> {
        // Manually encode each field using der::Encode and collect into a Vec.
        // This is equivalent to the content bytes of a SEQUENCE, but without
        // the SEQUENCE tag and length prefix.
        let mut buf = Vec::new();

        // version [0] EXPLICIT INTEGER DEFAULT 0 — omit if V1 (default)
        if self.version != Version::V1 {
            use der::asn1::ContextSpecific;
            use der::TagMode;
            let tagged = ContextSpecific::<Version> {
                tag_number: der::TagNumber(0),
                tag_mode: TagMode::Explicit,
                value: self.version,
            };
            tagged.encode_to_vec(&mut buf)?;
        }

        self.issuer.encode_to_vec(&mut buf)?;
        self.validity.encode_to_vec(&mut buf)?;
        self.subject.encode_to_vec(&mut buf)?;
        self.subject_public_key_info_algorithm
            .encode_to_vec(&mut buf)?;
        self.subject_public_key_info_hash.encode_to_vec(&mut buf)?;

        // issuerUniqueID [1] IMPLICIT BIT STRING OPTIONAL
        if let Some(ref v) = self.issuer_unique_id {
            use der::asn1::ContextSpecificRef;
            use der::TagMode;
            ContextSpecificRef::<BitString> {
                tag_number: der::TagNumber(1),
                tag_mode: TagMode::Implicit,
                value: v,
            }
            .encode_to_vec(&mut buf)?;
        }

        // subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL
        if let Some(ref v) = self.subject_unique_id {
            use der::asn1::ContextSpecificRef;
            use der::TagMode;
            ContextSpecificRef::<BitString> {
                tag_number: der::TagNumber(2),
                tag_mode: TagMode::Implicit,
                value: v,
            }
            .encode_to_vec(&mut buf)?;
        }

        // extensions [3] EXPLICIT Extensions OPTIONAL
        if let Some(ref exts) = self.extensions {
            use der::asn1::ContextSpecific;
            use der::TagMode;
            let tagged = ContextSpecific::<Extensions> {
                tag_number: der::TagNumber(3),
                tag_mode: TagMode::Explicit,
                value: exts.clone(),
            };
            tagged.encode_to_vec(&mut buf)?;
        }

        Ok(buf)
    }

    /// Decode all fields from raw concatenated DER (no outer SEQUENCE wrapper).
    ///
    /// # Errors
    ///
    /// Returns a `MtcError` if the data is malformed.
    pub fn decode_fields(data: &[u8]) -> Result<Self, MtcError> {
        use der::{asn1::ContextSpecific, SliceReader, TagNumber};

        let mut reader = SliceReader::new(data)?;

        // version [0] EXPLICIT INTEGER DEFAULT V1
        let version = if der::Tag::peek(&reader).ok().is_some_and(|t| {
            t == der::Tag::ContextSpecific {
                constructed: true,
                number: TagNumber(0),
            }
        }) {
            let cs = ContextSpecific::<Version>::decode(&mut reader)?;
            cs.value
        } else {
            Version::V1
        };

        let issuer = Name::decode(&mut reader)?;
        let validity = Validity::decode(&mut reader)?;
        let subject = Name::decode(&mut reader)?;
        let subject_public_key_info_algorithm = AlgorithmIdentifierOwned::decode(&mut reader)?;
        let subject_public_key_info_hash = OctetString::decode(&mut reader)?;

        // issuerUniqueID [1] IMPLICIT BIT STRING OPTIONAL
        let issuer_unique_id =
            ContextSpecific::<BitString>::decode_implicit(&mut reader, TagNumber(1))?
                .map(|cs| cs.value);

        // subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL
        let subject_unique_id =
            ContextSpecific::<BitString>::decode_implicit(&mut reader, TagNumber(2))?
                .map(|cs| cs.value);

        // extensions [3] EXPLICIT Extensions OPTIONAL
        let extensions = if der::Tag::peek(&reader).ok().is_some_and(|t| {
            t == der::Tag::ContextSpecific {
                constructed: true,
                number: TagNumber(3),
            }
        }) {
            let cs = ContextSpecific::<Extensions>::decode(&mut reader)?;
            Some(cs.value)
        } else {
            None
        };

        reader.finish().map_err(MtcError::from)?;
        Ok(Self {
            version,
            issuer,
            validity,
            subject,
            subject_public_key_info_algorithm,
            subject_public_key_info_hash,
            issuer_unique_id,
            subject_unique_id,
            extensions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;
    use der::asn1::UtcTime;
    use std::time::Duration;
    use x509_cert::{
        ext::pkix::{name::GeneralName, SubjectAltName},
        time::Time,
    };

    fn dummy_validity() -> Validity {
        Validity::new(
            Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(1_700_000_000)).unwrap()),
            Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(1_700_086_400)).unwrap()),
        )
    }

    // Pre-built P-256 DER CSRs (base64url, no padding).
    // Subject: CN=test.example.com,O=Test,C=US
    // Generated with: openssl req -new -key <p256-key> -subj "..." [-addext "subjectAltName=..."]
    const CSR_NO_SAN_B64URL: &str =
        "MIHyMIGZAgEAMDcxGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20xDTALBgNVBAoM\
         BFRlc3QxCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs6dP\
         v4lKY7RVXxTGVLkj8lK3H1bgpSrAYXXg-b-aYb_KFMcYrbcW8ytv0hFnDXWVUTgo\
         Dyp4pbkBhgXieKD0MKAAMAoGCCqGSM49BAMCA0gAMEUCIQD9BWGDjR6Ul8jYQuyC\
         1Xw1Ydt0Z9TbFsDsS9d8NiHgigIgXDq9F4hRBvdwYvnRxP7jqW6ae_bamy1BOdzn\
         15F90uE";
    const CSR_WITH_SANS_B64URL: &str =
        "MIIBLDCB0wIBADA3MRkwFwYDVQQDDBB0ZXN0LmV4YW1wbGUuY29tMQ0wCwYDVQQK\
         DARUZXN0MQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLOn\
         T7-JSmO0VV8UxlS5I_JStx9W4KUqwGF14Pm_mmG_yhTHGK23FvMrb9IRZw11lVE4\
         KA8qeKW5AYYF4nig9DCgOjA4BgkqhkiG9w0BCQ4xKzApMCcGA1UdEQQgMB6CC2V4\
         YW1wbGUuY29tgg93d3cuZXhhbXBsZS5jb20wCgYIKoZIzj0EAwIDSAAwRQIgNoiV\
         IX6MeFGZgPSHjy0SY40txuhSOrGkat6KteN5v1oCIQCwKyv4B7cTXcCnligVQ-IY\
         6nyTYJJ0sDmRpgD03Ejqhg";

    fn decode_csr(b64url: &str) -> Vec<u8> {
        BASE64_URL_SAFE_NO_PAD
            .decode(b64url.replace(['\n', ' '], "").as_bytes())
            .unwrap()
    }

    #[test]
    fn test_encode_null_entry() {
        let null_entry = MerkleTreeCertEntry::NullEntry;
        assert_eq!(
            null_entry,
            MerkleTreeCertEntry::decode(&null_entry.encode().unwrap()).unwrap()
        );
    }

    #[test]
    fn test_build_pending_entry_with_sans() {
        let req = AddEntryRequest {
            csr: decode_csr(CSR_WITH_SANS_B64URL),
        };

        let entry = build_pending_entry(&req, &RdnSequence::default(), dummy_validity()).unwrap();
        let decoded = MerkleTreeCertEntry::decode(&entry.entry.data).unwrap();

        let MerkleTreeCertEntry::TbsCertEntry(tbs) = decoded else {
            panic!("expected TbsCertEntry");
        };

        let exts = tbs.extensions.unwrap();
        assert_eq!(exts.len(), 1);
        assert_eq!(exts[0].extn_id, ID_CE_SUBJECT_ALT_NAME);

        let san = SubjectAltName::from_der(exts[0].extn_value.as_bytes()).unwrap();
        assert_eq!(san.0.len(), 2);
        assert!(matches!(&san.0[0], GeneralName::DnsName(n) if n.as_str() == "example.com"));
        assert!(matches!(&san.0[1], GeneralName::DnsName(n) if n.as_str() == "www.example.com"));
    }

    #[test]
    fn test_build_pending_entry_no_sans() {
        let req = AddEntryRequest {
            csr: decode_csr(CSR_NO_SAN_B64URL),
        };

        let entry = build_pending_entry(&req, &RdnSequence::default(), dummy_validity()).unwrap();
        let decoded = MerkleTreeCertEntry::decode(&entry.entry.data).unwrap();
        let MerkleTreeCertEntry::TbsCertEntry(tbs) = decoded else {
            panic!("expected TbsCertEntry");
        };
        assert!(tbs.extensions.is_none());
    }

    #[test]
    fn test_build_pending_entry_invalid_csr() {
        let req = AddEntryRequest {
            csr: b"not a valid csr".to_vec(),
        };
        assert!(build_pending_entry(&req, &RdnSequence::default(), dummy_validity()).is_err());
    }

    #[test]
    fn test_add_entry_request_serde() {
        let csr_bytes = decode_csr(CSR_NO_SAN_B64URL);
        let b64url = BASE64_URL_SAFE_NO_PAD.encode(&csr_bytes);

        // Without optional fields.
        let json = format!(r#"{{"csr": "{b64url}"}}"#);
        let req: AddEntryRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.csr, csr_bytes);
        assert_eq!(req.csr, csr_bytes);
    }
}
