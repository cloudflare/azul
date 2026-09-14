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
    Any, Decode, Encode, Reader,
    asn1::{BitString, OctetString, Uint},
    oid::{ObjectIdentifier, db::rfc5280::ID_CE_SUBJECT_ALT_NAME},
};
use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as,
};
use sha2::{Digest, Sha256};
use std::{io::Read, num::ParseIntError};
use thiserror::Error;
use tlog_checkpoint::UnixTimestampMillis;
use tlog_core::{Hash, LeafIndex, Proof, Subtree, TlogError};
use tlog_entry::{
    LogEntry, LookupKey, PendingLogEntry, TlogTilesLogEntry, TlogTilesPendingLogEntry,
};
use tlog_tiles::PathElem;
use x509_cert::{
    certificate::Version,
    ext::{Extension, Extensions},
    name::{Name, RdnSequence},
    request::CertReq,
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned, SubjectPublicKeyInfo},
    time::Validity,
};

/// OID for Trust Anchor IDs, as specified in draft-ietf-plants-merkle-tree-certs-06.
///
/// The experimental value `1.3.6.1.4.1.44363.47.1` (Cloudflare's private OID arc)
/// is used until the IANA assignment from the draft is finalized.
pub const ID_RDNA_TRUSTANCHOR_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.44363.47.3");

/// OID for the MTC proof algorithm, used in the `signature_algorithm` field of
/// landmark certificates, as specified in draft-ietf-plants-merkle-tree-certs-06.
///
/// The experimental value `1.3.6.1.4.1.44363.47.0` is used until the IANA
/// assignment from the draft is finalized.
pub const ID_ALG_MTCPROOF: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.44363.47.0");

/// Experimental OID for the SHA-256 MTC CA certificate extension.
pub const ID_PE_MTC_CERTIFICATION_AUTHORITY_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.44363.47.4");

/// Contents of the critical MTC CA certificate extension.
#[derive(Clone, Debug, Eq, PartialEq, der::Sequence)]
pub struct MtcCertificationAuthority {
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub min_serial: Uint,
    pub max_serial: Uint,
}

impl MtcCertificationAuthority {
    /// Encode this representation as a critical X.509 extension.
    ///
    /// # Errors
    ///
    /// Returns an error if DER encoding fails.
    pub fn to_extension(&self) -> Result<Extension, MtcError> {
        Ok(Extension {
            extn_id: ID_PE_MTC_CERTIFICATION_AUTHORITY_SHA256,
            critical: true,
            extn_value: OctetString::new(self.to_der()?)?,
        })
    }
}

/// The draft version of the IETF MTC spec that this crate implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DraftVersion {
    #[default]
    Draft06,
}

pub const UINT48_MAX: u64 = (1_u64 << 48) - 1;
const UINT24_MAX: usize = (1_usize << 24) - 1;
const UINT16_MAX: usize = u16::MAX as usize;

fn write_length_prefixed(
    buffer: &mut Vec<u8>,
    data: &[u8],
    max_len: usize,
    prefix_len: usize,
    field: &str,
) -> Result<(), MtcError> {
    check_length(data.len(), max_len, field)?;
    buffer.write_uint::<BigEndian>(data.len() as u64, prefix_len)?;
    buffer.extend_from_slice(data);
    Ok(())
}

fn check_length(len: usize, max_len: usize, field: &str) -> Result<(), MtcError> {
    if len > max_len {
        return Err(MtcError::Dynamic(format!("{field} is too long")));
    }
    Ok(())
}

/// A tag-length-value extension on a Merkle Tree certificate entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleTreeCertEntryExtension {
    pub extension_type: u16,
    pub extension_data: Vec<u8>,
}

fn write_extensions(
    buffer: &mut Vec<u8>,
    extensions: &[MerkleTreeCertEntryExtension],
) -> Result<(), MtcError> {
    let mut encoded = Vec::new();
    let mut previous = None;
    for extension in extensions {
        if previous.is_some_and(|value| value >= extension.extension_type) {
            return Err(MtcError::Dynamic(
                "entry extensions must be ordered and unique".into(),
            ));
        }
        encoded.write_u16::<BigEndian>(extension.extension_type)?;
        write_length_prefixed(
            &mut encoded,
            &extension.extension_data,
            UINT16_MAX,
            2,
            "entry extension",
        )?;
        previous = Some(extension.extension_type);
    }
    write_length_prefixed(buffer, &encoded, UINT16_MAX, 2, "entry extensions")?;
    Ok(())
}

fn read_extensions(bytes: &mut &[u8]) -> Result<Vec<MerkleTreeCertEntryExtension>, MtcError> {
    let len = bytes.read_u16::<BigEndian>()? as usize;
    if bytes.len() < len {
        return Err(MtcError::Dynamic("truncated entry extensions".into()));
    }
    let (mut encoded, rest) = bytes.split_at(len);
    *bytes = rest;
    let mut extensions = Vec::new();
    let mut previous = None;
    while !encoded.is_empty() {
        let extension_type = encoded.read_u16::<BigEndian>()?;
        if previous.is_some_and(|value| value >= extension_type) {
            return Err(MtcError::Dynamic(
                "entry extensions must be ordered and unique".into(),
            ));
        }
        let data_len = encoded.read_u16::<BigEndian>()? as usize;
        if encoded.len() < data_len {
            return Err(MtcError::Dynamic("truncated entry extension".into()));
        }
        let (extension_data, rest) = encoded.split_at(data_len);
        encoded = rest;
        extensions.push(MerkleTreeCertEntryExtension {
            extension_type,
            extension_data: extension_data.to_vec(),
        });
        previous = Some(extension_type);
    }
    Ok(extensions)
}

fn write_u48(buffer: &mut Vec<u8>, value: u64) -> Result<(), MtcError> {
    if value > UINT48_MAX {
        return Err(MtcError::Dynamic("value exceeds uint48".into()));
    }
    buffer.extend_from_slice(&value.to_be_bytes()[2..]);
    Ok(())
}

// MTCSignature from draft-ietf-plants-merkle-tree-certs §6.1.
struct MtcSignature {
    cosigner_id: TrustAnchorID,
    signature: Vec<u8>,
}

impl MtcSignature {
    fn to_bytes(&self) -> Result<Vec<u8>, MtcError> {
        let mut buffer = Vec::new();
        write_length_prefixed(
            &mut buffer,
            self.cosigner_id.as_bytes(),
            u8::MAX as usize,
            1,
            "cosigner ID",
        )?;
        write_length_prefixed(&mut buffer, &self.signature, UINT16_MAX, 2, "signature")?;
        Ok(buffer)
    }
}

// MTCProof from draft-ietf-plants-merkle-tree-certs §6.1.
struct MtcProof {
    extensions: Vec<MerkleTreeCertEntryExtension>,
    start: u64,
    end: u64,
    inclusion_proof: Proof,
    signatures: Vec<MtcSignature>,
}

impl MtcProof {
    fn to_bytes(&self) -> Result<Vec<u8>, MtcError> {
        let mut buffer = Vec::new();
        write_extensions(&mut buffer, &self.extensions)?;
        write_u48(&mut buffer, self.start)?;
        write_u48(&mut buffer, self.end)?;
        write_length_prefixed(
            &mut buffer,
            &self
                .inclusion_proof
                .iter()
                .flat_map(|h| h.0.to_vec())
                .collect::<Vec<u8>>(),
            UINT16_MAX,
            2,
            "inclusion proof",
        )?;
        let signatures = self
            .signatures
            .iter()
            .map(MtcSignature::to_bytes)
            .collect::<Result<Vec<_>, _>>()?
            .concat();
        write_length_prefixed(&mut buffer, &signatures, UINT24_MAX, 3, "signatures")?;
        Ok(buffer)
    }
}

/// Add-entry request for the IETF MTC submission API.
///
/// The payload is a PKCS#10 Certificate Signing Request (CSR) in DER format,
/// base64url-encoded (no padding), matching the ACME `finalize` endpoint
/// format (RFC 8555 §7.4).  The server extracts the subject, SPKI, and SANs
/// from the CSR; the CSR signature is not verified.
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
    /// SHA-256 of the CSR, used to deduplicate issuance retries.
    pub lookup_key: LookupKey,
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

    fn lookup_key(&self) -> LookupKey {
        self.lookup_key
    }
}

/// A sequenced IETF MTC log entry.
#[derive(Debug, Clone, PartialEq)]
pub struct IetfMtcLogEntry(TlogTilesLogEntry);

impl LogEntry for IetfMtcLogEntry {
    const REQUIRE_CHECKPOINT_TIMESTAMP: bool = false;
    type Pending = IetfMtcPendingLogEntry;
    type ParseError = MtcError;

    fn initial_entry() -> Option<Self::Pending> {
        let entry = TlogTilesPendingLogEntry {
            data: MerkleTreeCertEntry::NullEntry {
                extensions: Vec::new(),
            }
            .encode()
            .unwrap(),
        };
        Some(Self::Pending {
            lookup_key: entry.lookup_key(),
            entry,
        })
    }

    fn new(pending: Self::Pending, leaf_index: LeafIndex, timestamp: UnixTimestampMillis) -> Self {
        Self(TlogTilesLogEntry::new(pending.entry, leaf_index, timestamp))
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

    // The log entry carries the SPKI algorithm separately from the SPKI hash.
    let spki_algorithm = csr.info.public_key.algorithm;

    // Extract SubjectAltName from the CSR's extensionRequest attribute (RFC 2985 §5.4.2).
    let extensions = extract_san_from_csr(&csr.info.attributes)?;

    // Convert RdnSequence → Name via DER round-trip (x509-cert 0.3).
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
            data: MerkleTreeCertEntry::TbsCertEntry {
                extensions: Vec::new(),
                tbs_certificate: log_entry,
            }
            .encode()?,
        },
        lookup_key: Sha256::digest(&req.csr).into(),
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
    log_number: u16,
    leaf_index: LeafIndex,
    spki_der: &[u8],
    subtree: &Subtree,
    inclusion_proof: Proof,
    cosignatures: &[(TrustAnchorID, Vec<u8>)],
) -> Result<Vec<u8>, MtcError> {
    if log_number == 0 || leaf_index >= UINT48_MAX {
        return Err(MtcError::Dynamic(
            "log number must be positive and index must be less than UINT48_MAX".into(),
        ));
    }
    if subtree.hi() > UINT48_MAX || !subtree.contains(leaf_index) {
        return Err(MtcError::Dynamic(
            "certificate subtree must fit uint48 and contain the entry".into(),
        ));
    }
    let (entry_extensions, entry) = match MerkleTreeCertEntry::decode(&log_entry.0.inner.data)? {
        MerkleTreeCertEntry::TbsCertEntry {
            extensions,
            tbs_certificate,
        } => (extensions, tbs_certificate),
        MerkleTreeCertEntry::NullEntry { .. } => {
            return Err(MtcError::Dynamic("no tbs cert entry for null entry".into()));
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

    let tbs_certificate = x509_util::OwnedTbsCertificate {
        version: entry.version,
        serial_number: SerialNumber::new(
            &((u64::from(log_number) << 48) | leaf_index).to_be_bytes(),
        )?,
        signature: signature_algorithm.clone(),
        issuer: entry.issuer,
        validity: entry.validity,
        subject: entry.subject,
        subject_public_key_info: spki,
        issuer_unique_id: entry.issuer_unique_id,
        subject_unique_id: entry.subject_unique_id,
        extensions: entry.extensions,
    };
    let mut cosignatures = cosignatures.to_vec();
    cosignatures.sort_by(|(a, _), (b, _)| {
        a.as_bytes()
            .len()
            .cmp(&b.as_bytes().len())
            .then_with(|| a.as_bytes().cmp(b.as_bytes()))
    });
    if cosignatures.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(MtcError::Dynamic("duplicate cosigner ID".into()));
    }
    let signatures = cosignatures
        .into_iter()
        .map(|(cosigner_id, sig)| MtcSignature {
            cosigner_id,
            signature: sig,
        })
        .collect();
    let certificate = x509_util::OwnedCertificate {
        tbs_certificate,
        signature_algorithm,
        signature: BitString::from_bytes(
            &MtcProof {
                extensions: entry_extensions,
                start: subtree.lo(),
                end: subtree.hi(),
                inclusion_proof,
                signatures,
            }
            .to_bytes()?,
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
    NullEntry {
        extensions: Vec<MerkleTreeCertEntryExtension>,
    },
    TbsCertEntry {
        extensions: Vec<MerkleTreeCertEntryExtension>,
        tbs_certificate: TbsCertificateLogEntry,
    },
}

impl MerkleTreeCertEntry {
    /// Encode entry to bytes.
    ///
    /// # Errors
    ///
    /// Will return an error if there are issues encoding the entry.
    pub fn encode(&self) -> Result<Vec<u8>, MtcError> {
        let mut encoded = Vec::new();
        match self {
            Self::NullEntry { extensions } => {
                write_extensions(&mut encoded, extensions)?;
                encoded.write_u16::<BigEndian>(MerkleTreeCertEntryType::NullEntry as u16)?;
            }
            Self::TbsCertEntry {
                extensions,
                tbs_certificate,
            } => {
                write_extensions(&mut encoded, extensions)?;
                encoded.write_u16::<BigEndian>(MerkleTreeCertEntryType::TbsCertEntry as u16)?;
                encoded.extend(tbs_certificate.encode_fields()?);
            }
        }
        if encoded.len() > UINT16_MAX {
            return Err(MtcError::Dynamic(
                "encoded MTC log entry exceeds 65535 bytes".into(),
            ));
        }
        Ok(encoded)
    }

    /// Decode entry from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry cannot be decoded.
    pub fn decode(mut data: &[u8]) -> Result<Self, MtcError> {
        if data.len() > UINT16_MAX {
            return Err(MtcError::Dynamic(
                "encoded MTC log entry exceeds 65535 bytes".into(),
            ));
        }
        let extensions = read_extensions(&mut data)?;
        match MerkleTreeCertEntryType::try_from(data.read_u16::<BigEndian>()?)? {
            MerkleTreeCertEntryType::NullEntry => {
                if data.is_empty() {
                    Ok(Self::NullEntry { extensions })
                } else {
                    Err(MtcError::Dynamic(
                        "data for null entry must be empty".into(),
                    ))
                }
            }
            MerkleTreeCertEntryType::TbsCertEntry => {
                // The remaining bytes are raw field DER without the SEQUENCE wrapper.
                let tbs_cert_entry = TbsCertificateLogEntry::decode_fields(data)?;
                Ok(Self::TbsCertEntry {
                    extensions,
                    tbs_certificate: tbs_cert_entry,
                })
            }
        }
    }
}

/// A `TBSCertificateLogEntry` as defined in draft-ietf-plants-merkle-tree-certs §5.3
/// (draft-06).
///
/// Differs from a standard `TBSCertificate` in that `subject_public_key_info`
/// is replaced by two separate fields:
/// - `subject_public_key_info_algorithm`: the `AlgorithmIdentifier` from the SPKI
///   (not present in davidben-09)
/// - `subject_public_key_info_hash`: SHA-256 of the full DER-encoded SPKI
///
/// Unlike in davidben-09, the entry is **not** wrapped in an ASN.1 SEQUENCE —
/// the fields are encoded as raw concatenated DER values (the SEQUENCE wrapper
/// was dropped in davidben-10).  For this reason we implement `Encode`/`Decode`
/// manually rather than using `#[derive(Sequence)]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TbsCertificateLogEntry {
    /// The certificate version
    ///
    /// Note that this value defaults to Version 1 per the RFC. However,
    /// fields such as `issuer_unique_id`, `subject_unique_id` and `extensions`
    /// require later versions. Care should be taken in order to ensure
    /// standards compliance.
    pub version: Version,
    pub issuer: Name,
    pub validity: Validity,
    pub subject: Name,
    /// The `AlgorithmIdentifier` from the submitted SPKI.
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
            use der::TagMode;
            use der::asn1::ContextSpecific;
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
            use der::TagMode;
            use der::asn1::ContextSpecific;
            let tagged = ContextSpecific::<BitString> {
                tag_number: der::TagNumber(1),
                tag_mode: TagMode::Implicit,
                value: v.clone(),
            };
            tagged.encode_to_vec(&mut buf)?;
        }

        // subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL
        if let Some(ref v) = self.subject_unique_id {
            use der::TagMode;
            use der::asn1::ContextSpecific;
            let tagged = ContextSpecific::<BitString> {
                tag_number: der::TagNumber(2),
                tag_mode: TagMode::Implicit,
                value: v.clone(),
            };
            tagged.encode_to_vec(&mut buf)?;
        }

        // extensions [3] EXPLICIT Extensions OPTIONAL
        if let Some(ref exts) = self.extensions {
            use der::TagMode;
            use der::asn1::ContextSpecific;
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
        use der::{SliceReader, TagNumber, asn1::ContextSpecific};

        let mut reader = SliceReader::new(data)?;

        // version [0] EXPLICIT INTEGER DEFAULT V1
        let version = if der::Tag::peek(&reader).is_ok_and(|t| {
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
        let extensions = if der::Tag::peek(&reader).is_ok_and(|t| {
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

        reader.finish().map_err(|e: der::Error| MtcError::from(e))?;
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
        ext::pkix::{SubjectAltName, name::GeneralName},
        time::Time,
    };

    fn dummy_validity() -> Validity {
        Validity::new(
            Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(1_700_000_000)).unwrap()),
            Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(1_700_086_400)).unwrap()),
        )
    }

    /// Generate a CSR with no extensions.
    fn make_csr_no_san() -> Vec<u8> {
        use crypto_common::Generate as _;
        use der::Encode as _;
        use p256::ecdsa::SigningKey;
        use std::str::FromStr;
        use x509_cert::{
            builder::{Builder, RequestBuilder},
            name::Name,
        };
        let sk = SigningKey::generate_from_rng(&mut rand::rng());
        let subject = Name::from_str("CN=test.example.com,O=Test,C=US").unwrap();
        RequestBuilder::new(subject)
            .unwrap()
            .build::<_, p256::ecdsa::DerSignature>(&sk)
            .unwrap()
            .to_der()
            .unwrap()
    }

    /// Generate a CSR with a subjectAltName containing two DNS names.
    fn make_csr_with_sans() -> Vec<u8> {
        use crypto_common::Generate as _;
        use der::Encode as _;
        use p256::ecdsa::SigningKey;
        use std::str::FromStr;
        use x509_cert::{
            builder::{Builder, RequestBuilder},
            ext::pkix::{SubjectAltName, name::GeneralName},
            name::Name,
        };
        let sk = SigningKey::generate_from_rng(&mut rand::rng());
        let subject = Name::from_str("CN=test.example.com,O=Test,C=US").unwrap();
        let mut builder = RequestBuilder::new(subject).unwrap();
        let san = SubjectAltName(vec![
            GeneralName::DnsName(der::asn1::Ia5String::new("example.com").unwrap()),
            GeneralName::DnsName(der::asn1::Ia5String::new("www.example.com").unwrap()),
        ]);
        builder.add_extension(&san).unwrap();
        builder
            .build::<_, p256::ecdsa::DerSignature>(&sk)
            .unwrap()
            .to_der()
            .unwrap()
    }

    #[test]
    fn test_encode_null_entry() {
        let null_entry = MerkleTreeCertEntry::NullEntry {
            extensions: Vec::new(),
        };
        assert_eq!(
            null_entry,
            MerkleTreeCertEntry::decode(&null_entry.encode().unwrap()).unwrap()
        );
    }

    #[test]
    fn test_entry_extension_framing_and_ordering() {
        let entry = MerkleTreeCertEntry::NullEntry {
            extensions: vec![
                MerkleTreeCertEntryExtension {
                    extension_type: 1,
                    extension_data: vec![2, 3],
                },
                MerkleTreeCertEntryExtension {
                    extension_type: 4,
                    extension_data: Vec::new(),
                },
            ],
        };
        let encoded = entry.encode().unwrap();
        assert_eq!(MerkleTreeCertEntry::decode(&encoded).unwrap(), entry);

        let unordered = MerkleTreeCertEntry::NullEntry {
            extensions: vec![
                MerkleTreeCertEntryExtension {
                    extension_type: 4,
                    extension_data: Vec::new(),
                },
                MerkleTreeCertEntryExtension {
                    extension_type: 1,
                    extension_data: Vec::new(),
                },
            ],
        };
        assert!(unordered.encode().is_err());
    }

    #[test]
    fn test_log_entry_size_limit() {
        let at_limit = MerkleTreeCertEntry::NullEntry {
            extensions: vec![MerkleTreeCertEntryExtension {
                extension_type: 1,
                extension_data: vec![0; 65_527],
            }],
        };
        assert_eq!(at_limit.encode().unwrap().len(), UINT16_MAX);

        let over_limit = MerkleTreeCertEntry::NullEntry {
            extensions: vec![MerkleTreeCertEntryExtension {
                extension_type: 1,
                extension_data: vec![0; 65_528],
            }],
        };
        assert!(
            matches!(over_limit.encode(), Err(MtcError::Dynamic(message)) if message.contains("exceeds 65535"))
        );
        assert!(
            matches!(MerkleTreeCertEntry::decode(&vec![0; UINT16_MAX + 1]), Err(MtcError::Dynamic(message)) if message.contains("exceeds 65535"))
        );
    }

    #[test]
    fn test_mtc_proof_length_bounds() {
        let id: TrustAnchorID = "1".parse().unwrap();
        let proof = MtcProof {
            extensions: Vec::new(),
            start: 0,
            end: 1,
            inclusion_proof: Vec::new(),
            signatures: vec![MtcSignature {
                cosigner_id: id.clone(),
                signature: vec![0; UINT16_MAX],
            }],
        };
        let encoded = proof.to_bytes().unwrap();
        assert_eq!(&encoded[16..19], &[1, 0, 3]);
        assert_eq!(
            ParsedMtcProof::from_bytes(&encoded).unwrap().signatures[&id].len(),
            UINT16_MAX
        );

        let oversized_signature = MtcProof {
            signatures: vec![MtcSignature {
                cosigner_id: "1".parse().unwrap(),
                signature: vec![0; UINT16_MAX + 1],
            }],
            ..proof
        };
        assert!(oversized_signature.to_bytes().is_err());

        let oversized_proof = MtcProof {
            inclusion_proof: vec![Hash::default(); 2048],
            signatures: Vec::new(),
            extensions: Vec::new(),
            start: 0,
            end: 1,
        };
        assert!(oversized_proof.to_bytes().is_err());
        assert!(check_length(UINT24_MAX, UINT24_MAX, "signatures").is_ok());
        assert!(check_length(UINT24_MAX + 1, UINT24_MAX, "signatures").is_err());
    }

    #[test]
    fn test_log_id_derivation() {
        let ca_id: TrustAnchorID = "44363.47".parse().unwrap();
        assert_eq!(ca_id.log_id(9).unwrap().to_string(), "44363.47.0.9");
        assert_eq!(ca_id.oid_name(), "oid/1.3.6.1.4.1.44363.47");
        assert!(ca_id.log_id(0).is_err());
    }

    #[test]
    fn test_mtc_ca_extension_representation() {
        let algorithm = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
            parameters: None,
        };
        let representation = MtcCertificationAuthority {
            signature_algorithm: algorithm,
            min_serial: Uint::new(&0_u64.to_be_bytes()).unwrap(),
            max_serial: Uint::new(&u64::MAX.to_be_bytes()).unwrap(),
        };
        let extension = representation.to_extension().unwrap();
        assert_eq!(extension.extn_id, ID_PE_MTC_CERTIFICATION_AUTHORITY_SHA256);
        assert!(extension.critical);
        assert_eq!(
            MtcCertificationAuthority::from_der(extension.extn_value.as_bytes()).unwrap(),
            representation
        );
    }

    #[test]
    fn test_certificate_serial_includes_log_number() {
        let csr = CertReq::from_der(&make_csr_no_san()).unwrap();
        let spki_der = csr.info.public_key.to_der().unwrap();
        let pending = build_pending_entry(
            &AddEntryRequest {
                csr: csr.to_der().unwrap(),
            },
            &RdnSequence::default(),
            dummy_validity(),
        )
        .unwrap();
        let log_entry = IetfMtcLogEntry::new(pending, 1, 0);
        let cosignatures = vec![
            ("128".parse().unwrap(), vec![2]),
            ("1.2".parse().unwrap(), vec![1]),
        ];
        let cert_der = serialize_mtc_cert(
            &log_entry,
            7,
            1,
            &spki_der,
            &Subtree::new(0, 2).unwrap(),
            Vec::new(),
            &cosignatures,
        )
        .unwrap();
        let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();
        let mut serial = [0_u8; 8];
        let bytes = cert.tbs_certificate().serial_number().as_bytes();
        serial[8 - bytes.len()..].copy_from_slice(bytes);
        assert_eq!(u64::from_be_bytes(serial), (7_u64 << 48) | 1);
        ParsedMtcProof::from_bytes(cert.signature().as_bytes().unwrap()).unwrap();

        assert!(
            serialize_mtc_cert(
                &log_entry,
                0,
                1,
                &spki_der,
                &Subtree::new(0, 2).unwrap(),
                Vec::new(),
                &[],
            )
            .is_err()
        );

        assert!(
            serialize_mtc_cert(
                &log_entry,
                7,
                UINT48_MAX - 1,
                &spki_der,
                &Subtree::new(0, UINT48_MAX).unwrap(),
                Vec::new(),
                &[],
            )
            .is_ok()
        );
        assert!(
            serialize_mtc_cert(
                &log_entry,
                7,
                UINT48_MAX,
                &spki_der,
                &Subtree::new(0, UINT48_MAX).unwrap(),
                Vec::new(),
                &[],
            )
            .is_err()
        );

        let duplicate = vec![
            ("1.2".parse().unwrap(), vec![1]),
            ("1.2".parse().unwrap(), vec![2]),
        ];
        assert!(
            serialize_mtc_cert(
                &log_entry,
                7,
                1,
                &spki_der,
                &Subtree::new(0, 2).unwrap(),
                Vec::new(),
                &duplicate,
            )
            .is_err()
        );
    }

    #[test]
    fn test_build_pending_entry_with_sans() {
        let req = AddEntryRequest {
            csr: make_csr_with_sans(),
        };

        let entry = build_pending_entry(&req, &RdnSequence::default(), dummy_validity()).unwrap();
        let decoded = MerkleTreeCertEntry::decode(&entry.entry.data).unwrap();

        let MerkleTreeCertEntry::TbsCertEntry {
            tbs_certificate: tbs,
            ..
        } = decoded
        else {
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
            csr: make_csr_no_san(),
        };

        let entry = build_pending_entry(&req, &RdnSequence::default(), dummy_validity()).unwrap();
        let decoded = MerkleTreeCertEntry::decode(&entry.entry.data).unwrap();
        let MerkleTreeCertEntry::TbsCertEntry {
            tbs_certificate: tbs,
            ..
        } = decoded
        else {
            panic!("expected TbsCertEntry");
        };
        assert!(tbs.extensions.is_none());
    }

    #[test]
    fn test_pending_entry_lookup_key_is_stable_across_retries() {
        let req = AddEntryRequest {
            csr: make_csr_no_san(),
        };
        let first = build_pending_entry(&req, &RdnSequence::default(), dummy_validity()).unwrap();
        let later_validity = Validity::new(
            Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(1_700_000_001)).unwrap()),
            Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(1_700_086_401)).unwrap()),
        );
        let retry = build_pending_entry(&req, &RdnSequence::default(), later_validity).unwrap();

        assert_eq!(first.lookup_key(), retry.lookup_key());
        assert_ne!(first.entry.data, retry.entry.data);
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
        let csr_bytes = make_csr_no_san();
        let b64url = BASE64_URL_SAFE_NO_PAD.encode(&csr_bytes);

        // Without optional fields.
        let json = format!(r#"{{"csr": "{b64url}"}}"#);
        let req: AddEntryRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.csr, csr_bytes);
        assert_eq!(req.csr, csr_bytes);
    }

    // ---- TbsCertificateLogEntry encoding regression ----

    /// Reference mirror of [`TbsCertificateLogEntry`] that uses
    /// `#[derive(Sequence)]` to produce an outer-SEQUENCE DER encoding via the
    /// macro. Used by [`test_tbs_cert_log_entry_encoding_matches_sequence_derive`]
    /// to verify that the hand-rolled, SEQUENCE-less
    /// [`TbsCertificateLogEntry::encode_fields`] matches the content bytes of
    /// the macro-derived SEQUENCE encoding.
    ///
    /// The field list and ASN.1 annotations are identical to the bootstrap
    /// `TbsCertificateLogEntry` shape, plus the `subject_public_key_info_algorithm`
    /// field present in the current draft.
    #[derive(Clone, Debug, Eq, PartialEq, der::Sequence, der::ValueOrd)]
    struct OldTbsCertificateLogEntry {
        #[asn1(context_specific = "0", default = "Default::default")]
        pub version: Version,
        pub issuer: Name,
        pub validity: Validity,
        pub subject: Name,
        pub subject_public_key_info_algorithm: AlgorithmIdentifierOwned,
        pub subject_public_key_info_hash: OctetString,
        #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
        pub issuer_unique_id: Option<BitString>,
        #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
        pub subject_unique_id: Option<BitString>,
        #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
        pub extensions: Option<Extensions>,
    }

    /// Strip the outer SEQUENCE tag (`0x30`) + length from a DER-encoded value
    /// and return the content bytes.
    ///
    /// # Panics
    ///
    /// Panics if `der` does not start with a SEQUENCE tag or the length can't be
    /// parsed.
    fn strip_sequence_wrapper(der: &[u8]) -> &[u8] {
        assert_eq!(der[0], 0x30, "expected SEQUENCE tag");
        // DER length: short form if top bit of first length byte is 0.
        let first_len = der[1];
        let (body_offset, _content_len) = if first_len & 0x80 == 0 {
            (2usize, first_len as usize)
        } else {
            // Long form: low 7 bits = number of subsequent length bytes.
            let num_len_bytes = (first_len & 0x7f) as usize;
            let mut content_len: usize = 0;
            for i in 0..num_len_bytes {
                content_len = (content_len << 8) | der[2 + i] as usize;
            }
            (2 + num_len_bytes, content_len)
        };
        &der[body_offset..]
    }

    /// Build an [`OctetString`] containing a deterministic 32-byte "SPKI hash"
    /// for tests.
    fn dummy_spki_hash() -> OctetString {
        OctetString::new(vec![0x42u8; 32]).unwrap()
    }

    /// Build an RSA-SHA256-style `AlgorithmIdentifier` for use as a placeholder
    /// `subject_public_key_info_algorithm`.
    fn dummy_spki_algorithm() -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
            parameters: None,
        }
    }

    fn dummy_issuer() -> Name {
        use std::str::FromStr;
        Name::from_str("CN=Test Issuer,O=Test,C=US").unwrap()
    }

    fn dummy_subject() -> Name {
        use std::str::FromStr;
        Name::from_str("CN=test.example.com,O=Test,C=US").unwrap()
    }

    fn dummy_extensions() -> Extensions {
        use der::Encode as _;
        let san = SubjectAltName(vec![GeneralName::DnsName(
            der::asn1::Ia5String::new("example.com").unwrap(),
        )]);
        vec![x509_cert::ext::Extension {
            extn_id: ObjectIdentifier::new_unwrap("2.5.29.17"),
            critical: false,
            extn_value: OctetString::new(san.to_der().unwrap()).unwrap(),
        }]
    }

    /// Regression: `TbsCertificateLogEntry::encode_fields` (hand-rolled, no
    /// outer SEQUENCE) must produce byte-for-byte the same content bytes as
    /// `#[derive(Sequence)]` applied to a struct with the same fields, after
    /// stripping the SEQUENCE tag + length.
    ///
    /// This pins the wire format against future refactors: any change to the
    /// hand-rolled encoder would immediately diverge from the macro-derived
    /// reference and fail this test.
    #[test]
    fn test_tbs_cert_log_entry_encoding_matches_sequence_derive() {
        use der::Encode as _;

        // Test matrix: mix of V1/V3, optional fields present/absent.
        let cases: Vec<(&str, TbsCertificateLogEntry, OldTbsCertificateLogEntry)> = {
            // Case 1: V1, no optional fields.
            let v1 = TbsCertificateLogEntry {
                version: Version::V1,
                issuer: dummy_issuer(),
                validity: dummy_validity(),
                subject: dummy_subject(),
                subject_public_key_info_algorithm: dummy_spki_algorithm(),
                subject_public_key_info_hash: dummy_spki_hash(),
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: None,
            };
            let v1_old = OldTbsCertificateLogEntry {
                version: v1.version,
                issuer: v1.issuer.clone(),
                validity: v1.validity,
                subject: v1.subject.clone(),
                subject_public_key_info_algorithm: v1.subject_public_key_info_algorithm.clone(),
                subject_public_key_info_hash: v1.subject_public_key_info_hash.clone(),
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: None,
            };

            // Case 2: V3 with extensions only.
            let v3_ext = TbsCertificateLogEntry {
                version: Version::V3,
                issuer: dummy_issuer(),
                validity: dummy_validity(),
                subject: dummy_subject(),
                subject_public_key_info_algorithm: dummy_spki_algorithm(),
                subject_public_key_info_hash: dummy_spki_hash(),
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: Some(dummy_extensions()),
            };
            let v3_ext_old = OldTbsCertificateLogEntry {
                version: v3_ext.version,
                issuer: v3_ext.issuer.clone(),
                validity: v3_ext.validity,
                subject: v3_ext.subject.clone(),
                subject_public_key_info_algorithm: v3_ext.subject_public_key_info_algorithm.clone(),
                subject_public_key_info_hash: v3_ext.subject_public_key_info_hash.clone(),
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: v3_ext.extensions.clone(),
            };

            // Case 3: V3 with every optional field populated.
            let iuid = BitString::from_bytes(&[0xaa, 0xbb, 0xcc]).unwrap();
            let suid = BitString::from_bytes(&[0xdd, 0xee]).unwrap();
            let v3_all = TbsCertificateLogEntry {
                version: Version::V3,
                issuer: dummy_issuer(),
                validity: dummy_validity(),
                subject: dummy_subject(),
                subject_public_key_info_algorithm: dummy_spki_algorithm(),
                subject_public_key_info_hash: dummy_spki_hash(),
                issuer_unique_id: Some(iuid.clone()),
                subject_unique_id: Some(suid.clone()),
                extensions: Some(dummy_extensions()),
            };
            let v3_all_old = OldTbsCertificateLogEntry {
                version: v3_all.version,
                issuer: v3_all.issuer.clone(),
                validity: v3_all.validity,
                subject: v3_all.subject.clone(),
                subject_public_key_info_algorithm: v3_all.subject_public_key_info_algorithm.clone(),
                subject_public_key_info_hash: v3_all.subject_public_key_info_hash.clone(),
                issuer_unique_id: Some(iuid),
                subject_unique_id: Some(suid),
                extensions: v3_all.extensions.clone(),
            };

            vec![
                ("V1 no optionals", v1, v1_old),
                ("V3 extensions only", v3_ext, v3_ext_old),
                ("V3 all optionals", v3_all, v3_all_old),
            ]
        };

        for (name, new, old) in cases {
            let new_encoded = new.encode_fields().expect("encode_fields");
            let old_der = old.to_der().expect("to_der on reference struct");
            let old_content = strip_sequence_wrapper(&old_der);
            assert_eq!(
                new_encoded, old_content,
                "{name}: encode_fields must match derive(Sequence) content bytes"
            );

            // Round-trip through decode_fields for good measure.
            let decoded =
                TbsCertificateLogEntry::decode_fields(&new_encoded).expect("decode_fields");
            assert_eq!(decoded, new, "{name}: decode_fields must round-trip");
        }
    }
}
