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
#[serde_as]
#[derive(Serialize)]
pub struct AddEntryResponse {
    /// The index of the entry in the log.
    pub leaf_index: LeafIndex,

    /// The time at which the entry was added to the log.
    pub timestamp: UnixTimestamp,

    /// The validity period of the entry as accepted by the log (may be
    /// clipped to the log's `max_certificate_lifetime_secs`).
    pub not_before: UnixTimestamp,
    pub not_after: UnixTimestamp,
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

    fn initial_entry() -> Option<Self::Pending> {
        Some(Self::Pending {
            entry: TlogTilesPendingLogEntry {
                data: MerkleTreeCertEntry::NullEntry.encode().unwrap(),
            },
        })
    }

    fn new(pending: Self::Pending, leaf_index: LeafIndex, timestamp: UnixTimestamp) -> Self {
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

    // Extract the AlgorithmIdentifier from the SPKI (new field in plants-02).
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

/// Return the serialized DER-encoded bytes of a landmark-relative
/// certificate (draft-ietf-plants-merkle-tree-certs §6.3).
///
/// # Errors
///
/// Returns an error if the SPKI hash does not match the entry, or if there
/// are any serialization errors.
pub fn serialize_landmark_relative_cert(
    log_entry: &IetfMtcLogEntry,
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
    let certificate = x509_util::OwnedCertificate {
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
            Self::TbsCertEntry(tbs_cert_entry) => Ok([
                (MerkleTreeCertEntryType::TbsCertEntry as u16)
                    .to_be_bytes()
                    .to_vec(),
                // plants-02: fields are written directly after the u16 type tag,
                // without an outer ASN.1 SEQUENCE wrapper (dropped in davidben-10).
                tbs_cert_entry.encode_fields()?,
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
            use der::asn1::ContextSpecific;
            use der::TagMode;
            let tagged = ContextSpecific::<BitString> {
                tag_number: der::TagNumber(1),
                tag_mode: TagMode::Implicit,
                value: v.clone(),
            };
            tagged.encode_to_vec(&mut buf)?;
        }

        // subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL
        if let Some(ref v) = self.subject_unique_id {
            use der::asn1::ContextSpecific;
            use der::TagMode;
            let tagged = ContextSpecific::<BitString> {
                tag_number: der::TagNumber(2),
                tag_mode: TagMode::Implicit,
                value: v.clone(),
            };
            tagged.encode_to_vec(&mut buf)?;
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
        ext::pkix::{name::GeneralName, SubjectAltName},
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
            ext::pkix::{name::GeneralName, SubjectAltName},
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
        let null_entry = MerkleTreeCertEntry::NullEntry;
        assert_eq!(
            null_entry,
            MerkleTreeCertEntry::decode(&null_entry.encode().unwrap()).unwrap()
        );
    }

    #[test]
    fn test_build_pending_entry_with_sans() {
        let req = AddEntryRequest {
            csr: make_csr_with_sans(),
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
            csr: make_csr_no_san(),
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
    /// field that draft-ietf-plants-merkle-tree-certs-02 added.
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

    /// Build an RSA-SHA256-style AlgorithmIdentifier for use as a placeholder
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
