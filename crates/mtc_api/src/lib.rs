use anyhow::{anyhow, bail, ensure};
use der::{asn1::BitString, oid::db::rfc5280, Decode, Encode, Sequence, ValueOrd};
use length_prefixed::WriteLengthPrefixedBytesExt;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    io::Read,
};
use thiserror::Error;
use tlog_tiles::{
    Hash, LeafIndex, LogEntry, PathElem, PendingLogEntry, SequenceMetadata, TlogError,
    TlogTilesLogEntry, TlogTilesPendingLogEntry, UnixTimestamp,
};
use x509_util::CertPool;
use x509_verify::{
    der::asn1::OctetString,
    x509_cert::{
        certificate::Version,
        ext::{
            pkix::{ExtendedKeyUsage, KeyUsage, KeyUsages},
            Extension,
        },
        name::RdnSequence,
        time::Validity,
        Certificate, TbsCertificate,
    },
};

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
    pub leaf_index: LeafIndex,
    pub timestamp: UnixTimestamp,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct MtcPendingLogEntry {
    /// The serialized bootstrap chain.
    pub bootstrap: Vec<u8>,

    /// The serialized `TbsCertificateLogEntry`.
    pub entry: TlogTilesPendingLogEntry,
}

impl PendingLogEntry for MtcPendingLogEntry {
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

#[derive(Debug, Clone, PartialEq)]
pub struct MtcLogEntry(TlogTilesLogEntry);

impl LogEntry for MtcLogEntry {
    const REQUIRE_CHECKPOINT_TIMESTAMP: bool = false;
    type Pending = MtcPendingLogEntry;
    type ParseError = MtcError;

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

#[derive(Debug, Error)]
pub enum MtcError {
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
    #[error(transparent)]
    Tlog(#[from] TlogError),
    #[error(transparent)]
    Der(#[from] der::Error),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error("empty chain")]
    EmptyChain,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct TbsCertificateLogEntry {
    pub version: Version,
    pub issuer: RdnSequence,
    pub validity: Validity,
    pub subject: RdnSequence,
    pub subject_public_key_info_hash: OctetString,
    pub issuer_unique_id: Option<BitString>,
    pub subject_unique_id: Option<BitString>,
    pub extensions: Option<Vec<Extension>>,
}

// Validate and filter extended key usage extension.
fn filter_ext_key_usage(extension: &mut Extension) -> Result<(), anyhow::Error> {
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
    ensure!(!is_err, "unexpected key usage");
    ensure!(!eku.0.is_empty(), "key usage missing id-kp-serverAuth");
    extension.extn_value = OctetString::new(eku.to_der()?)?;
    Ok(())
}

// Validate and filter key usage extension.
fn filter_key_usage(extension: &mut Extension) -> Result<(), anyhow::Error> {
    let mut ku = KeyUsage::from_der(extension.extn_value.as_bytes())?;
    // Require digital_signature, allow key_encipherment, and filter everything else.
    ku.0 &= KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment;
    ensure!(
        ku.0.contains(KeyUsages::DigitalSignature),
        "key usage missing DigitalSignature"
    );
    extension.extn_value = OctetString::new(ku.to_der()?)?;
    Ok(())
}

fn filter_extensions(extensions: &mut Vec<Extension>) -> Result<(), anyhow::Error> {
    let mut result = Ok(());
    let mut oids = BTreeSet::new();
    extensions.retain_mut(|extension| {
        if oids.contains(&extension.extn_id) {
            result = Err(anyhow!("duplicate extension"));
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
                    result = Err(anyhow!("unsupported critical extension {id}"));
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
) -> Result<TbsCertificateLogEntry, anyhow::Error> {
    ensure!(bootstrap.version == Version::V3);
    ensure!(validity
        .not_before
        .to_unix_duration()
        .ge(&bootstrap.validity.not_before.to_unix_duration()));
    ensure!(validity
        .not_after
        .to_unix_duration()
        .le(&bootstrap.validity.not_after.to_unix_duration()));

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
            Sha256::digest(
                bootstrap
                    .subject_public_key_info
                    .to_der()
                    .map_err(|e| anyhow!(e.to_string()))?,
            )
            .as_slice(),
        )
        .map_err(|e| anyhow!(e.to_string()))?,
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
pub fn validate_correspondence(
    log_entry: &TbsCertificateLogEntry,
    chain: &[Certificate],
) -> Result<(), anyhow::Error> {
    // TODO validate bootstrap chain
    ensure!(!chain.is_empty());
    let bootstrap = chain[0].tbs_certificate.clone();

    ensure!(log_entry.version == bootstrap.version && log_entry.version == Version::V3);
    // Make sure the validity is contained within the validity of every cert in
    // the chain.
    for cert in chain {
        ensure!(log_entry.validity.not_after.to_unix_duration().le(&cert
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()));
        ensure!(log_entry.validity.not_before.to_unix_duration().ge(&cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()));
    }
    ensure!(log_entry.subject == bootstrap.subject);
    ensure!(
        log_entry.subject_public_key_info_hash
            == OctetString::new(
                Sha256::digest(
                    bootstrap
                        .subject_public_key_info
                        .to_der()
                        .map_err(|e| anyhow!(e.to_string()))?,
                )
                .as_slice(),
            )
            .map_err(|e| anyhow!(e.to_string()))?
    );
    ensure!(log_entry.issuer_unique_id == bootstrap.issuer_unique_id);
    ensure!(log_entry.subject_unique_id == bootstrap.subject_unique_id);

    match (log_entry.extensions.as_ref(), bootstrap.extensions) {
        (None, None) => {}
        (Some(log_entry_extensions), Some(mut bootstrap_extensions)) => {
            // Check and filter bootstrap extensions.
            filter_extensions(&mut bootstrap_extensions)?;

            // Make sure the filtered bootstrap extensions cover those of the log entry.
            ensure!(log_entry_extensions.len() == bootstrap_extensions.len());
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
                            ensure!(extension == bootstrap_extension);
                        } else {
                            bail!("bootstrap missing extension {id}");
                        }
                    }
                    id => bail!("log entry has unsupported extension {id}"),
                }
            }
        }
        _ => bail!("mismatched extensions"),
    }

    Ok(())
}

/// Parse and validate a bootstrap chain, returning a pending log entry.
///
/// # Errors
///
/// Returns an error if the chain is invalid.
pub fn validate_chain(
    raw_chain: &[Vec<u8>],
    _roots: &CertPool,
    issuer: RdnSequence,
    mut validity: Validity,
) -> Result<MtcPendingLogEntry, MtcError> {
    let mut iter = raw_chain.iter();
    let leaf: Certificate = match iter.next() {
        Some(v) => Certificate::from_der(v)?,
        None => return Err(MtcError::EmptyChain),
    };

    // TODO actually validate chain
    let chain = iter
        .map(|x| Certificate::from_der(x))
        .collect::<Result<Vec<Certificate>, der::Error>>()?;

    for cert in std::iter::once(&leaf).chain(&chain) {
        if validity.not_after.to_unix_duration().gt(&cert
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration())
        {
            validity.not_after = cert.tbs_certificate.validity.not_after;
        }
    }

    let mut bootstrap = Vec::new();
    bootstrap.write_length_prefixed(&raw_chain[0], 3)?;
    bootstrap.write_length_prefixed(
        &raw_chain[1..]
            .iter()
            .map(Sha256::digest)
            .collect::<Vec<_>>()
            .concat(),
        2,
    )?;

    let mut bootstrap_tile_entry = Vec::new();
    bootstrap_tile_entry.write_length_prefixed(bootstrap.as_slice(), 3)?;

    let tbs_certificate_log_entry = tbs_cert_to_log_entry(leaf.tbs_certificate, issuer, validity)?;

    let pending_entry = MtcPendingLogEntry {
        bootstrap: bootstrap_tile_entry,
        entry: TlogTilesPendingLogEntry {
            data: tbs_certificate_log_entry.to_der()?,
        },
    };
    Ok(pending_entry)
}

#[cfg(test)]
mod tests {
    use der::asn1::UtcTime;
    use std::time::Duration;
    use x509_verify::x509_cert::{time::Time, Certificate};

    use super::*;

    #[test]
    fn test_tbs_cert_to_log_entry() {
        let bootstrap_chain =
            Certificate::load_pem_chain(include_bytes!("../../static_ct_api/tests/leaf-cert.pem"))
                .unwrap();
        let bootstrap = &bootstrap_chain[0].tbs_certificate;
        let issuer = RdnSequence::default();

        let validity = Validity {
            not_before: Time::UtcTime(
                UtcTime::from_unix_duration(Duration::from_secs(1_518_521_919)).unwrap(),
            ),
            not_after: Time::UtcTime(
                UtcTime::from_unix_duration(Duration::from_secs(1_743_161_919)).unwrap(),
            ),
        };

        let mut log_entry = tbs_cert_to_log_entry(bootstrap.clone(), issuer, validity).unwrap();

        // Valid.
        validate_correspondence(&log_entry, &bootstrap_chain).unwrap();

        // Put the extensions in a different order.
        log_entry
            .extensions
            .as_mut()
            .unwrap_or(&mut Vec::new())
            .sort_by(|a, b| b.extn_id.cmp(&a.extn_id));

        // Still valid.
        validate_correspondence(&log_entry, &bootstrap_chain).unwrap();

        // Remove an extension.
        let ext = log_entry
            .extensions
            .as_mut()
            .unwrap_or(&mut Vec::new())
            .pop()
            .unwrap();

        // No longer valid.
        validate_correspondence(&log_entry, &bootstrap_chain).unwrap_err();

        // Put it back.
        log_entry
            .extensions
            .as_mut()
            .unwrap_or(&mut Vec::new())
            .push(ext);

        // Valid again.
        validate_correspondence(&log_entry, &bootstrap_chain).unwrap();

        // Increase the validity to outside the bootstrap's validity.
        log_entry.validity.not_after =
            Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(1_743_161_920)).unwrap());

        // No longer valid.
        validate_correspondence(&log_entry, &bootstrap_chain).unwrap_err();
    }

    #[test]
    fn test_log_entry_der() {
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
        let encoded = log_entry.to_der().unwrap();
        let decoded = TbsCertificateLogEntry::from_der(&encoded).unwrap();

        assert_eq!(log_entry, decoded);
    }
}
