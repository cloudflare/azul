// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Certificate chain fixtures for integration tests.
//!
//! Rather than using static pre-built fixtures (which expire), chains are
//! generated dynamically at test time using the committed CA key.
//!
//! The leaf's `notAfter` is set to the midpoint of the target log shard's
//! temporal interval (read from `ct_worker/config.dev.json`).
//!
//! # Committed test CA
//!
//! `tests/fixtures/ca-key.pem` and the corresponding CA cert are dev-only
//! keys — **not** production secrets. The CA cert is trusted by the CT worker's
//! `wrangler dev` instance via `ct_worker/roots.dev.pem`.

// These are test helpers — doc exhaustiveness is not required.
#![allow(clippy::missing_errors_doc)]

use std::str::FromStr;

use anyhow::{Context, Result};
use const_oid::AssociatedOid;
use crypto_common::Generate;
use der::{
    Decode, Encode, Length, Writer,
    asn1::{Ia5String, Null},
};
use p256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use serde::Deserialize;
use x509_cert::{
    builder::profile::BuilderProfile,
    builder::{Builder, CertificateBuilder},
    certificate::{Certificate, TbsCertificate},
    ext::{
        Criticality, Extension,
        pkix::{ExtendedKeyUsage, SubjectAltName, name::GeneralName},
    },
    name::Name,
    serial_number::SerialNumber,
    spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef},
    time::{Time, Validity},
};

// ---------------------------------------------------------------------------
// CT poison extension
// ---------------------------------------------------------------------------

/// OID for the CT Precertificate Poison extension (RFC 6962 §3.1).
const CT_PRECERT_POISON_OID: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.3");

/// A type representing the CT Precertificate Poison extension for use with
/// `CertificateBuilder::add_extension`.  Value is ASN.1 NULL; criticality is
/// always `true`.
struct CtPoisonExtension;

impl AssociatedOid for CtPoisonExtension {
    const OID: der::asn1::ObjectIdentifier = CT_PRECERT_POISON_OID;
}

// x509-cert 0.3: ToExtension is implemented for `&T` when T: Criticality + AssociatedOid + Encode.
// We implement Encode (value = ASN.1 NULL) and Criticality (always critical).
impl Encode for CtPoisonExtension {
    fn encoded_len(&self) -> der::Result<Length> {
        Null.encoded_len()
    }
    fn encode(&self, writer: &mut impl Writer) -> der::Result<()> {
        Null.encode(writer)
    }
}

impl Criticality for CtPoisonExtension {
    fn criticality(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Config parsing (mirrors ct_worker/config/src/lib.rs)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DevConfig {
    logs: std::collections::HashMap<String, LogParams>,
}

#[derive(Deserialize)]
struct LogParams {
    temporal_interval: TemporalInterval,
}

#[derive(Deserialize)]
struct TemporalInterval {
    start_inclusive: chrono::DateTime<chrono::Utc>,
    end_exclusive: chrono::DateTime<chrono::Utc>,
}

/// The dev config, embedded at compile time.
// NOTE: compile-time dependency on ct_worker/config.dev.json. If that file is
// moved or renamed, the error will surface here rather than in ct_worker.
const DEV_CONFIG_JSON: &str = include_str!("../../ct_worker/config.dev.json");

// ---------------------------------------------------------------------------
// Committed test CA
// ---------------------------------------------------------------------------

const CA_KEY_PEM: &str = include_str!("../tests/fixtures/ca-key.pem");

/// PEM-encoded "Azul Integration Test Root" CA certificate.
///
/// Embedded from `tests/fixtures/ca-cert.pem`, which is extracted verbatim
/// from `ct_worker/roots.dev.pem`.
/// Using the same PEM bytes ensures the DER fingerprint matches what the
/// root pool loads, so `CertPool::includes()` succeeds during chain validation.
const CA_CERT_PEM: &str = include_str!("../tests/fixtures/ca-cert.pem");

/// Parse and return the DER bytes of the test CA certificate.
///
/// Parsed once per call; callers that need it repeatedly should cache the result.
fn ca_cert_der_bytes() -> Vec<u8> {
    use x509_cert::der::DecodePem;
    Certificate::from_pem(CA_CERT_PEM)
        .expect("parsing CA_CERT_PEM")
        .to_der()
        .expect("encoding CA cert to DER")
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// A pair of cert chains generated for a specific log shard's temporal interval.
pub struct GeneratedChains {
    /// DER-encoded certificates: `[leaf, CA]`
    pub chain: Vec<Vec<u8>>,
    /// DER-encoded certificates: `[precert, CA]`
    pub pre_chain: Vec<Vec<u8>>,
}

/// Generate a leaf cert and precert whose `notAfter` falls within the temporal
/// interval of `log_name` in `config.dev.json`.
///
/// The leaf is signed by the committed test CA key
/// (`tests/fixtures/ca-key.pem`).  The CA cert is trusted by `wrangler dev`
/// via `ct_worker/roots.dev.pem`.
pub fn make_chains(log_name: &str) -> Result<GeneratedChains> {
    let config: DevConfig =
        serde_json::from_str(DEV_CONFIG_JSON).context("parsing config.dev.json")?;
    let log = config
        .logs
        .get(log_name)
        .with_context(|| format!("log '{log_name}' not found in config.dev.json"))?;

    let start = log.temporal_interval.start_inclusive;
    let end = log.temporal_interval.end_exclusive;

    // Fixed historical shard dates make these fixtures reproducible. Historical
    // test shards must configure reject_expired=false.
    let not_before = start;
    let not_after = {
        let mid_ts = start.timestamp() + (end.timestamp() - start.timestamp()) / 2;
        chrono::DateTime::<chrono::Utc>::from_timestamp(mid_ts, 0)
            .context("computing notAfter midpoint")?
    };

    let ca_key = SigningKey::from_pkcs8_pem(CA_KEY_PEM).context("loading CA key")?;

    let leaf_der =
        build_cert(&ca_key, not_before, not_after, false).context("building leaf cert")?;
    let precert_der =
        build_cert(&ca_key, not_before, not_after, true).context("building precert")?;

    Ok(GeneratedChains {
        chain: vec![leaf_der, ca_cert_der_bytes()],
        pre_chain: vec![precert_der, ca_cert_der_bytes()],
    })
}

/// Generate a certificate chain that expired within the configured temporal interval.
pub fn make_expired_chain(log_name: &str) -> Result<Vec<Vec<u8>>> {
    let config: DevConfig =
        serde_json::from_str(DEV_CONFIG_JSON).context("parsing config.dev.json")?;
    let log = config
        .logs
        .get(log_name)
        .with_context(|| format!("log '{log_name}' not found in config.dev.json"))?;
    let not_before = log.temporal_interval.start_inclusive;
    let not_after = not_before + chrono::TimeDelta::days(1);
    anyhow::ensure!(not_after < log.temporal_interval.end_exclusive);
    anyhow::ensure!(not_after < chrono::Utc::now());

    let ca_key = SigningKey::from_pkcs8_pem(CA_KEY_PEM).context("loading CA key")?;
    let leaf_der =
        build_cert(&ca_key, not_before, not_after, false).context("building leaf cert")?;
    Ok(vec![leaf_der, ca_cert_der_bytes()])
}

/// Returns the DER bytes of the test CA certificate.
#[must_use]
pub fn ca_cert_der() -> Vec<u8> {
    ca_cert_der_bytes()
}

// ---------------------------------------------------------------------------
// Certificate construction
// ---------------------------------------------------------------------------

fn build_cert(
    ca_key: &SigningKey,
    not_before: chrono::DateTime<chrono::Utc>,
    not_after: chrono::DateTime<chrono::Utc>,
    is_precert: bool,
) -> Result<Vec<u8>> {
    let serial = SerialNumber::from(rand::random::<u32>());

    let validity = Validity::new(
        Time::GeneralTime(der::asn1::GeneralizedTime::from_date_time(to_der_datetime(
            not_before,
        )?)),
        Time::GeneralTime(der::asn1::GeneralizedTime::from_date_time(to_der_datetime(
            not_after,
        )?)),
    );

    let subject = Name::from_str("CN=integration-test.example.com,O=Test,C=US")
        .context("building subject name")?;

    let leaf_key = SigningKey::generate_from_rng(&mut rand::rng());
    let leaf_spki = SubjectPublicKeyInfoOwned::from_key(leaf_key.verifying_key())
        .context("encoding leaf SPKI")?;

    let ca_cert = Certificate::from_der(&ca_cert_der_bytes()).context("parsing CA cert")?;
    let issuer = ca_cert.tbs_certificate().subject().clone();

    let profile = LeafProfile { issuer, subject };
    let mut builder = CertificateBuilder::new(profile, serial, validity, leaf_spki)
        .context("creating CertificateBuilder")?;

    let san = SubjectAltName(vec![GeneralName::DnsName(
        Ia5String::new("integration-test.example.com").context("building SAN")?,
    )]);
    builder.add_extension(&san).context("adding SAN")?;

    let eku = ExtendedKeyUsage(vec![der::asn1::ObjectIdentifier::new_unwrap(
        "1.3.6.1.5.5.7.3.1",
    )]);
    builder.add_extension(&eku).context("adding EKU")?;

    if is_precert {
        builder
            .add_extension(&CtPoisonExtension)
            .context("adding CT poison extension")?;
    }

    builder
        .build_with_rng::<_, p256::ecdsa::DerSignature, _>(ca_key, &mut rand::rng())
        .context("signing certificate")?
        .to_der()
        .context("encoding certificate to DER")
}

/// Minimal leaf certificate profile for integration tests.
struct LeafProfile {
    issuer: Name,
    subject: Name,
}

impl BuilderProfile for LeafProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }
    fn get_subject(&self) -> Name {
        self.subject.clone()
    }
    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> Result<Vec<Extension>, x509_cert::builder::Error> {
        Ok(vec![])
    }
}

/// Convert a `chrono::DateTime<Utc>` to a `der::DateTime`.
fn to_der_datetime(dt: chrono::DateTime<chrono::Utc>) -> Result<der::DateTime> {
    use chrono::{Datelike, Timelike};
    der::DateTime::new(
        dt.year().try_into().context("year out of range")?,
        dt.month().try_into().context("month out of range")?,
        dt.day().try_into().context("day out of range")?,
        dt.hour().try_into().context("hour out of range")?,
        dt.minute().try_into().context("minute out of range")?,
        dt.second().try_into().context("second out of range")?,
    )
    .context("constructing der::DateTime")
}

// ---------------------------------------------------------------------------
// Invalid inputs for negative tests
// ---------------------------------------------------------------------------

/// A chain containing a single entry that is not a valid DER certificate.
#[must_use]
pub fn garbage_chain() -> Vec<Vec<u8>> {
    vec![b"this is not a certificate".to_vec()]
}

/// An empty chain (no certificates at all).
#[must_use]
pub fn empty_chain() -> Vec<Vec<u8>> {
    vec![]
}
