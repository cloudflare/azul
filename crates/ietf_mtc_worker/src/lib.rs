// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

use config::AppConfig;
use ietf_mtc_api::{MtcCosigner, MtcSigningKey, MtcVerifyingKey, TrustAnchorID};
#[cfg(feature = "ml-dsa")]
use ml_dsa::{KeyPair, MlDsa44, MlDsa65, MlDsa87};
use pkcs8::{DecodePrivateKey, PrivateKeyInfo};
use signed_note::KeyName;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{LazyLock, OnceLock};
use tlog_tiles::SequenceMetadata;
#[allow(clippy::wildcard_imports)]
use worker::*;

mod batcher_do;
mod cleaner_do;
mod frontend_worker;
mod sequencer_do;

// Algorithm OID constants.
const OID_ED25519: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.101.112");
#[cfg(feature = "ml-dsa")]
const OID_ML_DSA_44: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
#[cfg(feature = "ml-dsa")]
const OID_ML_DSA_65: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
#[cfg(feature = "ml-dsa")]
const OID_ML_DSA_87: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

// Application configuration.
static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| {
    serde_json::from_str::<AppConfig>(include_str!(concat!(env!("OUT_DIR"), "/config.json")))
        .expect("Failed to parse config")
});

type CachedKeys = (MtcSigningKey, MtcVerifyingKey);
static KEY_MAP: OnceLock<HashMap<String, OnceLock<CachedKeys>>> = OnceLock::new();

/// Return the key pair for the given log, using a per-log cache.
///
/// Uses `OnceLock::get()` to check the cache without blocking.  If the cache
/// is not yet populated (either empty or being initialized by another request),
/// the key pair is parsed directly from the secret without waiting.  This
/// avoids the cross-request `OnceLock::get_or_init` deadlock that the Workers
/// runtime detects when two requests concurrently initialize the same cell.
pub(crate) fn load_key_pair(env: &Env, name: &str) -> Result<CachedKeys> {
    let once = &KEY_MAP.get_or_init(|| {
        CONFIG
            .logs
            .keys()
            .map(|n| (n.clone(), OnceLock::new()))
            .collect()
    })[name];

    // Fast path: already cached.
    if let Some(keys) = once.get() {
        return Ok(keys.clone());
    }

    // Slow path: parse from secret.  We do not call get_or_init here because
    // that would block if another request is currently initializing the cell,
    // which the Workers runtime detects and cancels as a cross-request deadlock.
    // Instead, parse directly and attempt to store the result; if another
    // request beat us to it, use its cached value.
    let pem = env.secret(&format!("SIGNING_KEY_{name}"))?.to_string();
    let keys = parse_key_pair(&pem).map_err(worker::Error::from)?;
    Ok(once.get_or_init(|| keys).clone())
}

/// Parse a PKCS#8 PEM key, dispatching to the correct algorithm based on the
/// `AlgorithmIdentifier` OID embedded in the `PrivateKeyInfo`.
fn parse_key_pair(pem: &str) -> std::result::Result<(MtcSigningKey, MtcVerifyingKey), String> {
    let (_label, doc) = pkcs8::SecretDocument::from_pem(pem).map_err(|e| e.to_string())?;
    let pki = PrivateKeyInfo::try_from(doc.as_bytes()).map_err(|e| e.to_string())?;

    match pki.algorithm.oid {
        OID_ED25519 => {
            let sk = ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
                .map_err(|e| e.to_string())?;
            let vk = sk.verifying_key();
            Ok((MtcSigningKey::Ed25519(sk), MtcVerifyingKey::Ed25519(vk)))
        }
        #[cfg(feature = "ml-dsa")]
        OID_ML_DSA_44 => {
            let kp = KeyPair::<MlDsa44>::from_pkcs8_pem(pem).map_err(|e| e.to_string())?;
            Ok((
                MtcSigningKey::MlDsa44(kp.signing_key().clone()),
                MtcVerifyingKey::MlDsa44(kp.verifying_key().clone()),
            ))
        }
        #[cfg(feature = "ml-dsa")]
        OID_ML_DSA_65 => {
            let kp = KeyPair::<MlDsa65>::from_pkcs8_pem(pem).map_err(|e| e.to_string())?;
            Ok((
                MtcSigningKey::MlDsa65(kp.signing_key().clone()),
                MtcVerifyingKey::MlDsa65(kp.verifying_key().clone()),
            ))
        }
        #[cfg(feature = "ml-dsa")]
        OID_ML_DSA_87 => {
            let kp = KeyPair::<MlDsa87>::from_pkcs8_pem(pem).map_err(|e| e.to_string())?;
            Ok((
                MtcSigningKey::MlDsa87(kp.signing_key().clone()),
                MtcVerifyingKey::MlDsa87(kp.verifying_key().clone()),
            ))
        }
        oid => Err(format!("unsupported signing algorithm OID: {oid}")),
    }
}

pub(crate) fn load_checkpoint_cosigner(env: &Env, name: &str) -> MtcCosigner {
    let log_id = TrustAnchorID::from_str(&CONFIG.logs[name].log_id).unwrap();
    let cosigner_id = TrustAnchorID::from_str(&CONFIG.logs[name].cosigner_id).unwrap();
    let (sk, vk) = load_key_pair(env, name).unwrap();
    MtcCosigner::new_checkpoint(cosigner_id, log_id, sk, vk)
}

pub(crate) fn load_origin(name: &str) -> KeyName {
    KeyName::new(
        CONFIG.logs[name]
            .submission_url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .to_string(),
    )
    .expect("invalid origin name")
}
