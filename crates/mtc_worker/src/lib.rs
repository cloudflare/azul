// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

use config::AppConfig;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use mtc_api::{MTCSubtreeCosigner, RelativeOid, TrustAnchorID};
use p256::pkcs8::DecodePrivateKey;
use signed_note::KeyName;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{LazyLock, OnceLock};
use tlog_tiles::{CheckpointSigner, CosignatureV1CheckpointSigner, LookupKey, SequenceMetadata};
#[allow(clippy::wildcard_imports)]
use worker::*;
use x509_cert::Certificate;
use x509_util::CertPool;

mod batcher_do;
mod frontend_worker;
mod sequencer_do;

// Application configuration.
static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| {
    serde_json::from_str::<AppConfig>(include_str!(concat!(env!("OUT_DIR"), "/config.json")))
        .expect("Failed to parse config")
});

static ROOTS: LazyLock<CertPool> = LazyLock::new(|| {
    CertPool::new(
        Certificate::load_pem_chain(include_bytes!(concat!(env!("OUT_DIR"), "/roots.pem")))
            .expect("Failed to parse roots"),
    )
    .unwrap()
});

static SIGNING_KEY_MAP: OnceLock<HashMap<String, OnceLock<Ed25519SigningKey>>> = OnceLock::new();
static WITNESS_KEY_MAP: OnceLock<HashMap<String, OnceLock<Ed25519SigningKey>>> = OnceLock::new();

pub(crate) fn load_signing_key(env: &Env, name: &str) -> Result<&'static Ed25519SigningKey> {
    load_ed25519_key(env, name, &SIGNING_KEY_MAP, &format!("SIGNING_KEY_{name}"))
}

pub(crate) fn load_witness_key(env: &Env, name: &str) -> Result<&'static Ed25519SigningKey> {
    load_ed25519_key(env, name, &WITNESS_KEY_MAP, &format!("WITNESS_KEY_{name}"))
}

pub(crate) fn load_ed25519_key(
    env: &Env,
    name: &str,
    key_map: &'static OnceLock<HashMap<String, OnceLock<Ed25519SigningKey>>>,
    binding: &str,
) -> Result<&'static Ed25519SigningKey> {
    let once = &key_map.get_or_init(|| {
        CONFIG
            .logs
            .keys()
            .map(|name| (name.clone(), OnceLock::new()))
            .collect()
    })[name];
    if let Some(key) = once.get() {
        Ok(key)
    } else {
        let key = Ed25519SigningKey::from_pkcs8_pem(&env.secret(binding)?.to_string())
            .map_err(|e| e.to_string())?;
        Ok(once.get_or_init(|| key))
    }
}

pub(crate) fn load_checkpoint_signers(env: &Env, name: &str) -> Vec<Box<dyn CheckpointSigner>> {
    let origin = load_origin(name);

    // Parse the log ID, an ASN.1 `RELATIVE OID` in decimal-dotted string form.
    let log_id_relative_oid = RelativeOid::from_str(&CONFIG.logs[name].log_id).unwrap();

    // Get the BER/DER serialization of the content bytes, as described in <https://datatracker.ietf.org/doc/html/draft-ietf-tls-trust-anchor-ids-01#name-trust-anchor-identifiers>.
    let log_id = TrustAnchorID(log_id_relative_oid.as_bytes().to_vec());

    // TODO should the CA cosigner have a different ID than the log itself?
    let cosigner_id = log_id.clone();
    let signing_key = load_signing_key(env, name).unwrap().clone();
    let witness_key = load_witness_key(env, name).unwrap().clone();

    // Make the checkpoint signers from the secret keys and put them in a vec
    let signer = MTCSubtreeCosigner::new(cosigner_id, log_id, origin.clone(), signing_key);
    let witness = CosignatureV1CheckpointSigner::new(origin, witness_key);

    vec![Box::new(signer), Box::new(witness)]
}

pub(crate) fn load_origin(name: &str) -> KeyName {
    // https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md#parameters
    // The origin line SHOULD be the schema-less URL prefix of the log with no
    // trailing slashes. For example, a log with prefix
    // https://rome.ct.example.com/tevere/ will use rome.ct.example.com/tevere
    // as the checkpoint origin line.
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
