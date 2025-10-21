// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

use crate::ccadb_roots_cron::{update_ccadb_roots, CCADB_ROOTS_FILENAME, CCADB_ROOTS_NAMESPACE};
use config::AppConfig;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use mtc_api::{MTCSubtreeCosigner, RelativeOid, TrustAnchorID};
use p256::pkcs8::DecodePrivateKey;
use signed_note::KeyName;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{LazyLock, OnceLock};
use tlog_tiles::SequenceMetadata;
use tokio::sync::OnceCell;
#[allow(clippy::wildcard_imports)]
use worker::*;
use x509_util::CertPool;

mod batcher_do;
mod ccadb_roots_cron;
mod cleaner_do;
mod frontend_worker;
mod sequencer_do;

// Application configuration.
static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| {
    serde_json::from_str::<AppConfig>(include_str!(concat!(env!("OUT_DIR"), "/config.json")))
        .expect("Failed to parse config")
});

static SIGNING_KEY_MAP: OnceLock<HashMap<String, OnceLock<Ed25519SigningKey>>> = OnceLock::new();
static ROOTS: OnceCell<CertPool> = OnceCell::const_new();

pub(crate) fn load_signing_key(env: &Env, name: &str) -> Result<&'static Ed25519SigningKey> {
    load_ed25519_key(env, name, &SIGNING_KEY_MAP, &format!("SIGNING_KEY_{name}"))
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

pub(crate) fn load_cosigner(env: &Env, name: &str) -> MTCSubtreeCosigner {
    let origin = load_origin(name);

    // Parse the log ID, an ASN.1 `RELATIVE OID` in decimal-dotted string form.
    let log_id = {
        let relative_oid = RelativeOid::from_str(&CONFIG.logs[name].log_id).unwrap();
        // Get the BER/DER serialization of the content bytes, as described in
        // <https://datatracker.ietf.org/doc/html/draft-ietf-tls-trust-anchor-ids-01#name-trust-anchor-identifiers>.
        TrustAnchorID(relative_oid.as_bytes().to_vec())
    };

    // Likewise for the cosigner ID.
    let cosigner_id = {
        let relative_oid = RelativeOid::from_str(&CONFIG.logs[name].cosigner_id).unwrap();
        TrustAnchorID(relative_oid.as_bytes().to_vec())
    };

    let signing_key = load_signing_key(env, name).unwrap().clone();

    MTCSubtreeCosigner::new(cosigner_id, log_id, origin.clone(), signing_key)
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

async fn load_roots(env: &Env, name: &str) -> Result<&'static CertPool> {
    // Load embedded roots.
    ROOTS
        .get_or_try_init(|| async {
            let mut pool = CertPool::default();
            // Load additional roots from the CCADB roots file in Workers KV.
            let kv = env.kv(CCADB_ROOTS_NAMESPACE)?;
            let pem = if let Some(pem) = kv.get(CCADB_ROOTS_FILENAME).text().await? {
                pem
            } else {
                // The roots file might not exist if the CCADB roots cron job hasn't
                // run yet. Try to create it once before failing.
                update_ccadb_roots(&kv).await?;
                kv.get(CCADB_ROOTS_FILENAME)
                    .text()
                    .await?
                    .ok_or(format!("{name}: '{CCADB_ROOTS_FILENAME}' not found in KV"))?
            };

            pool.append_certs_from_pem(pem.as_bytes())
                .map_err(|e| format!("failed to add CCADB certs to pool: {e}"))?;

            // Add additional roots when the 'dev-bootstrap-roots' feature is
            // enabled.
            //
            // A note on the differences between how roots are handled for the
            // MTC vs CT applications:
            //
            // The purpose of CT is to observe certificates but not police them.
            // As long as it's not a spam vector, we're generally willing to
            // accept any root certificates that have been trusted by at least
            // one major root program during the log shard's lifetime. Roots
            // aren't removed from the list once they're added in order to keep
            // a better record. We have the ability to add in custom roots from
            // a per-environment roots file too, in order to support test CAs.
            //
            // For bootstrap MTC, the roots are meant to ensure that the log
            // only accepts bootstrap MTC chains that will be trusted by Chrome,
            // since Chrome might reject an entire batch of MTCs if there's a
            // single untrusted entry. Thus, we want to keep the trusted roots
            // as a subset of Chrome's trust store. We're using Mozilla's CRLite
            // filters to check for revocation, so we need to be a subset of
            // Mozilla's trust store too. When either root program stops
            // trusting a root, we also need to remove it from our trust store.
            // Given that, we gate the ability to add in custom roots behind the
            // 'dev-bootstrap-roots' feature flag.
            #[cfg(feature = "dev-bootstrap-roots")]
            {
                pool.append_certs_from_pem(include_bytes!("../dev-bootstrap-roots.pem"))
                    .map_err(|e| format!("failed to add dev certs to pool: {e}"))?;
            }

            Ok(pool)
        })
        .await
}
