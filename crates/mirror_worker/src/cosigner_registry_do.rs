// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::collections::{BTreeSet, HashMap};

use futures_util::TryStreamExt as _;
use ml_dsa::{MlDsa44, VerifyingKey as MlDsaVerifyingKey};
use pkcs8::{
    DecodePublicKey as _,
    der::{Document, oid::db::fips204::ID_ML_DSA_44},
    spki::SubjectPublicKeyInfoRef,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
#[allow(clippy::wildcard_imports)]
use worker::*;

use crate::{CONFIG, LogKey, log_verifiers_for_keys};

pub(crate) const COSIGNER_REGISTRY_BINDING: &str = "COSIGNER_REGISTRY";
const REGISTRY_NAME: &str = "cosigners-v1";
const REGISTRY_KEY: &str = "registry";
const COSIGNERS_JSON_URL: &str = "https://www.gstatic.com/mtcs/cosigners/v1/cosigners.json";
const COSIGNERS_PEM_URL: &str = "https://www.gstatic.com/mtcs/cosigners/v1/cosigners.pem";
const MAX_JSON_BYTES: usize = 1024 * 1024;
const MAX_PEM_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct RegistryLog {
    pub(crate) description: Option<String>,
    pub(crate) origin: String,
    pub(crate) signer_name: String,
    pub(crate) public_key: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct RegistryRecord {
    pub(crate) version: String,
    pub(crate) timestamp: Option<String>,
    pub(crate) logs: Vec<RegistryLog>,
}

#[derive(Deserialize)]
struct CosignerDocument {
    version: String,
    timestamp: Option<String>,
    #[serde(default)]
    issuers: Vec<Issuer>,
}

#[derive(Deserialize)]
struct Issuer {
    friendly_name: Option<String>,
    base_id: String,
    key_sha256: String,
    min_log_number: Option<u64>,
    #[serde(rename = "type")]
    kind: Option<String>,
}

#[durable_object]
struct CosignerRegistry {
    state: State,
}

impl std::panic::RefUnwindSafe for CosignerRegistry {}

impl DurableObject for CosignerRegistry {
    fn new(state: State, env: Env) -> Self {
        crate::init_sentry(&env);
        Self { state }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        generic_log_worker::obs::sentry::catch_unwind_report_and_flush(
            &[("handler", "do_fetch"), ("do_type", "cosigner_registry")],
            self.fetch_inner(req),
        )
        .await
    }
}

impl CosignerRegistry {
    async fn fetch_inner(&self, req: Request) -> Result<Response> {
        match req.path().as_str() {
            "/registry" => {
                let record = self
                    .state
                    .storage()
                    .get::<RegistryRecord>(REGISTRY_KEY)
                    .await?;
                Response::from_json(&record)
            }
            "/sync" => {
                let (json, pem) = futures_util::try_join!(
                    fetch_bounded(COSIGNERS_JSON_URL, MAX_JSON_BYTES),
                    fetch_bounded(COSIGNERS_PEM_URL, MAX_PEM_BYTES),
                )?;
                let record = normalize_registry(&json, &pem).map_err(Error::from)?;
                let current = self
                    .state
                    .storage()
                    .get::<RegistryRecord>(REGISTRY_KEY)
                    .await?;
                validate_replacement(current.as_ref(), &record).map_err(Error::from)?;
                let log_count = record.logs.len();
                let version = record.version.clone();
                self.state.storage().put(REGISTRY_KEY, &record).await?;
                log::info!(
                    "cosigner registry synchronized version {version} with {log_count} logs"
                );
                Response::ok("cosigner registry synchronized")
            }
            _ => Response::error("not found", 404),
        }
    }
}

async fn fetch_bounded(url: &str, limit: usize) -> Result<Vec<u8>> {
    let mut response = Fetch::Url(url.parse()?).send().await?;
    if response.status_code() != 200 {
        return Err(format!("GET {url} returned HTTP {}", response.status_code()).into());
    }
    if let Some(length) = response.headers().get("content-length")?
        && length
            .parse::<usize>()
            .map_err(|e| Error::from(format!("invalid content-length from {url}: {e}")))?
            > limit
    {
        return Err(format!("GET {url} exceeds {limit} bytes").into());
    }
    response
        .stream()?
        .try_fold(Vec::new(), |mut body, chunk| async move {
            if body.len().saturating_add(chunk.len()) > limit {
                return Err(Error::from(format!("GET {url} exceeds {limit} bytes")));
            }
            body.extend_from_slice(&chunk);
            Ok(body)
        })
        .await
}

fn normalize_registry(json: &[u8], pem: &[u8]) -> Result<RegistryRecord, String> {
    let document: CosignerDocument =
        serde_json::from_slice(json).map_err(|e| format!("cosigners JSON: {e}"))?;
    if document.version.is_empty()
        || document
            .timestamp
            .as_ref()
            .is_some_and(std::string::String::is_empty)
    {
        return Err(
            "cosigners JSON version must be non-empty and timestamp cannot be empty".to_owned(),
        );
    }
    let keys = parse_pem_keys(pem)?;
    let mut base_ids = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    let mut logs = Vec::new();
    for (index, issuer) in document.issuers.into_iter().enumerate() {
        if issuer.kind.as_deref().is_some_and(|kind| kind != "ISSUER") {
            return Err(format!("issuers[{index}].type must be ISSUER"));
        }
        if issuer.base_id.split('.').any(|arc| {
            arc.is_empty()
                || !arc.bytes().all(|byte| byte.is_ascii_digit())
                || (arc.len() > 1 && arc.starts_with('0'))
        }) {
            return Err(format!(
                "issuers[{index}].base_id is not a valid relative OID"
            ));
        }
        let oid = format!("1.3.6.1.4.1.{}", issuer.base_id);
        oid.parse::<pkcs8::ObjectIdentifier>()
            .map_err(|e| format!("issuers[{index}].base_id is invalid: {e}"))?;
        if !base_ids.insert(issuer.base_id.clone()) {
            return Err(format!("duplicate issuer base_id {:?}", issuer.base_id));
        }
        let min_log_number = issuer.min_log_number.unwrap_or(1);
        if !(1..=5).contains(&min_log_number) {
            return Err(format!(
                "issuers[{index}].min_log_number must be between 1 and 5"
            ));
        }
        if issuer.key_sha256.len() != 64
            || !issuer
                .key_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!(
                "issuers[{index}].key_sha256 must be 32 lowercase hex bytes"
            ));
        }
        let fingerprint: [u8; 32] = hex::decode(&issuer.key_sha256)
            .map_err(|e| format!("issuers[{index}].key_sha256: {e}"))?
            .try_into()
            .map_err(|_| format!("issuers[{index}].key_sha256 must be 32 bytes"))?;
        if !fingerprints.insert(fingerprint) {
            return Err(format!(
                "duplicate issuer key fingerprint {:?}",
                issuer.key_sha256
            ));
        }
        let public_key = keys
            .get(&fingerprint)
            .ok_or_else(|| format!("issuers[{index}] has no PEM key for {}", issuer.key_sha256))?;
        if Sha256::digest(public_key).as_slice() != fingerprint {
            return Err(format!(
                "issuers[{index}] PEM key does not match key_sha256 {}",
                issuer.key_sha256
            ));
        }
        let spki = SubjectPublicKeyInfoRef::try_from(public_key.as_slice())
            .map_err(|e| format!("issuers[{index}] SPKI: {e}"))?;
        if spki.algorithm.oid != ID_ML_DSA_44 || spki.algorithm.parameters.is_some() {
            return Err(format!("issuers[{index}] key is not pure ML-DSA-44"));
        }
        MlDsaVerifyingKey::<MlDsa44>::from_public_key_der(public_key)
            .map_err(|e| format!("issuers[{index}] ML-DSA-44 key: {e}"))?;
        let signer_name = format!("oid/{oid}");
        for log_number in min_log_number..=4 {
            logs.push(RegistryLog {
                description: issuer.friendly_name.clone(),
                origin: format!("{signer_name}.0.{log_number}"),
                signer_name: signer_name.clone(),
                public_key: public_key.clone(),
            });
        }
    }
    logs.sort_by(|a, b| a.origin.cmp(&b.origin));
    Ok(RegistryRecord {
        version: document.version,
        timestamp: document.timestamp,
        logs,
    })
}

fn validate_replacement(
    current: Option<&RegistryRecord>,
    candidate: &RegistryRecord,
) -> Result<(), String> {
    let Some(current) = current else {
        return Ok(());
    };
    if current.version == candidate.version && current.logs != candidate.logs {
        return Err(format!(
            "cosigner registry version {} has different normalized content",
            candidate.version
        ));
    }
    if let (Some(current), Some(candidate)) = (&current.timestamp, &candidate.timestamp)
        && let (Ok(current), Ok(candidate)) = (
            chrono::DateTime::parse_from_rfc3339(current),
            chrono::DateTime::parse_from_rfc3339(candidate),
        )
        && candidate < current
    {
        return Err("cosigner registry timestamp regressed".to_owned());
    }
    Ok(())
}

fn parse_pem_keys(pem: &[u8]) -> Result<HashMap<[u8; 32], Vec<u8>>, String> {
    let pem = std::str::from_utf8(pem).map_err(|e| format!("cosigners PEM is not UTF-8: {e}"))?;
    let begin = "-----BEGIN PUBLIC KEY-----";
    let end = "-----END PUBLIC KEY-----";
    let mut rest = pem;
    let mut keys = HashMap::new();
    while let Some(start) = rest.find(begin) {
        let fingerprint = rest[..start]
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .and_then(|line| line.trim().strip_prefix("# "))
            .ok_or_else(|| {
                "cosigners PEM public key is missing its fingerprint comment".to_owned()
            })?;
        if fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("cosigners PEM fingerprint must be 32 lowercase hex bytes".to_owned());
        }
        let fingerprint: [u8; 32] = hex::decode(fingerprint)
            .map_err(|e| format!("cosigners PEM fingerprint: {e}"))?
            .try_into()
            .map_err(|_| "cosigners PEM fingerprint must be 32 bytes".to_owned())?;
        let block_and_rest = &rest[start..];
        let finish = block_and_rest
            .find(end)
            .ok_or_else(|| "cosigners PEM has an unterminated public key".to_owned())?
            + end.len();
        let block = &block_and_rest[..finish];
        let (label, document) =
            Document::from_pem(block).map_err(|e| format!("cosigners PEM public key: {e}"))?;
        if label != "PUBLIC KEY" {
            return Err(format!("unexpected PEM label {label:?}"));
        }
        let der = document.as_bytes().to_vec();
        if keys.insert(fingerprint, der).is_some() {
            return Err("cosigners PEM contains a duplicate fingerprint".to_owned());
        }
        rest = &block_and_rest[finish..];
    }
    if keys.is_empty() {
        return Err("cosigners PEM contains no public keys".to_owned());
    }
    Ok(keys)
}

fn registry_stub(env: &Env) -> Result<Stub> {
    env.durable_object(COSIGNER_REGISTRY_BINDING)?
        .id_from_name(REGISTRY_NAME)?
        .get_stub()
}

pub(crate) async fn registry_record(env: &Env) -> Result<Option<RegistryRecord>> {
    if !CONFIG.enable_chrome_cosigners {
        return Ok(None);
    }
    let mut response = registry_stub(env)?
        .fetch_with_str("http://do/registry")
        .await?;
    if response.status_code() != 200 {
        return Err(format!(
            "cosigner registry DO returned HTTP {}",
            response.status_code()
        )
        .into());
    }
    response.json().await
}

pub(crate) async fn log_verifiers(
    env: &Env,
    origin: &str,
) -> Result<Option<signed_note::VerifierList>> {
    if let Some(keys) = crate::LOG_KEYS.get(origin) {
        return Ok(Some(log_verifiers_for_keys(keys)));
    }
    let Some(log) = registry_record(env)
        .await?
        .and_then(|record| record.logs.into_iter().find(|log| log.origin == origin))
    else {
        return Ok(None);
    };
    let name = signed_note::KeyName::new(log.signer_name)
        .map_err(|e| Error::from(format!("stored cosigner signer name: {e:?}")))?;
    let verifying_key = MlDsaVerifyingKey::<MlDsa44>::from_public_key_der(&log.public_key)
        .map_err(|e| Error::from(format!("stored cosigner key: {e}")))?;
    Ok(Some(log_verifiers_for_keys(&[LogKey::SubtreeV1 {
        name,
        verifying_key,
    }])))
}

pub(crate) fn merged_registry_logs(record: Option<RegistryRecord>) -> Vec<RegistryLog> {
    let mut logs = record.map_or_else(Vec::new, |record| record.logs);
    logs.retain(|log| {
        !CONFIG
            .logs
            .keys()
            .any(|origin| origin.as_str() == log.origin)
    });
    logs
}

pub(crate) async fn synchronize(env: &Env) -> Result<()> {
    if !CONFIG.enable_chrome_cosigners {
        return Ok(());
    }
    let mut response = registry_stub(env)?.fetch_with_str("http://do/sync").await?;
    if response.status_code() == 200 {
        return Ok(());
    }
    let status = response.status_code();
    let message = response.text().await.unwrap_or_default();
    Err(format!("cosigner registry synchronization returned HTTP {status}: {message}").into())
}

#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    crate::init_sentry(&env);
    if !CONFIG.enable_chrome_cosigners {
        return;
    }
    generic_log_worker::obs::sentry::catch_unwind_and_flush(async {
        if let Err(error) = synchronize(&env).await {
            log::error!("cosigner registry synchronization failed: {error}");
            generic_log_worker::obs::sentry::capture_error_and_flush(
                &error,
                sentry_core::Level::Error,
                &[("handler", "scheduled"), ("cron", "cosigner_registry")],
            )
            .await;
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::{RegistryRecord, merged_registry_logs, normalize_registry, validate_replacement};
    use ml_dsa::{Keypair as _, MlDsa44, SigningKey};
    use pkcs8::EncodePublicKey as _;
    use sha2::{Digest as _, Sha256};

    fn fixture(min_log_number: Option<u64>) -> (String, String, String) {
        let key = SigningKey::<MlDsa44>::from_seed(&ml_dsa::B32::from([7; 32]));
        let der = key.verifying_key().to_public_key_der().unwrap();
        let fingerprint = hex::encode(Sha256::digest(der.as_bytes()));
        let pem = key
            .verifying_key()
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .unwrap();
        let pem = format!("# {fingerprint}\n{pem}");
        let min =
            min_log_number.map_or_else(String::new, |n| format!(r#", "min_log_number": {n}"#));
        let json = format!(
            r#"{{"version":"2.0.7","timestamp":"2026-09-10T22:00:00Z","future":true,"issuers":[{{"friendly_name":"Test CA","base_id":"11129.11.99.1","type":"ISSUER","cert_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","key_sha256":"{fingerprint}"{min},"future_field":{{"x":1}}}}]}}"#
        );
        (json, pem, fingerprint)
    }

    #[test]
    fn normalizes_current_document_and_ignores_unknown_fields() {
        let (json, pem, _) = fixture(Some(2));
        let registry = normalize_registry(json.as_bytes(), pem.as_bytes()).unwrap();
        assert_eq!(registry.version, "2.0.7");
        assert_eq!(registry.logs.len(), 3);
        assert_eq!(
            registry.logs[0].signer_name,
            "oid/1.3.6.1.4.1.11129.11.99.1"
        );
        assert_eq!(registry.logs[0].origin, "oid/1.3.6.1.4.1.11129.11.99.1.0.2");
    }

    #[test]
    fn defaults_min_log_number_and_expands_through_four() {
        let (json, pem, _) = fixture(None);
        let registry = normalize_registry(json.as_bytes(), pem.as_bytes()).unwrap();
        assert_eq!(registry.logs.len(), 4);
        assert!(registry.logs[3].origin.ends_with(".0.4"));
    }

    #[test]
    fn min_log_number_above_window_generates_no_logs() {
        let (json, pem, _) = fixture(Some(5));
        assert!(
            normalize_registry(json.as_bytes(), pem.as_bytes())
                .unwrap()
                .logs
                .is_empty()
        );
    }

    #[test]
    fn rejects_min_log_number_outside_chrome_range() {
        for min in [0, 6] {
            let (json, pem, _) = fixture(Some(min));
            assert!(normalize_registry(json.as_bytes(), pem.as_bytes()).is_err());
        }
    }

    #[test]
    fn absent_timestamp_and_issuers_can_replace_with_empty_registry() {
        let (json, pem, _) = fixture(None);
        let current = normalize_registry(json.as_bytes(), pem.as_bytes()).unwrap();
        let registry = normalize_registry(br#"{"version":"2.0.8"}"#, pem.as_bytes()).unwrap();
        assert_eq!(registry.timestamp, None);
        assert!(registry.logs.is_empty());
        assert!(validate_replacement(Some(&current), &registry).is_ok());
    }

    #[test]
    fn rejects_key_hash_mismatch() {
        let (json, pem, fingerprint) = fixture(None);
        let other_key = SigningKey::<MlDsa44>::from_seed(&ml_dsa::B32::from([8; 32]));
        let other_pem = other_key
            .verifying_key()
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .unwrap();
        let mismatched_pem = format!("# {fingerprint}\n{other_pem}");
        assert!(normalize_registry(json.as_bytes(), mismatched_pem.as_bytes()).is_err());
        assert!(normalize_registry(json.as_bytes(), pem.as_bytes()).is_ok());
    }

    #[test]
    fn rejects_missing_pem() {
        let (json, _, _) = fixture(None);
        assert!(normalize_registry(json.as_bytes(), b"not a PEM").is_err());
    }

    #[test]
    fn rejects_invalid_type_and_base_id() {
        let (json, pem, _) = fixture(None);
        assert!(
            normalize_registry(json.replace("ISSUER", "MIRROR").as_bytes(), pem.as_bytes())
                .is_err()
        );
        assert!(
            normalize_registry(
                json.replace("11129.11.99.1", "01.2").as_bytes(),
                pem.as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_duplicate_base_ids_and_fingerprints() {
        let (json, pem, fingerprint) = fixture(None);
        let issuer = format!(r#"{{"base_id":"11129.11.99.1","key_sha256":"{fingerprint}"}}"#);
        let duplicate_base = json.replace("]}", &format!(",{issuer}]}}"));
        assert!(normalize_registry(duplicate_base.as_bytes(), pem.as_bytes()).is_err());
        let duplicate_key = issuer.replace("11129.11.99.1", "11129.11.99.2");
        let duplicate_key = json.replace("]}", &format!(",{duplicate_key}]}}"));
        assert!(normalize_registry(duplicate_key.as_bytes(), pem.as_bytes()).is_err());
    }

    #[test]
    fn merge_removes_dynamic_origins_present_in_static_config() {
        let static_origin = crate::CONFIG
            .logs
            .keys()
            .next()
            .unwrap()
            .as_str()
            .to_owned();
        let (_, pem, _) = fixture(None);
        let dynamic = super::RegistryLog {
            description: None,
            origin: static_origin,
            signer_name: "oid/1.3.6.1.4.1.1".to_owned(),
            public_key: pem.into_bytes(),
        };
        let logs = merged_registry_logs(Some(RegistryRecord {
            version: "1".to_owned(),
            timestamp: None,
            logs: vec![dynamic],
        }));
        assert!(logs.is_empty());
    }

    #[test]
    fn rejects_same_version_with_different_normalized_content() {
        let (json, pem, _) = fixture(None);
        let current = normalize_registry(json.as_bytes(), pem.as_bytes()).unwrap();
        let mut candidate = current.clone();
        candidate.logs.pop();
        assert!(validate_replacement(Some(&current), &candidate).is_err());
        assert!(validate_replacement(Some(&current), &current).is_ok());
    }

    #[test]
    fn rejects_parseable_timestamp_regression() {
        let current = RegistryRecord {
            version: "opaque-a".to_owned(),
            timestamp: Some("2026-09-10T22:00:00Z".to_owned()),
            logs: Vec::new(),
        };
        let candidate = RegistryRecord {
            version: "opaque-b".to_owned(),
            timestamp: Some("2026-09-09T22:00:00Z".to_owned()),
            logs: Vec::new(),
        };
        assert!(validate_replacement(Some(&current), &candidate).is_err());

        let mut opaque_timestamp = candidate;
        opaque_timestamp.timestamp = Some("not-a-timestamp".to_owned());
        assert!(validate_replacement(Some(&current), &opaque_timestamp).is_ok());
    }
}
