// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Configuration for the configurable transparency-log worker.

use ed25519_dalek::pkcs8::DecodePublicKey as _;
use ml_dsa::{MlDsa44, VerifyingKey as MlDsaVerifyingKey};
use serde::{Deserialize, Serialize, de::Error as _};
use serde_with::{base64::Base64, serde_as};
use signed_note::{Ed25519NoteVerifier, KeyName, NoteVerifier};
use std::collections::{BTreeSet, HashMap};
use tlog_cosignature::SubtreeV1NoteVerifier;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub logging_level: Option<String>,
    pub submission_prefix: String,
    pub monitoring_prefix: Option<String>,
    pub witness: Option<IdentityConfig>,
    pub mirror: Option<MirrorConfig>,
    #[serde(deserialize_with = "deserialize_logs")]
    pub logs: HashMap<KeyName, LogParams>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    #[serde(deserialize_with = "deserialize_key_name")]
    pub name: KeyName,
    pub description: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct MirrorConfig {
    #[serde(deserialize_with = "deserialize_key_name")]
    pub name: KeyName,
    pub description: Option<String>,
    pub clean_interval_secs: Option<u64>,
    pub commit_packages: Option<u64>,
    pub max_chunk_bytes: Option<u64>,
}

impl MirrorConfig {
    #[must_use]
    pub fn clean_interval_secs(&self) -> u64 {
        self.clean_interval_secs.unwrap_or(3600)
    }

    #[must_use]
    pub fn commit_packages(&self) -> u64 {
        self.commit_packages.unwrap_or(32)
    }

    #[must_use]
    pub fn max_chunk_bytes(&self) -> u64 {
        self.max_chunk_bytes.unwrap_or(16 * 1024 * 1024)
    }
}

fn deserialize_key_name<'de, D>(deserializer: D) -> Result<KeyName, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let name = String::deserialize(deserializer)?;
    KeyName::new(name).map_err(D::Error::custom)
}

fn deserialize_logs<'de, D>(deserializer: D) -> Result<HashMap<KeyName, LogParams>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct LogsVisitor;

    impl<'de> serde::de::Visitor<'de> for LogsVisitor {
        type Value = HashMap<KeyName, LogParams>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a map of checkpoint origin to log parameters")
        }

        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut logs = HashMap::with_capacity(access.size_hint().unwrap_or(0));
            while let Some((origin, params)) = access.next_entry::<String, LogParams>()? {
                let origin = KeyName::new(origin).map_err(serde::de::Error::custom)?;
                if logs.contains_key(&origin) {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate checkpoint origin {origin:?} in logs"
                    )));
                }
                logs.insert(origin, params);
            }
            Ok(logs)
        }
    }

    deserializer.deserialize_map(LogsVisitor)
}

impl AppConfig {
    #[must_use]
    pub const fn witness_enabled(&self) -> bool {
        self.witness.is_some()
    }

    #[must_use]
    pub const fn mirror_enabled(&self) -> bool {
        self.mirror.is_some()
    }

    #[must_use]
    pub const fn mode(&self) -> &'static str {
        match (self.witness_enabled(), self.mirror_enabled()) {
            (true, true) => "witness-and-mirror",
            (true, false) => "witness",
            (false, true) => "mirror",
            (false, false) => "disabled",
        }
    }

    #[must_use]
    /// Return the mirror settings for a validated mirror-enabled config.
    ///
    /// # Panics
    ///
    /// Panics if mirror configuration is absent.
    pub fn mirror_config(&self) -> &MirrorConfig {
        self.mirror
            .as_ref()
            .expect("validated mirror mode must have mirror config")
    }

    /// Validate role configuration, algorithms, and keys.
    ///
    /// # Errors
    ///
    /// Returns an operator-readable description of the invalid field.
    pub fn validate(&self) -> Result<(), String> {
        if !self.witness_enabled() && !self.mirror_enabled() {
            return Err("at least one of witness or mirror must be configured".to_owned());
        }
        if let (Some(witness), Some(mirror)) = (&self.witness, &self.mirror)
            && witness.name == mirror.name
        {
            return Err("witness.name and mirror.name must be distinct".to_owned());
        }
        for (origin, log) in &self.logs {
            log.validate(origin)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CheckpointAlgorithm {
    #[serde(rename = "ed25519")]
    Ed25519,
    #[serde(rename = "subtree/v1")]
    SubtreeV1,
}

impl CheckpointAlgorithm {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::SubtreeV1 => "subtree/v1",
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct LogParams {
    pub description: Option<String>,
    pub checkpoint_signers: Vec<CheckpointSigner>,
}

#[serde_as]
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CheckpointSigner {
    #[serde(deserialize_with = "deserialize_key_name")]
    pub name: KeyName,
    pub algorithm: CheckpointAlgorithm,
    #[serde_as(as = "Base64")]
    pub public_key: Vec<u8>,
}

impl LogParams {
    fn validate(&self, origin: &KeyName) -> Result<(), String> {
        if self.checkpoint_signers.is_empty() {
            return Err(format!(
                "log {origin:?}: checkpoint_signers must not be empty"
            ));
        }
        let mut seen = BTreeSet::new();
        for (i, signer) in self.checkpoint_signers.iter().enumerate() {
            let name = signer.name.clone();
            let key_id = match signer.algorithm {
                CheckpointAlgorithm::Ed25519 => {
                    let key = ed25519_dalek::VerifyingKey::from_public_key_der(&signer.public_key)
                        .map_err(|e| {
                            format!(
                                "log {origin:?}: checkpoint_signers[{i}].public_key is not an Ed25519 SPKI: {e}"
                            )
                        })?;
                    Ed25519NoteVerifier::new(name.clone(), key).key_id()
                }
                CheckpointAlgorithm::SubtreeV1 => {
                    let key = MlDsaVerifyingKey::<MlDsa44>::from_public_key_der(&signer.public_key)
                        .map_err(|e| {
                            format!(
                                "log {origin:?}: checkpoint_signers[{i}].public_key is not an ML-DSA-44 SPKI: {e}"
                            )
                        })?;
                    SubtreeV1NoteVerifier::new(name.clone(), key).key_id()
                }
            };
            if !seen.insert((name, key_id)) {
                return Err(format!(
                    "log {origin:?}: checkpoint_signers[{i}] duplicates an earlier (name, key_id)"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::EncodePublicKey as _;
    use ml_dsa::{Keypair as _, SigningKey};

    fn key_name(name: &str) -> KeyName {
        KeyName::new(name.to_owned()).unwrap()
    }

    fn config(witness: bool, mirror: bool) -> AppConfig {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .to_vec();
        AppConfig {
            logging_level: None,
            submission_prefix: "https://submit.example/".to_owned(),
            monitoring_prefix: Some("https://monitor.example/".to_owned()),
            witness: witness.then(|| IdentityConfig {
                name: key_name("witness.example"),
                description: None,
            }),
            mirror: mirror.then(|| MirrorConfig {
                name: key_name("mirror.example"),
                description: None,
                clean_interval_secs: None,
                commit_packages: None,
                max_chunk_bytes: None,
            }),
            logs: HashMap::from([(
                key_name("log.example"),
                LogParams {
                    description: None,
                    checkpoint_signers: vec![CheckpointSigner {
                        name: key_name("log.example"),
                        algorithm: CheckpointAlgorithm::Ed25519,
                        public_key: key,
                    }],
                },
            )]),
        }
    }

    #[test]
    fn accepts_all_three_modes() {
        config(true, false).validate().unwrap();
        config(false, true).validate().unwrap();
        config(true, true).validate().unwrap();
    }

    #[test]
    fn rejects_disabled_config() {
        assert!(config(false, false).validate().is_err());
    }

    #[test]
    fn derives_mode_from_role_sections() {
        assert_eq!(config(true, false).mode(), "witness");
        assert_eq!(config(false, true).mode(), "mirror");
        assert_eq!(config(true, true).mode(), "witness-and-mirror");
    }

    fn ml_dsa_spki(seed: u8) -> Vec<u8> {
        SigningKey::<MlDsa44>::from_seed(&ml_dsa::B32::from([seed; 32]))
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .to_vec()
    }

    #[test]
    fn accepts_ml_dsa_spki_and_mixed_algorithms() {
        let mut config = config(true, false);
        config
            .logs
            .get_mut(&key_name("log.example"))
            .unwrap()
            .checkpoint_signers
            .push(CheckpointSigner {
                name: key_name("log.example/post-quantum"),
                algorithm: CheckpointAlgorithm::SubtreeV1,
                public_key: ml_dsa_spki(9),
            });
        config.validate().unwrap();
    }

    #[test]
    fn rejects_algorithm_key_mismatch() {
        let mut wrong_ml = config(true, false);
        let signer = &mut wrong_ml
            .logs
            .get_mut(&key_name("log.example"))
            .unwrap()
            .checkpoint_signers[0];
        signer.algorithm = CheckpointAlgorithm::SubtreeV1;
        assert!(wrong_ml.validate().unwrap_err().contains("ML-DSA-44 SPKI"));

        let mut wrong_ed = config(true, false);
        let signer = &mut wrong_ed
            .logs
            .get_mut(&key_name("log.example"))
            .unwrap()
            .checkpoint_signers[0];
        signer.public_key = ml_dsa_spki(10);
        assert!(wrong_ed.validate().unwrap_err().contains("Ed25519 SPKI"));
    }

    #[test]
    fn rejects_malformed_spki() {
        let mut config = config(true, false);
        config
            .logs
            .get_mut(&key_name("log.example"))
            .unwrap()
            .checkpoint_signers[0]
            .public_key = b"not DER".to_vec();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_signer_id() {
        let mut config = config(true, false);
        let log = config.logs.get_mut(&key_name("log.example")).unwrap();
        log.checkpoint_signers.push(CheckpointSigner {
            name: log.checkpoint_signers[0].name.clone(),
            algorithm: log.checkpoint_signers[0].algorithm,
            public_key: log.checkpoint_signers[0].public_key.clone(),
        });
        assert!(config.validate().unwrap_err().contains("duplicates"));
    }

    #[test]
    fn combined_mode_requires_distinct_identity_names() {
        let mut config = config(true, true);
        config.mirror.as_mut().unwrap().name = config.witness.as_ref().unwrap().name.clone();
        assert!(config.validate().unwrap_err().contains("must be distinct"));
    }

    #[test]
    fn invalid_key_names_fail_deserialization() {
        let fixture = include_str!("../../config.witness.json");
        for invalid in [
            fixture.replace("dev.witness.example", "invalid witness"),
            fixture.replace("\"example.com/witness-log\":", "\"invalid origin\":"),
            fixture.replace(
                "\"name\": \"example.com/witness-log\"",
                "\"name\": \"invalid signer\"",
            ),
        ] {
            assert!(serde_json::from_str::<AppConfig>(&invalid).is_err());
        }
    }

    #[test]
    fn standalone_config_fixtures_validate() {
        for fixture in [
            include_str!("../../config.witness.json"),
            include_str!("../../config.mirror.json"),
        ] {
            serde_json::from_str::<AppConfig>(fixture)
                .unwrap()
                .validate()
                .unwrap();
        }
    }
}
