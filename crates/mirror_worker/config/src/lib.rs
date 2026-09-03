// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Configuration for the configurable transparency-log worker.

use ed25519_dalek::pkcs8::DecodePublicKey as _;
use ml_dsa::{MlDsa44, VerifyingKey as MlDsaVerifyingKey};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use signed_note::{Ed25519NoteVerifier, KeyName, NoteVerifier};
use std::collections::{BTreeSet, HashMap};
use tlog_cosignature::SubtreeV1NoteVerifier;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Witness,
    Mirror,
    WitnessAndMirror,
}

impl Mode {
    #[must_use]
    pub const fn witness_enabled(self) -> bool {
        matches!(self, Self::Witness | Self::WitnessAndMirror)
    }

    #[must_use]
    pub const fn mirror_enabled(self) -> bool {
        matches!(self, Self::Mirror | Self::WitnessAndMirror)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Witness => "witness",
            Self::Mirror => "mirror",
            Self::WitnessAndMirror => "witness-and-mirror",
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub mode: Mode,
    pub logging_level: Option<String>,
    pub submission_prefix: String,
    pub monitoring_prefix: Option<String>,
    pub witness: Option<IdentityConfig>,
    pub mirror: Option<MirrorConfig>,
    #[serde(deserialize_with = "deserialize_logs")]
    pub logs: HashMap<String, LogParams>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct MirrorConfig {
    pub name: String,
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

fn deserialize_logs<'de, D>(deserializer: D) -> Result<HashMap<String, LogParams>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct LogsVisitor;

    impl<'de> serde::de::Visitor<'de> for LogsVisitor {
        type Value = HashMap<String, LogParams>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a map of checkpoint origin to log parameters")
        }

        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut logs = HashMap::with_capacity(access.size_hint().unwrap_or(0));
            while let Some((origin, params)) = access.next_entry::<String, LogParams>()? {
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
        self.mode.witness_enabled()
    }

    #[must_use]
    pub const fn mirror_enabled(&self) -> bool {
        self.mode.mirror_enabled()
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

    /// Validate mode-specific identities, signed-note names, algorithms, and keys.
    ///
    /// # Errors
    ///
    /// Returns an operator-readable description of the invalid field.
    pub fn validate(&self) -> Result<(), String> {
        if self.witness_enabled() != self.witness.is_some() {
            return Err(format!(
                "mode {} requires witness configuration iff witness is enabled",
                self.mode.as_str()
            ));
        }
        if self.mirror_enabled() != self.mirror.is_some() {
            return Err(format!(
                "mode {} requires mirror configuration iff mirror is enabled",
                self.mode.as_str()
            ));
        }
        if let Some(identity) = &self.witness {
            validate_identity_name("witness.name", &identity.name)?;
        }
        if let Some(identity) = &self.mirror {
            validate_identity_name("mirror.name", &identity.name)?;
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

fn validate_identity_name(field: &str, name: &str) -> Result<(), String> {
    KeyName::new(name.to_owned())
        .map(|_| ())
        .map_err(|e| format!("{field} {name:?} is not a valid signed-note key name: {e:?}"))
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
    pub name: String,
    pub algorithm: CheckpointAlgorithm,
    #[serde_as(as = "Base64")]
    pub public_key: Vec<u8>,
}

impl LogParams {
    fn validate(&self, origin: &str) -> Result<(), String> {
        validate_identity_name(&format!("log {origin:?} origin"), origin)?;
        if self.checkpoint_signers.is_empty() {
            return Err(format!(
                "log {origin:?}: checkpoint_signers must not be empty"
            ));
        }
        let mut seen = BTreeSet::new();
        for (i, signer) in self.checkpoint_signers.iter().enumerate() {
            let name = KeyName::new(signer.name.clone()).map_err(|e| {
                format!(
                    "log {origin:?}: checkpoint_signers[{i}].name is not a valid signed-note key name: {e:?}"
                )
            })?;
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

    fn config(mode: Mode, witness: bool, mirror: bool) -> AppConfig {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .to_vec();
        AppConfig {
            mode,
            logging_level: None,
            submission_prefix: "https://submit.example/".to_owned(),
            monitoring_prefix: Some("https://monitor.example/".to_owned()),
            witness: witness.then(|| IdentityConfig {
                name: "witness.example".to_owned(),
                description: None,
            }),
            mirror: mirror.then(|| MirrorConfig {
                name: "mirror.example".to_owned(),
                description: None,
                clean_interval_secs: None,
                commit_packages: None,
                max_chunk_bytes: None,
            }),
            logs: HashMap::from([(
                "log.example".to_owned(),
                LogParams {
                    description: None,
                    checkpoint_signers: vec![CheckpointSigner {
                        name: "log.example".to_owned(),
                        algorithm: CheckpointAlgorithm::Ed25519,
                        public_key: key,
                    }],
                },
            )]),
        }
    }

    #[test]
    fn accepts_all_three_modes() {
        config(Mode::Witness, true, false).validate().unwrap();
        config(Mode::Mirror, false, true).validate().unwrap();
        config(Mode::WitnessAndMirror, true, true)
            .validate()
            .unwrap();
    }

    #[test]
    fn rejects_missing_or_disabled_identity_sections() {
        assert!(config(Mode::Witness, false, false).validate().is_err());
        assert!(config(Mode::Witness, true, true).validate().is_err());
        assert!(config(Mode::Mirror, false, false).validate().is_err());
        assert!(config(Mode::Mirror, true, true).validate().is_err());
        assert!(
            config(Mode::WitnessAndMirror, true, false)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn rejects_unknown_mode() {
        let error = serde_json::from_str::<Mode>(r#""witness-mirror""#).unwrap_err();
        assert!(error.to_string().contains("unknown variant"));
    }

    #[test]
    fn mode_serde_spelling_is_stable() {
        assert_eq!(
            serde_json::to_string(&Mode::Witness).unwrap(),
            r#""witness""#
        );
        assert_eq!(serde_json::to_string(&Mode::Mirror).unwrap(), r#""mirror""#);
        assert_eq!(
            serde_json::to_string(&Mode::WitnessAndMirror).unwrap(),
            r#""witness-and-mirror""#
        );
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
        let mut config = config(Mode::Witness, true, false);
        config
            .logs
            .get_mut("log.example")
            .unwrap()
            .checkpoint_signers
            .push(CheckpointSigner {
                name: "log.example/post-quantum".to_owned(),
                algorithm: CheckpointAlgorithm::SubtreeV1,
                public_key: ml_dsa_spki(9),
            });
        config.validate().unwrap();
    }

    #[test]
    fn rejects_algorithm_key_mismatch() {
        let mut wrong_ml = config(Mode::Witness, true, false);
        let signer = &mut wrong_ml
            .logs
            .get_mut("log.example")
            .unwrap()
            .checkpoint_signers[0];
        signer.algorithm = CheckpointAlgorithm::SubtreeV1;
        assert!(wrong_ml.validate().unwrap_err().contains("ML-DSA-44 SPKI"));

        let mut wrong_ed = config(Mode::Witness, true, false);
        let signer = &mut wrong_ed
            .logs
            .get_mut("log.example")
            .unwrap()
            .checkpoint_signers[0];
        signer.public_key = ml_dsa_spki(10);
        assert!(wrong_ed.validate().unwrap_err().contains("Ed25519 SPKI"));
    }

    #[test]
    fn rejects_malformed_spki() {
        let mut config = config(Mode::Witness, true, false);
        config
            .logs
            .get_mut("log.example")
            .unwrap()
            .checkpoint_signers[0]
            .public_key = b"not DER".to_vec();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_signer_id() {
        let mut config = config(Mode::Witness, true, false);
        let log = config.logs.get_mut("log.example").unwrap();
        log.checkpoint_signers.push(CheckpointSigner {
            name: log.checkpoint_signers[0].name.clone(),
            algorithm: log.checkpoint_signers[0].algorithm,
            public_key: log.checkpoint_signers[0].public_key.clone(),
        });
        assert!(config.validate().unwrap_err().contains("duplicates"));
    }

    #[test]
    fn combined_mode_requires_distinct_identity_names() {
        let mut config = config(Mode::WitnessAndMirror, true, true);
        config.mirror.as_mut().unwrap().name = config.witness.as_ref().unwrap().name.clone();
        assert!(config.validate().unwrap_err().contains("must be distinct"));
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
