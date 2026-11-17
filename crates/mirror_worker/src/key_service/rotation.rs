// Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Operator-initiated key service rotation through a dedicated Cloudflare Queue.
//! The Queue is populated with an account-scoped API token or the dashboard;
//! there is no public rotation endpoint or Workflow entrypoint.

use super::{State, TicketVersionState, VersionState, keyring};
use crate::key_service::{KeyName, KeyServiceError, SigningKeyName};
use serde::Deserialize;
use std::num::NonZeroU32;
use worker::{Context, Env, MessageBatch, event};

#[derive(Clone, Copy, Deserialize, Debug, PartialEq, Eq)]
enum SigningAlgorithm {
    #[serde(rename = "ED25519")]
    Ed25519,
    #[serde(rename = "ML_DSA_44")]
    MlDsa44,
}

impl SigningAlgorithm {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ED25519",
            Self::MlDsa44 => "ML_DSA_44",
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "lowercase", deny_unknown_fields)]
enum RotationRequest {
    Rotate {
        role: Role,
        expected_default_version: NonZeroU32,
    },
    Retire {
        role: Role,
        version: NonZeroU32,
    },
    Create {
        role: Role,
        algorithm: Option<SigningAlgorithm>,
    },
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Role {
    Mirror,
    Witness,
    Ticket,
}

fn key_name(role: Role) -> KeyName {
    match role {
        Role::Ticket => KeyName::Ticket,
        Role::Mirror => KeyName::SigningKey(SigningKeyName::Mirror),
        Role::Witness => KeyName::SigningKey(SigningKeyName::Witness),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RotationDecision {
    Create,
    AlreadyAdvanced,
}

fn decide_rotation(
    expected: NonZeroU32,
    current: NonZeroU32,
    versions: &[VersionState],
) -> Result<RotationDecision, worker::Error> {
    if current != expected {
        return Ok(RotationDecision::AlreadyAdvanced);
    }
    if versions.last().map(|version| version.number) != Some(current) {
        return Err(worker::Error::from(
            "key service has a newer version that is not the default; inspect before retrying rotation",
        ));
    }
    if !versions
        .iter()
        .any(|version| version.number == current && version.signing)
    {
        return Err(worker::Error::from(
            "key service default version cannot sign",
        ));
    }
    Ok(RotationDecision::Create)
}

async fn create(
    env: &Env,
    role: Role,
    algorithm: Option<SigningAlgorithm>,
) -> Result<(), KeyServiceError> {
    let name = key_name(role);
    let ring = keyring(env)?;
    match key_name(role) {
        KeyName::Ticket => {
            if algorithm.is_some() {
                return Err(
                    worker::Error::from("ticket key rotation does not take an algorithm").into(),
                );
            }
            create_ticket(env).await?
        }
        KeyName::SigningKey(k) => {
            let algorithm = algorithm.ok_or_else(|| {
                worker::Error::from("initial signing key rotation requires algorithm")
            })?;
            if ring.signing_key_exists(k).await? {
                // A repeated initial request must not create a second version.
                ring.current_default(k).await?;
                ring.key_versions(k).await?;
                log::info!("key service signing key {name} already exists");
            } else {
                ring.create_signing_key(k, algorithm.as_str()).await?;
                log::info!(
                    "created key service signing key {name} using {}",
                    algorithm.as_str()
                );
            }
        }
    }
    Ok(())
}

async fn rotate(
    env: &Env,
    role: Role,
    expected_default_version: NonZeroU32,
) -> Result<(), KeyServiceError> {
    let name = key_name(role);
    let ring = keyring(env)?;
    match key_name(role) {
        KeyName::Ticket => {
            rotate_ticket(env, expected_default_version).await?;
        }
        KeyName::SigningKey(k) => {
            let current = ring.current_default(k).await?;
            let versions = ring.key_versions(k).await?;
            match decide_rotation(expected_default_version, current, &versions)? {
                RotationDecision::AlreadyAdvanced => {
                    log::warn!(
                        "key service rotation for {name} ignored: expected default {}, found {current}",
                        expected_default_version
                    );
                    return Ok(());
                }
                RotationDecision::Create => {}
            }

            let new_version = ring.new_signing_version(k).await?;
            ring.promote(k, new_version).await?;
            log::info!("key service rotation for {name}: default {current} -> {new_version}");
        }
    }
    Ok(())
}

async fn create_ticket(env: &Env) -> Result<(), KeyServiceError> {
    let ring = keyring(env)?;
    // Idempotent Queue redelivery.
    match ring.ticket_versions().await {
        Err(KeyServiceError::KeyNotFound) => {
            ring.create_ticket_key().await?;
            log::info!("created key service ticket key {}", KeyName::Ticket);
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum TicketRotationDecision {
    Create,
    PromoteExisting(NonZeroU32),
    AlreadyAdvanced,
}

fn decide_ticket_rotation(
    expected: NonZeroU32,
    current: NonZeroU32,
    versions: &[TicketVersionState],
) -> Result<TicketRotationDecision, worker::Error> {
    if current != expected {
        return Ok(TicketRotationDecision::AlreadyAdvanced);
    }
    let latest = versions
        .last()
        .filter(|state| state.state == State::EncryptDecrypt)
        .ok_or_else(|| worker::Error::from("ticket key has no usable newest version"))?;
    if latest.number == current {
        return Ok(TicketRotationDecision::Create);
    }
    if current.checked_add(1) == Some(latest.number) {
        return Ok(TicketRotationDecision::PromoteExisting(latest.number));
    }
    Err(worker::Error::from(
        "ticket key has an unexpected newer version; inspect rotation",
    ))
}

async fn rotate_ticket(env: &Env, expected: NonZeroU32) -> Result<(), KeyServiceError> {
    let ring = keyring(env)?;
    let current = ring.current_ticket_default().await?;
    let versions = ring.ticket_versions().await?;
    let version = match decide_ticket_rotation(expected, current, &versions)? {
        TicketRotationDecision::AlreadyAdvanced => {
            log::warn!("ticket key rotation ignored: expected default {expected}, found {current}");
            return Ok(());
        }
        TicketRotationDecision::Create => ring.new_ticket_version().await?,
        TicketRotationDecision::PromoteExisting(version) => version,
    };
    ring.promote(KeyName::Ticket, version).await?;
    log::info!("ticket key rotated: default {current} -> {version}");
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum RetirementDecision {
    Retire,
    AlreadyRetired,
}

fn decide_retirement(
    version: NonZeroU32,
    current: NonZeroU32,
    versions: &[VersionState],
) -> Result<RetirementDecision, worker::Error> {
    if !versions
        .iter()
        .any(|state| state.number == current && state.signing)
    {
        return Err(worker::Error::from(
            "key service default version cannot sign",
        ));
    }
    if version == current {
        return Err(worker::Error::from(
            "cannot retire the key service default version",
        ));
    }
    let target = versions
        .iter()
        .find(|state| state.number == version)
        .ok_or_else(|| {
            worker::Error::from(format!("key service version {version} does not exist"))
        })?;
    if !target.signing {
        return Ok(RetirementDecision::AlreadyRetired);
    }
    if versions.iter().filter(|state| state.signing).count() <= 1 {
        return Err(worker::Error::from(
            "cannot retire the last signing version",
        ));
    }
    Ok(RetirementDecision::Retire)
}

async fn retire(env: &Env, role: Role, version: NonZeroU32) -> Result<(), KeyServiceError> {
    match key_name(role) {
        KeyName::Ticket => retire_ticket(env, version).await,
        KeyName::SigningKey(k) => {
            let ring = keyring(env)?;
            let current = ring.current_default(k).await?;
            let versions = ring.key_versions(k).await?;
            match decide_retirement(version, current, &versions)? {
                RetirementDecision::AlreadyRetired => {
                    log::info!("key service key {k} version {version} already retired",);
                    Ok(())
                }
                RetirementDecision::Retire => {
                    ring.retire(k, version).await?;
                    log::info!("key service key {k} version {version} retired");
                    Ok(())
                }
            }
        }
    }
}

fn decide_ticket_retirement(
    version: NonZeroU32,
    current: NonZeroU32,
    versions: &[TicketVersionState],
) -> Result<RetirementDecision, worker::Error> {
    if !versions
        .last()
        .is_some_and(|state| state.number == current && state.state == State::EncryptDecrypt)
    {
        return Err(worker::Error::from(
            "ticket key default is not the newest usable version",
        ));
    }
    let target = versions
        .iter()
        .find(|state| state.number == version)
        .ok_or_else(|| {
            worker::Error::from(format!("ticket key version {version} does not exist"))
        })?;
    if target.state == State::Retired {
        return Ok(RetirementDecision::AlreadyRetired);
    }
    if version == current {
        return Err(worker::Error::from(
            "cannot retire the current ticket key version",
        ));
    }
    if versions
        .iter()
        .find(|state| state.state != State::Retired)
        .map(|state| state.number)
        != Some(version)
    {
        return Err(worker::Error::from(
            "only the oldest decrypting ticket key version may be retired",
        ));
    }
    Ok(RetirementDecision::Retire)
}

async fn retire_ticket(env: &Env, version: NonZeroU32) -> Result<(), KeyServiceError> {
    let ring = keyring(env)?;
    let current = ring.current_ticket_default().await?;
    let versions = ring.ticket_versions().await?;
    match decide_ticket_retirement(version, current, &versions)? {
        RetirementDecision::AlreadyRetired => {
            log::info!("ticket key version {version} already retired");
        }
        RetirementDecision::Retire => {
            ring.retire_ticket_version(version).await?;
            log::info!("ticket key version {version} retired");
        }
    }
    Ok(())
}

/// Only the Queue consumer invokes rotation or retirement; no fetch route or cron does.
#[event(queue)]
async fn rotation_queue(
    batch: MessageBatch<RotationRequest>,
    env: Env,
    _ctx: Context,
) -> Result<(), worker::Error> {
    crate::init_sentry(&env);
    for message in batch.messages()? {
        let result = match message.body() {
            RotationRequest::Rotate {
                role,
                expected_default_version,
            } => rotate(&env, *role, *expected_default_version).await,
            RotationRequest::Retire { role, version } => retire(&env, *role, *version).await,
            RotationRequest::Create { role, algorithm } => create(&env, *role, *algorithm).await,
        };
        if let Err(e) = result {
            return Err(worker::Error::from(e.to_string()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        RetirementDecision, Role, RotationDecision, RotationRequest, State, TicketRotationDecision,
        TicketVersionState, VersionState, decide_retirement, decide_rotation,
        decide_ticket_retirement, decide_ticket_rotation,
    };
    use std::num::NonZeroU32;

    fn n(x: u32) -> NonZeroU32 {
        NonZeroU32::new(x).unwrap()
    }

    fn states(values: &[(u32, bool)]) -> Vec<VersionState> {
        values
            .iter()
            .map(|&(number, signing)| VersionState {
                number: n(number),
                signing,
            })
            .collect()
    }

    #[test]
    fn creation_and_rotation_messages_require_their_own_fields() {
        let request: RotationRequest = serde_json::from_str(
            r#"{"action":"rotate","role":"mirror","expected_default_version":1}"#,
        )
        .unwrap();
        assert!(matches!(
            request,
            RotationRequest::Rotate {
                role: Role::Mirror,
                expected_default_version,
            }
            if expected_default_version == n(1)));
        let initial: RotationRequest =
            serde_json::from_str(r#"{"action":"create","role":"mirror","algorithm":"ML_DSA_44"}"#)
                .unwrap();
        assert!(matches!(
            initial,
            RotationRequest::Create {
                role: Role::Mirror,
                algorithm: Some(super::SigningAlgorithm::MlDsa44)
            }
        ));
        let ed25519: RotationRequest =
            serde_json::from_str(r#"{"action":"create","role":"witness","algorithm":"ED25519"}"#)
                .unwrap();
        assert!(matches!(
            ed25519,
            RotationRequest::Create {
                algorithm: Some(super::SigningAlgorithm::Ed25519),
                role: Role::Witness,
            }
        ));
        assert!(
            serde_json::from_str::<RotationRequest>(
                r#"{"action":"create","role":"mirror","algorithm":"AES_256_GCM"}"#
            )
            .is_err()
        );
        for message in [
            r#"{"action":"rotate","role":"mirror"}"#,
            r#"{"action":"rotate","role":"mirror","expected_default_version":0}"#,
            r#"{"action":"rotate","role":"mirror","expected_default_version":1,"algorithm":"ML_DSA_44"}"#,
            r#"{"action":"create","role":"mirror","algorithm":"ML_DSA_44","expected_default_version":1}"#,
            r#"{"action":"rotate","role":"other","expected_default_version":1}"#,
            r#"{"role":"mirror","expected_default_version":1}"#,
            r#"{"action":"rotate","role":"mirror","expected_default_version":1,"version":2}"#,
        ] {
            assert!(
                serde_json::from_str::<RotationRequest>(message).is_err(),
                "{message:?}"
            );
        }
    }

    #[test]
    fn retirement_message_requires_action_role_and_version() {
        let request: RotationRequest =
            serde_json::from_str(r#"{"action":"retire","role":"witness","version":2}"#).unwrap();
        let RotationRequest::Retire { role, version } = request else {
            panic!("expected retirement request");
        };
        assert!(matches!(role, Role::Witness));
        assert_eq!(version, n(2));
        for message in [
            r#"{"action":"retire","role":"witness"}"#,
            r#"{"action":"delete","role":"witness","version":2}"#,
            r#"{"action":"retire","role":"other","version":2}"#,
            r#"{"action":"retire","role":"witness","version":2,"extra":true}"#,
            r#"{"action":"retire","role":"witness","version":0}"#,
        ] {
            assert!(serde_json::from_str::<RotationRequest>(message).is_err());
        }
    }

    #[test]
    fn rotate_only_from_expected_latest_default() {
        assert_eq!(
            decide_rotation(n(2), n(2), &states(&[(1, true), (2, true)])).unwrap(),
            RotationDecision::Create
        );
        assert_eq!(
            decide_rotation(n(2), n(3), &states(&[(1, false), (2, true), (3, true)])).unwrap(),
            RotationDecision::AlreadyAdvanced
        );
        assert!(decide_rotation(n(2), n(2), &states(&[(1, true), (2, true), (3, true)])).is_err());
        assert!(decide_rotation(n(2), n(2), &states(&[(1, true), (2, false)])).is_err());
    }

    #[test]
    fn retirement_requires_a_non_default_signing_version() {
        let versions = states(&[(1, true), (2, true), (3, false)]);
        assert_eq!(
            decide_retirement(n(1), n(2), &versions).unwrap(),
            RetirementDecision::Retire
        );
        assert_eq!(
            decide_retirement(n(3), n(2), &versions).unwrap(),
            RetirementDecision::AlreadyRetired
        );
        assert!(decide_retirement(n(2), n(2), &versions).is_err());
        assert!(decide_retirement(n(4), n(2), &versions).is_err());
        assert!(decide_retirement(n(1), n(2), &states(&[(1, true), (2, false)])).is_err());
        assert!(decide_retirement(n(1), n(2), &states(&[(1, false), (2, true)])).is_ok());
    }

    #[test]
    fn ticket_operator_messages_are_explicit() {
        assert!(matches!(
            serde_json::from_str::<RotationRequest>(r#"{"action":"create","role":"ticket"}"#)
                .unwrap(),
            RotationRequest::Create {
                role: Role::Ticket,
                algorithm: None
            }
        ));
        let rotate: RotationRequest = serde_json::from_str(
            r#"{"action":"rotate","role":"ticket","expected_default_version":2}"#,
        )
        .unwrap();
        assert!(matches!(
            rotate,
            RotationRequest::Rotate {
                role: Role::Ticket,
                expected_default_version,
            }
            if expected_default_version == n(2)
        ));
        assert!(matches!(
            serde_json::from_str::<RotationRequest>(
                r#"{"action":"retire","role":"ticket","version":1}"#
            )
            .unwrap(),
            RotationRequest::Retire { .. }
        ));
        for message in [
            r#"{"action":"rotate","role":"ticket"}"#,
            r#"{"action":"create","role":"ticket","expected_default_version":1}"#,
            r#"{"action":"rotate","role":"ticket","version":1}"#,
            r#"{"action":"retire","role":"ticket"}"#,
            r#"{"action":"retire","role":"ticket","expected_default_version":0}"#,
        ] {
            assert!(
                serde_json::from_str::<RotationRequest>(message).is_err(),
                "{message:?}"
            );
        }
    }

    #[test]
    fn ticket_rotation_and_oldest_retirement_are_retry_safe() {
        let states = |values: &[(u32, bool)]| {
            values
                .iter()
                .map(|&(number, decrypting)| {
                    TicketVersionState::new(
                        n(number),
                        if decrypting {
                            State::EncryptDecrypt
                        } else {
                            State::Retired
                        },
                    )
                })
                .collect::<Vec<_>>()
        };
        let versions = states(&[(1, true), (2, true), (3, true)]);
        assert_eq!(
            decide_ticket_rotation(n(3), n(3), &versions).unwrap(),
            TicketRotationDecision::Create
        );
        assert_eq!(
            decide_ticket_rotation(n(2), n(3), &versions).unwrap(),
            TicketRotationDecision::AlreadyAdvanced
        );
        assert_eq!(
            decide_ticket_rotation(n(2), n(2), &versions).unwrap(),
            TicketRotationDecision::PromoteExisting(n(3))
        );
        assert!(decide_ticket_rotation(n(1), n(1), &versions).is_err());
        assert_eq!(
            decide_ticket_retirement(n(1), n(3), &versions).unwrap(),
            RetirementDecision::Retire
        );
        assert!(decide_ticket_retirement(n(2), n(3), &versions).is_err());
        assert!(decide_ticket_retirement(n(3), n(3), &versions).is_err());
        let retired = states(&[(1, false), (2, true), (3, true)]);
        assert_eq!(
            decide_ticket_retirement(n(1), n(3), &retired).unwrap(),
            RetirementDecision::AlreadyRetired
        );
        assert_eq!(
            decide_ticket_retirement(n(2), n(3), &retired).unwrap(),
            RetirementDecision::Retire
        );
        let decrypt_only = vec![
            TicketVersionState::new(n(1), State::Decrypt),
            TicketVersionState::new(n(2), State::EncryptDecrypt),
        ];
        assert_eq!(
            decide_ticket_retirement(n(1), n(2), &decrypt_only).unwrap(),
            RetirementDecision::Retire
        );
        assert!(decide_ticket_retirement(n(2), n(2), &states(&[(1, false), (2, true)])).is_err());
    }
}
