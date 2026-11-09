// Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Operator-initiated key service rotation through a dedicated Cloudflare Queue.
//! The Queue is populated with an account-scoped API token or the dashboard;
//! there is no public rotation endpoint or Workflow entrypoint.

use super::{State, TICKET_KEY_NAME, TicketVersionState, VersionState, keyring};
use crate::{MIRROR_KEY_SERVICE, WITNESS_KEY_SERVICE};
use serde::Deserialize;
use worker::{Context, Env, Error, MessageBatch, Result, event};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateRequest {
    role: Role,
    expected_default_version: u32,
    algorithm: Option<SigningAlgorithm>,
}

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
#[serde(rename_all = "lowercase")]
enum RetireAction {
    Retire,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum CreateAction {
    Create,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum TicketRole {
    Ticket,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateTicketRequest {
    #[serde(rename = "action")]
    _action: CreateAction,
    #[serde(rename = "role")]
    _role: TicketRole,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetireRequest {
    #[serde(rename = "action")]
    _action: RetireAction,
    role: Role,
    version: u32,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RotationRequest {
    Rotate(RotateRequest),
    Retire(RetireRequest),
    CreateTicket(CreateTicketRequest),
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Role {
    Mirror,
    Witness,
    Ticket,
}

fn key_name(env: &Env, role: &Role) -> Result<String> {
    let binding = match role {
        Role::Ticket => return Ok(TICKET_KEY_NAME.to_owned()),
        Role::Mirror => MIRROR_KEY_SERVICE,
        Role::Witness => WITNESS_KEY_SERVICE,
    };
    let name = env
        .var(binding)
        .map_err(|_| Error::from(format!("{binding} must be set for key service rotation")))?
        .to_string();
    if name.trim().is_empty() {
        return Err(Error::from(format!("{binding} must not be empty")));
    }
    Ok(name)
}

#[derive(Debug, PartialEq, Eq)]
enum RotationDecision {
    Create,
    AlreadyAdvanced,
}

fn decide_rotation(
    expected: u32,
    current: u32,
    versions: &[VersionState],
) -> Result<RotationDecision> {
    if expected == 0 {
        return Err(Error::from("expected_default_version must be positive"));
    }
    if current != expected {
        return Ok(RotationDecision::AlreadyAdvanced);
    }
    if versions.last().map(|version| version.number) != Some(current) {
        return Err(Error::from(
            "key service has a newer version that is not the default; inspect before retrying rotation",
        ));
    }
    if !versions
        .iter()
        .any(|version| version.number == current && version.signing)
    {
        return Err(Error::from("key service default version cannot sign"));
    }
    Ok(RotationDecision::Create)
}

async fn rotate(env: &Env, request: &RotateRequest) -> Result<()> {
    if matches!(request.role, Role::Ticket) {
        if request.algorithm.is_some() {
            return Err(Error::from(
                "ticket key rotation does not take an algorithm",
            ));
        }
        return rotate_ticket(env, request.expected_default_version).await;
    }
    let name = key_name(env, &request.role)?;
    let ring = keyring(env)?;
    if request.expected_default_version == 0 {
        let algorithm = request
            .algorithm
            .ok_or_else(|| Error::from("initial signing key rotation requires algorithm"))?;
        if ring.signing_key_exists(&name).await? {
            // A repeated initial request must not create a second version.
            ring.current_default(&name).await?;
            ring.key_versions(&name).await?;
            log::info!("key service signing key {name} already exists");
        } else {
            ring.create_signing_key(&name, algorithm.as_str()).await?;
            log::info!(
                "created key service signing key {name} using {}",
                algorithm.as_str()
            );
        }
        return Ok(());
    }
    if request.algorithm.is_some() {
        return Err(Error::from(
            "algorithm is only allowed for initial signing key rotation",
        ));
    }
    let current = ring.current_default(&name).await?;
    let versions = ring.key_versions(&name).await?;
    match decide_rotation(request.expected_default_version, current, &versions)? {
        RotationDecision::AlreadyAdvanced => {
            log::warn!(
                "key service rotation for {name} ignored: expected default {}, found {current}",
                request.expected_default_version
            );
            return Ok(());
        }
        RotationDecision::Create => {}
    }

    let new_version = ring.new_signing_version(&name).await?;
    ring.promote(&name, new_version).await?;
    log::info!("key service rotation for {name}: default {current} -> {new_version}");
    Ok(())
}

async fn create_ticket(env: &Env) -> Result<()> {
    let ring = keyring(env)?;
    if super::ticket_key_exists(env).await? {
        let key = ring.get_ticket_default().await?;
        super::ticket_key(&key, "encrypt")?;
        super::ticket_key(&key, "decrypt")?;
        return Ok(()); // Idempotent Queue redelivery.
    }
    ring.create_ticket_key().await?;
    log::info!("created key service ticket key {TICKET_KEY_NAME}");
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum TicketRotationDecision {
    Create,
    PromoteExisting(u32),
    AlreadyAdvanced,
}

fn decide_ticket_rotation(
    expected: u32,
    current: u32,
    versions: &[TicketVersionState],
) -> Result<TicketRotationDecision> {
    if expected == 0 {
        return Err(Error::from("expected_default_version must be positive"));
    }
    if current != expected {
        return Ok(TicketRotationDecision::AlreadyAdvanced);
    }
    let latest = versions
        .last()
        .filter(|state| state.state == State::EncryptDecrypt)
        .ok_or_else(|| Error::from("ticket key has no usable newest version"))?;
    if latest.number == current {
        return Ok(TicketRotationDecision::Create);
    }
    if current.checked_add(1) == Some(latest.number) {
        return Ok(TicketRotationDecision::PromoteExisting(latest.number));
    }
    Err(Error::from(
        "ticket key has an unexpected newer version; inspect rotation",
    ))
}

async fn rotate_ticket(env: &Env, expected: u32) -> Result<()> {
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
    ring.promote(TICKET_KEY_NAME, version).await?;
    log::info!("ticket key rotated: default {current} -> {version}");
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum RetirementDecision {
    Retire,
    AlreadyRetired,
}

fn decide_retirement(
    version: u32,
    current: u32,
    versions: &[VersionState],
) -> Result<RetirementDecision> {
    if version == 0 {
        return Err(Error::from("retirement version must be positive"));
    }
    if !versions
        .iter()
        .any(|state| state.number == current && state.signing)
    {
        return Err(Error::from("key service default version cannot sign"));
    }
    if version == current {
        return Err(Error::from("cannot retire the key service default version"));
    }
    let target = versions
        .iter()
        .find(|state| state.number == version)
        .ok_or_else(|| Error::from(format!("key service version {version} does not exist")))?;
    if !target.signing {
        return Ok(RetirementDecision::AlreadyRetired);
    }
    if versions.iter().filter(|state| state.signing).count() <= 1 {
        return Err(Error::from("cannot retire the last signing version"));
    }
    Ok(RetirementDecision::Retire)
}

async fn retire(env: &Env, request: &RetireRequest) -> Result<()> {
    if matches!(request.role, Role::Ticket) {
        return retire_ticket(env, request.version).await;
    }
    let name = key_name(env, &request.role)?;
    let ring = keyring(env)?;
    let current = ring.current_default(&name).await?;
    let versions = ring.key_versions(&name).await?;
    match decide_retirement(request.version, current, &versions)? {
        RetirementDecision::AlreadyRetired => {
            log::info!(
                "key service key {name} version {} already retired",
                request.version
            );
            Ok(())
        }
        RetirementDecision::Retire => {
            ring.retire(&name, request.version).await?;
            log::info!("key service key {name} version {} retired", request.version);
            Ok(())
        }
    }
}

fn decide_ticket_retirement(
    version: u32,
    current: u32,
    versions: &[TicketVersionState],
) -> Result<RetirementDecision> {
    if version == 0 {
        return Err(Error::from("retirement version must be positive"));
    }
    if !versions
        .last()
        .is_some_and(|state| state.number == current && state.state == State::EncryptDecrypt)
    {
        return Err(Error::from(
            "ticket key default is not the newest usable version",
        ));
    }
    let target = versions
        .iter()
        .find(|state| state.number == version)
        .ok_or_else(|| Error::from(format!("ticket key version {version} does not exist")))?;
    if target.state == State::Retired {
        return Ok(RetirementDecision::AlreadyRetired);
    }
    if version == current {
        return Err(Error::from("cannot retire the current ticket key version"));
    }
    if versions
        .iter()
        .find(|state| state.state != State::Retired)
        .map(|state| state.number)
        != Some(version)
    {
        return Err(Error::from(
            "only the oldest decrypting ticket key version may be retired",
        ));
    }
    Ok(RetirementDecision::Retire)
}

async fn retire_ticket(env: &Env, version: u32) -> Result<()> {
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
) -> Result<()> {
    crate::init_sentry(&env);
    for message in batch.messages()? {
        match message.body() {
            RotationRequest::Rotate(request) => rotate(&env, request).await?,
            RotationRequest::Retire(request) => retire(&env, request).await?,
            RotationRequest::CreateTicket(_) => create_ticket(&env).await?,
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

    fn states(values: &[(u32, bool)]) -> Vec<VersionState> {
        values
            .iter()
            .map(|&(number, signing)| VersionState { number, signing })
            .collect()
    }

    #[test]
    fn rotation_message_requires_known_role_and_expected_version() {
        let request: RotationRequest =
            serde_json::from_str(r#"{"role":"mirror","expected_default_version":1}"#).unwrap();
        let RotationRequest::Rotate(request) = request else {
            panic!("expected rotation request");
        };
        assert!(matches!(request.role, Role::Mirror));
        assert_eq!(request.expected_default_version, 1);
        assert!(request.algorithm.is_none());
        let initial: RotationRequest = serde_json::from_str(
            r#"{"role":"mirror","expected_default_version":0,"algorithm":"ML_DSA_44"}"#,
        )
        .unwrap();
        let RotationRequest::Rotate(initial) = initial else {
            panic!("expected initial rotation request");
        };
        assert_eq!(initial.algorithm, Some(super::SigningAlgorithm::MlDsa44));
        let ed25519: RotationRequest = serde_json::from_str(
            r#"{"role":"witness","expected_default_version":0,"algorithm":"ED25519"}"#,
        )
        .unwrap();
        assert!(
            matches!(ed25519, RotationRequest::Rotate(request) if request.algorithm == Some(super::SigningAlgorithm::Ed25519))
        );
        assert!(
            serde_json::from_str::<RotationRequest>(
                r#"{"role":"mirror","expected_default_version":0,"algorithm":"AES_256_GCM"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<RotationRequest>(
                r#"{"role":"other","expected_default_version":1}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<RotationRequest>(r#"{"role":"mirror"}"#).is_err());
        assert!(
            serde_json::from_str::<RotationRequest>(
                r#"{"role":"mirror","expected_default_version":1,"version":2}"#
            )
            .is_err()
        );
    }

    #[test]
    fn retirement_message_requires_action_role_and_version() {
        let request: RotationRequest =
            serde_json::from_str(r#"{"action":"retire","role":"witness","version":2}"#).unwrap();
        let RotationRequest::Retire(request) = request else {
            panic!("expected retirement request");
        };
        assert!(matches!(request.role, Role::Witness));
        assert_eq!(request.version, 2);
        for message in [
            r#"{"action":"retire","role":"witness"}"#,
            r#"{"action":"delete","role":"witness","version":2}"#,
            r#"{"action":"retire","role":"other","version":2}"#,
            r#"{"action":"retire","role":"witness","version":2,"extra":true}"#,
        ] {
            assert!(serde_json::from_str::<RotationRequest>(message).is_err());
        }
    }

    #[test]
    fn rotate_only_from_expected_latest_default() {
        assert_eq!(
            decide_rotation(2, 2, &states(&[(1, true), (2, true)])).unwrap(),
            RotationDecision::Create
        );
        assert_eq!(
            decide_rotation(2, 3, &states(&[(1, false), (2, true), (3, true)])).unwrap(),
            RotationDecision::AlreadyAdvanced
        );
        assert!(decide_rotation(2, 2, &states(&[(1, true), (2, true), (3, true)])).is_err());
        assert!(decide_rotation(0, 1, &states(&[(1, true)])).is_err());
        assert!(decide_rotation(2, 2, &states(&[(1, true), (2, false)])).is_err());
    }

    #[test]
    fn retirement_requires_a_non_default_signing_version() {
        let versions = states(&[(1, true), (2, true), (3, false)]);
        assert_eq!(
            decide_retirement(1, 2, &versions).unwrap(),
            RetirementDecision::Retire
        );
        assert_eq!(
            decide_retirement(3, 2, &versions).unwrap(),
            RetirementDecision::AlreadyRetired
        );
        assert!(decide_retirement(2, 2, &versions).is_err());
        assert!(decide_retirement(0, 2, &versions).is_err());
        assert!(decide_retirement(4, 2, &versions).is_err());
        assert!(decide_retirement(1, 2, &states(&[(1, true), (2, false)])).is_err());
        assert!(decide_retirement(1, 2, &states(&[(1, false), (2, true)])).is_ok());
    }

    #[test]
    fn ticket_operator_messages_are_explicit() {
        assert!(matches!(
            serde_json::from_str::<RotationRequest>(r#"{"action":"create","role":"ticket"}"#)
                .unwrap(),
            RotationRequest::CreateTicket(_)
        ));
        let rotate: RotationRequest =
            serde_json::from_str(r#"{"role":"ticket","expected_default_version":2}"#).unwrap();
        assert!(
            matches!(rotate, RotationRequest::Rotate(request) if matches!(request.role, Role::Ticket))
        );
        assert!(matches!(
            serde_json::from_str::<RotationRequest>(
                r#"{"action":"retire","role":"ticket","version":1}"#
            )
            .unwrap(),
            RotationRequest::Retire(_)
        ));
        for message in [
            r#"{"action":"create","role":"mirror"}"#,
            r#"{"action":"create","role":"ticket","version":1}"#,
            r#"{"action":"retire","role":"ticket"}"#,
        ] {
            assert!(serde_json::from_str::<RotationRequest>(message).is_err());
        }
    }

    #[test]
    fn ticket_rotation_and_oldest_retirement_are_retry_safe() {
        let states = |values: &[(u32, bool)]| {
            values
                .iter()
                .map(|&(number, decrypting)| {
                    TicketVersionState::new(
                        number,
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
            decide_ticket_rotation(3, 3, &versions).unwrap(),
            TicketRotationDecision::Create
        );
        assert_eq!(
            decide_ticket_rotation(2, 3, &versions).unwrap(),
            TicketRotationDecision::AlreadyAdvanced
        );
        assert_eq!(
            decide_ticket_rotation(2, 2, &versions).unwrap(),
            TicketRotationDecision::PromoteExisting(3)
        );
        assert!(decide_ticket_rotation(1, 1, &versions).is_err());
        assert_eq!(
            decide_ticket_retirement(1, 3, &versions).unwrap(),
            RetirementDecision::Retire
        );
        assert!(decide_ticket_retirement(2, 3, &versions).is_err());
        assert!(decide_ticket_retirement(3, 3, &versions).is_err());
        let retired = states(&[(1, false), (2, true), (3, true)]);
        assert_eq!(
            decide_ticket_retirement(1, 3, &retired).unwrap(),
            RetirementDecision::AlreadyRetired
        );
        assert_eq!(
            decide_ticket_retirement(2, 3, &retired).unwrap(),
            RetirementDecision::Retire
        );
        let decrypt_only = vec![
            TicketVersionState::new(1, State::Decrypt),
            TicketVersionState::new(2, State::EncryptDecrypt),
        ];
        assert_eq!(
            decide_ticket_retirement(1, 2, &decrypt_only).unwrap(),
            RetirementDecision::Retire
        );
        assert!(decide_ticket_retirement(2, 2, &states(&[(1, false), (2, true)])).is_err());
        assert!(decide_ticket_retirement(0, 3, &versions).is_err());
    }
}
