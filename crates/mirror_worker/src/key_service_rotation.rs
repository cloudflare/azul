// Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Operator-initiated key service rotation through a dedicated Cloudflare Queue.
//! The Queue is populated with an account-scoped API token or the dashboard;
//! there is no public rotation endpoint or Workflow entrypoint.

use super::{VersionState, keyring};
use crate::{MIRROR_KEY_SERVICE, WITNESS_KEY_SERVICE};
use serde::Deserialize;
use worker::{Context, Env, Error, MessageBatch, Result, event};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateRequest {
    role: Role,
    expected_default_version: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RetireAction {
    Retire,
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
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Role {
    Mirror,
    Witness,
}

impl Role {
    const fn binding(&self) -> &'static str {
        match self {
            Self::Mirror => MIRROR_KEY_SERVICE,
            Self::Witness => WITNESS_KEY_SERVICE,
        }
    }
}

fn key_name(env: &Env, role: &Role) -> Result<String> {
    let binding = role.binding();
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
    let name = key_name(env, &request.role)?;
    let ring = keyring(env)?;
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
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        RetirementDecision, Role, RotationDecision, RotationRequest, VersionState,
        decide_retirement, decide_rotation,
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
}
