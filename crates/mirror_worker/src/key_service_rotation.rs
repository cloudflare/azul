// Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Operator-initiated key service rotation through a dedicated Cloudflare Queue.
//! The Queue is populated with an account-scoped API token or the dashboard;
//! there is no public rotation endpoint or Workflow entrypoint.

use super::keyring;
use serde::Deserialize;
use worker::{Context, Env, Error, MessageBatch, Result, event};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationRequest {
    role: Role,
    expected_default_version: u32,
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
            Self::Mirror => "MIRROR_KEY_SERVICE_KEY",
            Self::Witness => "WITNESS_KEY_SERVICE_KEY",
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

fn decide_rotation(expected: u32, current: u32, versions: &[u32]) -> Result<RotationDecision> {
    if expected == 0 {
        return Err(Error::from("expected_default_version must be positive"));
    }
    if current != expected {
        return Ok(RotationDecision::AlreadyAdvanced);
    }
    if versions.last().copied() != Some(current) {
        return Err(Error::from(
            "key service has a newer version that is not the default; inspect before retrying rotation",
        ));
    }
    Ok(RotationDecision::Create)
}

async fn rotate(env: &Env, request: &RotationRequest) -> Result<()> {
    let name = key_name(env, &request.role)?;
    let ring = keyring(env)?;
    let current = ring.current_default(&name).await?;
    let versions = ring.signing_versions(&name).await?;
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

/// Only the Queue consumer invokes rotation; no fetch route or cron does.
#[event(queue)]
async fn rotation_queue(
    batch: MessageBatch<RotationRequest>,
    env: Env,
    _ctx: Context,
) -> Result<()> {
    crate::init_sentry(&env);
    for message in batch.messages()? {
        rotate(&env, message.body()).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Role, RotationDecision, RotationRequest, decide_rotation};

    #[test]
    fn rotation_message_requires_known_role_and_expected_version() {
        let request: RotationRequest =
            serde_json::from_str(r#"{"role":"mirror","expected_default_version":1}"#).unwrap();
        assert!(matches!(request.role, Role::Mirror));
        assert_eq!(request.expected_default_version, 1);
        assert!(
            serde_json::from_str::<RotationRequest>(
                r#"{"role":"other","expected_default_version":1}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<RotationRequest>(r#"{"role":"mirror"}"#).is_err());
    }

    #[test]
    fn rotate_only_from_expected_latest_default() {
        assert_eq!(
            decide_rotation(2, 2, &[1, 2]).unwrap(),
            RotationDecision::Create
        );
        assert_eq!(
            decide_rotation(2, 3, &[1, 2, 3]).unwrap(),
            RotationDecision::AlreadyAdvanced
        );
        assert!(decide_rotation(2, 2, &[1, 2, 3]).is_err());
        assert!(decide_rotation(0, 1, &[1]).is_err());
    }
}
