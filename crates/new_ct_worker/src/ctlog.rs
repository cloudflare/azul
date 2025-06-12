// Ported from "sunlight" (https://github.com/FiloSottile/sunlight)
// Copyright 2023 The Sunlight Authors
// Licensed under ISC License found in the LICENSE file or at https://opensource.org/license/isc-license-txt
//
// This ports code from the original Go project "sunlight" and adapts it to Rust idioms.
//
// Modifications and Rust implementation Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Core functionality for a [Static CT API](https://c2sp.org/static-ct-api) log, including
//! creating and loading logs from persistent storage, adding leaves to logs, and sequencing logs.
//!
//! This file contains code ported from the original project [sunlight](https://github.com/FiloSottile/sunlight).
//!
//! References:
//! - [http.go](https://github.com/FiloSottile/sunlight/blob/36be227ff4599ac11afe3cec37a5febcd61da16a/internal/ctlog/http.go)
//! - [ctlog.go](https://github.com/FiloSottile/sunlight/blob/36be227ff4599ac11afe3cec37a5febcd61da16a/internal/ctlog/ctlog.go)
//! - [ctlog_test.go](https://github.com/FiloSottile/sunlight/blob/36be227ff4599ac11afe3cec37a5febcd61da16a/internal/ctlog/ctlog_test.go)
//! - [testlog_test.go](https://github.com/FiloSottile/sunlight/blob/36be227ff4599ac11afe3cec37a5febcd61da16a/internal/ctlog/testlog_test.go)

use crate::{util::now_millis, LookupKey, SequenceMetadata};
use anyhow::{anyhow, bail};
use futures_util::future::try_join_all;
use generic_log_worker::{ctlog::UploadOptions, ObjectBackend};
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signed_note::{NoteVerifier, VerifierList};
use std::collections::HashMap;
use std::time::Duration;
use std::{
    cmp::{Ord, Ordering},
    sync::LazyLock,
};
use thiserror::Error;
use tlog_tiles::{
    CheckpointSigner, Hash, HashReader, LogEntry, PathElem, PendingLogEntry, Tile, TileIterator,
    TlogError, TlogTile, UnixTimestamp, HASH_SIZE,
};
use tokio::sync::watch::{channel, Receiver, Sender};

/// Options for uploading issuers.
static OPTS_ISSUER: LazyLock<UploadOptions> = LazyLock::new(|| UploadOptions {
    content_type: Some("application/pkix-cert".to_string()),
    immutable: true,
});

/// Uploads any newly-observed issuers to the object backend, returning the paths of those uploaded.
pub(crate) async fn upload_issuers(
    object: &impl ObjectBackend,
    issuers: &[&[u8]],
    name: &str,
) -> worker::Result<()> {
    let issuer_futures: Vec<_> = issuers
        .iter()
        .map(|issuer| async move {
            let fingerprint: [u8; 32] = Sha256::digest(issuer).into();
            let path = format!("issuer/{}", hex::encode(fingerprint));

            if let Some(old) = object.fetch(&path).await? {
                if old != *issuer {
                    return Err(worker::Error::RustError(format!(
                        "invalid existing issuer: {}",
                        hex::encode(old)
                    )));
                }
                Ok(None)
            } else {
                object.upload(&path, issuer, &OPTS_ISSUER).await?;
                Ok(Some(path))
            }
        })
        .collect();

    for path in try_join_all(issuer_futures)
        .await?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
    {
        {
            info!("{name}: Observed new issuer; path={path}");
        }
    }

    Ok(())
}
