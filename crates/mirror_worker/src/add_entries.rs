// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! `POST /add-entries` handler.
//!
//! Implements the [c2sp.org/tlog-mirror `add-entries`][add-e] endpoint:
//! stream the (optionally gzip) request body, verify each [`EntryPackage`]
//! against the target pending checkpoint with a subtree consistency proof,
//! persist the verified entries as bundles and hash tiles (see
//! [`crate::commit`]), and advance the persisted-entry frontier. A
//! complete upload also writes the cosigned checkpoint and returns 200
//! with the mirror's [cosignature][cosig] line(s); a client-truncated
//! upload persists the verified prefix and returns 202 with the advanced
//! next entry so the client can resume ([C2SP/C2SP#253]).
//!
//! [add-e]: https://c2sp.org/tlog-mirror#add-entries
//! [cosig]: https://c2sp.org/tlog-cosignature
//! [C2SP/C2SP#253]: https://github.com/C2SP/C2SP/pull/253
//! [`EntryPackage`]: tlog_mirror::EntryPackage

use std::collections::HashMap;
use std::io::{Cursor, ErrorKind};

use axum::extract::State;
use axum::http::{StatusCode, header::CONTENT_TYPE};
use axum::response::IntoResponse as _;
use signed_note::{Note, NoteError};
use tlog_checkpoint::CheckpointText;
use tlog_core::{
    Hash, HashReader, Subtree, TlogError, stored_hash_index, stored_hashes_for_record_hash,
    tree_hash, verify_subtree_consistency_proof,
};
use tlog_mirror::{
    AddEntriesRequestHeader, EntryPackage, MIRROR_INFO_CONTENT_TYPE, MirrorInfo, PACKAGE_ALIGNMENT,
    ParseError, package_ranges,
};
#[allow(clippy::wildcard_imports)]
use worker::*;

use generic_log_worker::util::now_millis;

use crate::{
    body, commit,
    frontend_worker::{ApiResult, AppError},
    load_mirror_signer, load_ticket_sealer, log_verifiers,
    mirror_state_do::{
        AdvanceNextEntryRequest, CommitRequest, MirrorStateSnapshot, NextEntry, PendingCheckpoint,
        state_stub,
    },
    storage::load_origin_bucket,
    stream_buffer::StreamBuffer,
};

/// Handle `POST /add-entries`.
///
/// See the module-level comment for the full flow: parse and verify entry
/// packages over a streamed (optionally gzip) request body, persist the
/// verified entries and advance the persisted-entry frontier, and either
/// cosign the mirror checkpoint (200) or, for a truncated upload, persist
/// the verified prefix and return 202.
#[worker::send]
pub(crate) async fn add_entries(
    State(env): State<Env>,
    req: axum::extract::Request,
) -> ApiResult<axum::response::Response> {
    // No DefaultBodyLimit: Cloudflare enforces a request-body cap at the
    // edge (100 MB, higher on paid plans) and 413s oversized bodies there.
    // Clients on body-limited platforms truncate at a package boundary and
    // resume via the 202 + advanced next_entry (C2SP/C2SP#249). The Workers
    // runtime does not decompress request bodies, so gzip-encoded bodies
    // are gunzipped here; unknown encodings are 415'd (see `crate::body`).
    let (parts, body) = req.into_parts();
    let stream = body::decoded_stream(&parts.headers, body)?;
    let mut buf = StreamBuffer::new(stream);

    // Pull chunks until the header parses, retrying on UnexpectedEof. The
    // header size is bounded (~131 KB max), so the loop terminates.
    let header = parse_header(&mut buf).await?;

    let Some(verifiers) = log_verifiers(&header.log_origin) else {
        return Err(AppError::UnknownLogOrigin);
    };

    let snapshot = fetch_snapshot(&env, &header.log_origin).await?;

    // No pending checkpoint accepted yet means there is nothing to
    // authenticate the entries against, so this MUST be 422, not 409: the
    // client can't make progress by retrying and must first drive an
    // add-checkpoint (C2SP/C2SP#291). Empty pending signed-note bytes
    // reliably mean pristine state; once accepted, the DO retains the
    // latest pending forever.
    if snapshot.pending.signed_note_bytes.is_empty() {
        log::info!(
            "add-entries: no pending checkpoint for origin {:?}; returning 422",
            header.log_origin,
        );
        return Err(AppError::UnprocessableEntity(
            "mirror has no pending checkpoint for this log".to_owned(),
        ));
    }

    let target = match resolve_target_pending(&env, &header, &snapshot, &verifiers) {
        Ok(t) => t,
        Err(reason) => {
            log::info!(
                "add-entries: rejecting target pending: {reason} \
                 (origin={origin:?}, upload_end={ue}, pending_size={ps}, committed_size={cs})",
                origin = header.log_origin,
                ue = header.upload_end,
                ps = snapshot.pending.size,
                cs = snapshot.committed.size,
            );
            return Ok(mirror_info_409(&env, &snapshot, &header.log_origin));
        }
    };

    // upload_start must be <= next_entry (the first index not yet
    // persisted); a client resuming after a 202 sets it to the advertised
    // next entry. A non-256-aligned value is accepted; see
    // `first_package_prefix`.
    if header.upload_start > snapshot.next_entry.size {
        log::info!(
            "add-entries: rejecting upload_start={us} > next_entry={ne}",
            us = header.upload_start,
            ne = snapshot.next_entry.size,
        );
        return Ok(mirror_info_409(&env, &snapshot, &header.log_origin));
    }

    let first_prefix = first_package_prefix(&env, &header, snapshot.next_entry.size).await?;

    let received = receive_and_verify_packages(&mut buf, &header, &target, &first_prefix).await?;

    finalize_commit(&env, &header, &snapshot, &target, received).await
}

/// The verified entry prefix received from an `add-entries` body.
///
/// `entries[i]` is the raw bytes of leaf `header.upload_start + i`, so
/// `entries` spans `[upload_start, upload_start + entries.len())`. When
/// `complete` is true this reaches `upload_end` (every expected package
/// arrived); otherwise the client truncated the upload and only a prefix
/// of complete, verified packages is present (the partial-progress case).
struct ReceivedPrefix {
    entries: Vec<Vec<u8>>,
    complete: bool,
}

/// Read and verify entry packages in the canonical sequence for
/// `[upload_start, upload_end)`, returning the verified entries for the
/// complete-package prefix actually received.
///
/// Pulls bytes from `buf` as needed for each package. Returns
/// `Ok(Err(resp))` carrying a fully-formed error response for the spec's
/// hard-failure cases: 400 for a malformed body or a truncation with no
/// complete package received, and 422 for a package that fails
/// subtree-consistency verification.
///
/// A client truncation (clean between packages, or mid-package) *after*
/// at least one complete package is the partial-progress case: the
/// returned [`ReceivedPrefix`] has `complete == false` and carries the
/// verified prefix, which the caller persists before returning 202.
///
/// # Errors
///
/// Returns an error on a transport failure reading the body stream.
async fn receive_and_verify_packages<S>(
    buf: &mut StreamBuffer<S>,
    header: &AddEntriesRequestHeader,
    target: &PendingCheckpoint,
    first_prefix: &[Vec<u8>],
) -> ApiResult<ReceivedPrefix>
where
    S: futures_util::Stream<Item = Result<Vec<u8>>> + Unpin,
{
    let mut received_entries: Vec<Vec<u8>> = Vec::new();
    for (packages_received, (pkg_start, pkg_end)) in
        package_ranges(header.upload_start, header.upload_end).enumerate()
    {
        let num_entries = pkg_end - pkg_start;
        let pkg = match parse_next_package(buf, num_entries).await? {
            ParseOutcome::Ok(pkg) => pkg,
            // Client truncation. Clean and mid-package EOF are handled
            // identically: persist any complete packages already received
            // (202), or 400 if none arrived.
            ParseOutcome::CleanEof | ParseOutcome::MidPackageEof => {
                if packages_received == 0 {
                    log::warn!(
                        "add-entries: stream truncated before the first complete \
                         package at [{pkg_start}, {pkg_end})"
                    );
                    return Err(AppError::BadRequest(
                        "no complete entry package received".to_owned(),
                    ));
                }
                log::info!(
                    "add-entries: client-truncated stream after {packages_received} \
                     complete packages; persisting partial prefix"
                );
                return Ok(ReceivedPrefix {
                    entries: received_entries,
                    complete: false,
                });
            }
            ParseOutcome::Err(e) => {
                log::warn!("add-entries: malformed package [{pkg_start}, {pkg_end}): {e:?}");
                return Err(AppError::BadRequest(e.to_string()));
            }
        };
        // Only the first package can be non-256-aligned, carrying the
        // persisted-leaf prefix; later packages start on a 256 boundary
        // (subtree start == pkg_start) and need no prefix.
        let subtree_start = (pkg_start / PACKAGE_ALIGNMENT) * PACKAGE_ALIGNMENT;
        let prefix: &[Vec<u8>] = if packages_received == 0 {
            first_prefix
        } else {
            &[]
        };
        if let Err(reason) = verify_package(prefix, &pkg, subtree_start, pkg_end, target) {
            log::info!(
                "add-entries: package [{pkg_start}, {pkg_end}) failed verification: {reason}"
            );
            return Err(AppError::UnprocessableEntity(reason.to_owned()));
        }
        // Accumulating verified entries in memory is bounded by the
        // client's per-request package budget (spec-recommended <= 32
        // packages / 8192 entries).
        received_entries.extend(pkg.entries);
    }

    // All expected packages received and verified. The stream MUST now be
    // at EOF; trailing bytes after the last package are a malformed
    // request.
    if buf.len() > 0 || buf.pull_one().await? {
        log::warn!(
            "add-entries: trailing data after the last package: {} buffered, eof={}",
            buf.len(),
            buf.is_eof(),
        );
        return Err(AppError::BadRequest(
            "trailing data after the last entry package".to_owned(),
        ));
    }

    Ok(ReceivedPrefix {
        entries: received_entries,
        complete: true,
    })
}

/// Read the committed-leaf prefix required to verify a non-256-aligned
/// first package: the leaves `[subtree_start, upload_start)` where
/// `subtree_start` is `upload_start` rounded down to a 256 boundary.
///
/// Returns an empty vec when `upload_start` is already 256-aligned (the
/// common case and every non-first package). Because `upload_start <=
/// next_entry.size` is enforced upstream, the requested leaves are always
/// present in storage.
///
/// # Errors
///
/// Returns an error if opening the origin bucket or reading the persisted
/// entry bundle fails.
async fn first_package_prefix(
    env: &Env,
    header: &AddEntriesRequestHeader,
    persisted_size: u64,
) -> Result<Vec<Vec<u8>>> {
    let subtree_start = (header.upload_start / PACKAGE_ALIGNMENT) * PACKAGE_ALIGNMENT;
    if header.upload_start == subtree_start {
        return Ok(Vec::new());
    }
    let bucket = load_origin_bucket(env, &header.log_origin)?;
    commit::read_committed_leaves(
        &bucket,
        subtree_start,
        header.upload_start - subtree_start,
        persisted_size,
    )
    .await
}

/// Persist the newly-received entries, advance the persisted-entry
/// frontier, and either (complete upload) advance and cosign the mirror
/// checkpoint returning 200, or (partial upload) return 202 with the
/// advanced next entry.
///
/// `received.entries[i]` is the raw bytes of leaf `header.upload_start +
/// i`. Only the tail `[next_entry.size, persisted_end)` is newly
/// persisted; any already-persisted prefix (`upload_start <=
/// next_entry.size`) is skipped, per the spec's "skip saving
/// already-written entries" rule. Persistence resumes from the
/// authenticated frontier `(next_entry.size, next_entry.hash)` so the
/// mirror never re-reads the whole tree.
async fn finalize_commit(
    env: &Env,
    header: &AddEntriesRequestHeader,
    snapshot: &MirrorStateSnapshot,
    target: &PendingCheckpoint,
    received: ReceivedPrefix,
) -> ApiResult<axum::response::Response> {
    let frontier = &snapshot.next_entry;
    let bucket = load_origin_bucket(env, &header.log_origin)?;

    // Everything below frontier.size is already persisted. When the whole
    // received span is already persisted (a re-upload, or a request another
    // writer already fulfilled), skip straight to the response.
    let received_len =
        u64::try_from(received.entries.len()).map_err(|_| Error::from("received len overflow"))?;
    let persisted_end = header.upload_start + received_len;
    let effective_next = if persisted_end > frontier.size {
        let offset = usize::try_from(frontier.size - header.upload_start)
            .map_err(|_| Error::from("commit offset overflows usize"))?;
        let new_entries = received
            .entries
            .get(offset..)
            .ok_or_else(|| Error::from("received fewer entries than the frontier offset"))?;

        // Persist entry bundles + hash tiles, resuming from the frontier.
        let root = commit::persist_entries(
            &bucket,
            frontier.size,
            frontier.hash,
            persisted_end,
            new_entries,
        )
        .await?;

        // A complete upload's recomputed tree MUST match the pending
        // checkpoint the entries were proven consistent with. A mismatch
        // means proof verification and tile computation disagree: an
        // internal error, never a client fault. Partial uploads stop short
        // by design, so this is only checked when complete.
        if received.complete && (persisted_end != target.size || root != target.hash) {
            log::error!(
                "add-entries: recomputed frontier ({persisted_end}, {root}) != target ({}, {})",
                target.size,
                target.hash,
            );
            return Err(AppError::InternalServerError(
                "recomputed root mismatch".to_owned(),
            ));
        }

        // Advance the persisted-entry frontier in the DO (monotone). The
        // returned frontier reflects any concurrent advance.
        let advanced = advance_next_entry(env, &header.log_origin, persisted_end, root)
            .await?
            .size;

        // Kick the per-origin partial-tile cleaner to (re)start its alarm
        // loop. Best-effort: cleaning runs on the alarm and must never fail
        // this response, so `kick` logs and swallows any error.
        crate::cleaner_do::kick(env, &header.log_origin).await;

        advanced
    } else {
        frontier.size
    };

    // A truncated upload persisted a verified prefix but did not reach a
    // signed pending size: report the advanced next entry so the client
    // resumes; no cosignature is produced.
    if !received.complete {
        return Ok(mirror_info_202(
            env,
            snapshot,
            &header.log_origin,
            effective_next,
        ));
    }

    // Cosign the committed checkpoint with the mirror key. The checkpoint
    // text comes from the log-signed pending note; the response is the bare
    // cosignature line(s), identical to a witness's add-checkpoint response.
    let note = Note::from_bytes(&target.signed_note_bytes)
        .map_err(|e| Error::from(format!("target note parse: {e:?}")))?;
    let cp_text = CheckpointText::from_bytes(note.text())
        .map_err(|e| Error::from(format!("target checkpoint parse: {e:?}")))?;
    let note_sig = load_mirror_signer(env)?
        .as_checkpoint_signer()
        .sign(now_millis(), &cp_text)
        .map_err(|e| Error::from(format!("mirror cosign: {e:?}")))?;
    let cosig_body =
        tlog_witness::serialize_add_checkpoint_response(std::slice::from_ref(&note_sig));

    // Persist the served checkpoint (log note + mirror cosignature) before
    // advancing the durable mirror checkpoint, so a monitor can never
    // observe an advanced size without the matching checkpoint object.
    let mut checkpoint_obj = target.signed_note_bytes.clone();
    checkpoint_obj.extend_from_slice(&cosig_body);
    commit::write_checkpoint(&bucket, checkpoint_obj.clone()).await?;

    dispatch_commit(
        env,
        &header.log_origin,
        &CommitRequest {
            size: header.upload_end,
            hash: target.hash,
            signed_note_bytes: checkpoint_obj,
        },
    )
    .await?;

    Ok((
        StatusCode::OK,
        [(CONTENT_TYPE, "text/plain; charset=utf-8")],
        cosig_body,
    )
        .into_response())
}

/// POST the [`CommitRequest`] to the per-origin DO, advancing the mirror
/// checkpoint. A non-200 status (or a `/commit` beyond pending) is a
/// frontend/mirror bug, so it is surfaced as a transport error that the
/// handler maps to 500.
async fn dispatch_commit(env: &Env, origin: &str, commit_req: &CommitRequest) -> Result<()> {
    let stub = state_stub(env, origin)?;
    let mut resp = stub
        .fetch_with_request(Request::new_with_init(
            "http://do/commit",
            &RequestInit {
                method: Method::Post,
                body: Some(serde_json::to_string(commit_req)?.into()),
                headers: {
                    let h = Headers::new();
                    h.set("content-type", "application/json")?;
                    h
                },
                ..Default::default()
            },
        )?)
        .await?;
    match resp.status_code() {
        200 => Ok(()),
        status => {
            let msg = resp.text().await.unwrap_or_default();
            log::error!("add-entries: DO /commit returned {status}: {msg}");
            Err(Error::from(format!("commit failed ({status})")))
        }
    }
}

/// POST an [`AdvanceNextEntryRequest`] to the per-origin DO, advancing
/// the persisted-entry frontier to `(size, hash)`. Returns the effective
/// frontier (which reflects any concurrent advance). A DO rejection
/// (`size > pending`, a mirror bug) or RPC failure is surfaced as a
/// transport error that the handler maps to 500.
async fn advance_next_entry(env: &Env, origin: &str, size: u64, hash: Hash) -> Result<NextEntry> {
    let stub = state_stub(env, origin)?;
    let req = AdvanceNextEntryRequest { size, hash };
    let mut resp = stub
        .fetch_with_request(Request::new_with_init(
            "http://do/advance-next-entry",
            &RequestInit {
                method: Method::Post,
                body: Some(serde_json::to_string(&req)?.into()),
                headers: {
                    let h = Headers::new();
                    h.set("content-type", "application/json")?;
                    h
                },
                ..Default::default()
            },
        )?)
        .await?;
    match resp.status_code() {
        200 => Ok(resp.json().await?),
        status => {
            let msg = resp.text().await.unwrap_or_default();
            log::error!("add-entries: DO /advance-next-entry returned {status}: {msg}");
            Err(Error::from(format!("advance-next-entry failed ({status})")))
        }
    }
}

/// Outcome of attempting to read the next entry package from the stream
/// buffer.
///
/// `CleanEof` (stream ended cleanly between packages) and `MidPackageEof`
/// (stream ended partway through a package) are kept distinct for
/// diagnostics, though the handler treats both as a client truncation:
/// complete packages already received are persisted (partial progress),
/// and a truncation before the first complete package is a 400.
enum ParseOutcome {
    Ok(EntryPackage),
    CleanEof,
    MidPackageEof,
    Err(ParseError),
}

/// Read the `add-entries` request header from `buf`, pulling more
/// chunks from the underlying stream until the header parses or the
/// stream errors. Returns `Ok(Ok(header))` on success or `Ok(Err(resp))`
/// where `resp` is a fully-formed 400 response on malformed input.
///
/// The header has a bounded maximum size (u16 origin + u64s + u16
/// ticket + hash + u8 proof-size + 63 hashes <= ~131 KB), so the
/// retry-on-`UnexpectedEof` loop terminates.
async fn parse_header<S>(buf: &mut StreamBuffer<S>) -> ApiResult<AddEntriesRequestHeader>
where
    S: futures_util::Stream<Item = Result<Vec<u8>>> + Unpin,
{
    loop {
        let mut cursor = Cursor::new(buf.buffered());
        match AddEntriesRequestHeader::read_from(&mut cursor) {
            Ok(header) => {
                let consumed = usize::try_from(cursor.position()).unwrap_or(usize::MAX);
                buf.consume(consumed);
                return Ok(header);
            }
            Err(ParseError::Io(ref e)) if e.kind() == ErrorKind::UnexpectedEof => {
                // Need more bytes to parse the header. Pull another
                // chunk; if the stream is already at EOF, the header
                // is fundamentally malformed (truncated before being
                // complete).
                if !buf.pull_one().await? {
                    log::warn!(
                        "add-entries: stream ended before header was complete \
                         ({} bytes buffered)",
                        buf.len()
                    );
                    return Err(AppError::BadRequest(
                        "malformed (truncated header)".to_owned(),
                    ));
                }
            }
            Err(e) => {
                log::warn!("add-entries: malformed header: {e:?}");
                return Err(AppError::BadRequest(e.to_string()));
            }
        }
    }
}

/// Read the next entry package from `buf`, pulling more chunks from
/// the underlying stream until the package parses or the stream ends.
/// See [`ParseOutcome`] for the four cases.
async fn parse_next_package<S>(buf: &mut StreamBuffer<S>, num_entries: u64) -> Result<ParseOutcome>
where
    S: futures_util::Stream<Item = Result<Vec<u8>>> + Unpin,
{
    // EOF with an empty buffer: clean truncation between packages.
    if buf.is_eof() && buf.len() == 0 {
        return Ok(ParseOutcome::CleanEof);
    }
    loop {
        let mut cursor = Cursor::new(buf.buffered());
        match EntryPackage::read_from(&mut cursor, num_entries) {
            Ok(pkg) => {
                let consumed = usize::try_from(cursor.position()).unwrap_or(usize::MAX);
                buf.consume(consumed);
                return Ok(ParseOutcome::Ok(pkg));
            }
            Err(ParseError::Io(ref e)) if e.kind() == ErrorKind::UnexpectedEof => {
                if !buf.pull_one().await? {
                    if buf.len() == 0 {
                        return Ok(ParseOutcome::CleanEof);
                    }
                    return Ok(ParseOutcome::MidPackageEof);
                }
            }
            Err(e) => return Ok(ParseOutcome::Err(e)),
        }
    }
}

/// Read the per-origin DO state snapshot. A non-200 status or RPC failure
/// is a transport-level error the handler maps to 500.
async fn fetch_snapshot(env: &Env, origin: &str) -> Result<MirrorStateSnapshot> {
    let stub = state_stub(env, origin)?;
    let mut resp = stub
        .fetch_with_request(Request::new_with_init(
            "http://do/get-state",
            &RequestInit {
                method: Method::Post,
                body: None,
                headers: Headers::new(),
                ..Default::default()
            },
        )?)
        .await?;
    if resp.status_code() != 200 {
        return Err(Error::from(format!(
            "DO /get-state returned {}",
            resp.status_code()
        )));
    }
    let snapshot: MirrorStateSnapshot = resp.json().await?;
    Ok(snapshot)
}

/// Resolve the target pending checkpoint that this `add-entries`
/// request is uploading toward. Either:
///
///  * `upload_end == snapshot.pending.size`: use the current pending.
///  * The ticket round-trips and yields a past pending whose
///    embedded checkpoint has size `upload_end` and verifies against
///    the trusted log keys: use that.
///
/// Returns `Err(reason)` (a static `&str` describing why) when
/// neither path produces a target. The frontend turns the error into
/// a 409 with `text/x.tlog.mirror-info`.
fn resolve_target_pending(
    env: &Env,
    header: &AddEntriesRequestHeader,
    snapshot: &MirrorStateSnapshot,
    verifiers: &signed_note::VerifierList,
) -> std::result::Result<PendingCheckpoint, &'static str> {
    if header.upload_end == snapshot.pending.size {
        // Per spec: `upload_end` must be at-or-above the mirror's
        // committed checkpoint. The DO state guarantees pending >=
        // committed (the `/commit` RPC enforces it on the write
        // side), so checking against pending is sufficient.
        if header.upload_end < snapshot.committed.size {
            return Err("upload_end below committed checkpoint");
        }
        return Ok(snapshot.pending.clone());
    }

    // Try the ticket. An empty ticket can't carry a past pending, so
    // there's nothing to fall back to.
    if header.ticket.is_empty() {
        return Err("upload_end does not match current pending and no ticket provided");
    }
    let sealer = match load_ticket_sealer(env) {
        Ok(m) => m,
        Err(e) => {
            // A missing/malformed MIRROR_TICKET_KEY is an operator
            // misconfiguration, not a client error. Surface as 409
            // (which we'd return anyway) and log so an operator
            // notices.
            log::error!("add-entries: ticket sealer unavailable: {e:?}");
            return Err("ticket key unavailable");
        }
    };
    // The log origin is bound as associated data, so a ticket minted
    // for one log cannot be opened against another.
    let Ok(plaintext) = sealer.open(&header.ticket, header.log_origin.as_bytes()) else {
        return Err("ticket authentication failed");
    };
    // The ticket plaintext is the full signed-note bytes of a
    // previously accepted pending checkpoint. Re-parse and re-verify
    // against the trusted log keys; tickets are mirror-keyed so we
    // know they came from us, but the *embedded* signature is the
    // log's, and we've already established the log key isn't
    // self-signed by the ticket key.
    let Ok(note) = Note::from_bytes(&plaintext) else {
        return Err("ticket plaintext is not a valid signed note");
    };
    if let Err(e) = note.verify(verifiers) {
        match e {
            NoteError::UnverifiedNote | NoteError::InvalidSignature { .. } => {
                return Err("ticket-bound note has no valid signatures from trusted log keys");
            }
            _ => return Err("ticket-bound note failed structural verification"),
        }
    }
    let Ok(cp_text) = CheckpointText::from_bytes(note.text()) else {
        return Err("ticket-bound note text is not a valid checkpoint");
    };
    if cp_text.origin() != header.log_origin {
        return Err("ticket-bound checkpoint has a different origin");
    }
    if cp_text.size() != header.upload_end {
        return Err("ticket-bound checkpoint size != upload_end");
    }
    if cp_text.size() < snapshot.committed.size {
        return Err("ticket-bound checkpoint size < committed checkpoint size");
    }
    Ok(PendingCheckpoint {
        size: cp_text.size(),
        hash: *cp_text.hash(),
        signed_note_bytes: plaintext,
    })
}

/// Verify a single [`EntryPackage`] against the target pending
/// checkpoint at `upload_end`.
///
/// A package's subtree is `[subtree_start, pkg_end)` where `subtree_start`
/// is `pkg_start` rounded down to a [`PACKAGE_ALIGNMENT`] (256) boundary.
/// Only the *first* package of a request can have `pkg_start >
/// subtree_start`, when the client's `upload_start` is not
/// 256-aligned; the leading leaves `[subtree_start, pkg_start)` are then
/// already in the log and supplied here as `prefix_leaves` (read from
/// storage by the caller). For every other package `prefix_leaves` is
/// empty and `subtree_start == pkg_start`.
///
/// `prefix_leaves` and `pkg.entries` are the raw entry bytes for the
/// contiguous leaves `[subtree_start, pkg_end)`.
///
/// Returns `Err(reason)` if proof verification fails.
fn verify_package(
    prefix_leaves: &[Vec<u8>],
    pkg: &EntryPackage,
    subtree_start: u64,
    pkg_end: u64,
    target: &PendingCheckpoint,
) -> std::result::Result<(), &'static str> {
    debug_assert!(
        subtree_start.is_multiple_of(PACKAGE_ALIGNMENT),
        "subtree_start must be 256-aligned"
    );
    let prefix_len = u64::try_from(prefix_leaves.len()).map_err(|_| "prefix too large")?;
    let pkg_start = subtree_start + prefix_len;
    let received = u64::try_from(pkg.entries.len()).map_err(|_| "package has too many entries")?;
    if received != pkg_end - pkg_start {
        return Err("package entry count != range size");
    }

    // Reconstruct the package's subtree hash as a standalone Merkle tree
    // over its `count = prefix_len + received` leaves (committed
    // `prefix_leaves` first, then uploaded `pkg.entries`). Leaves are
    // replayed with *local* 0-based indices so a subtree-completing leaf
    // merges only within the subtree; replaying with absolute indices
    // would, at a subtree boundary, reach for a left sibling outside it
    // (e.g. leaf 511 of `[256,512)` would reach for `[0,256)`).
    let count = prefix_len + received;
    let mut store: HashMap<u64, Hash> =
        HashMap::with_capacity(usize::try_from(2 * count).unwrap_or(usize::MAX));
    let mut next_idx = stored_hash_index(0, 0);
    for (local_index, entry) in prefix_leaves.iter().chain(pkg.entries.iter()).enumerate() {
        let hashes = {
            let reader = MapReader { store: &store };
            stored_hashes_for_record_hash(
                local_index as u64,
                tlog_core::record_hash(entry),
                &reader,
            )
            .map_err(|_| "failed to compute stored hashes for leaf")?
        };
        for h in hashes {
            store.insert(next_idx, h);
            next_idx += 1;
        }
    }
    let reader = MapReader { store: &store };
    let Ok(pkg_hash) = tree_hash(count, &reader) else {
        return Err("failed to compute package subtree hash");
    };

    // The package's subtree is `[subtree_start, pkg_end)`. `Subtree::new`
    // requires `subtree_start` to be aligned to the next-power-of-2 >=
    // `pkg_end - subtree_start`; the 256-aligned `subtree_start` and a
    // span of at most 256 leaves guarantee that.
    let subtree =
        Subtree::new(subtree_start, pkg_end).map_err(|_| "package range is not a valid subtree")?;

    // Verify the consistency proof against the target tree size.
    if verify_subtree_consistency_proof(&pkg.proof, target.size, target.hash, &subtree, pkg_hash)
        .is_err()
    {
        return Err("subtree consistency proof failed");
    }

    Ok(())
}

/// Build a `text/x.tlog.mirror-info` response carrying the mirror's
/// current pending tree size, the advertised `next_entry`, and a sealed
/// ticket, at the given HTTP `status`.
///
/// The ticket is sealed via [`tlog_mirror::TicketSealer`] (AES-256-GCM-SIV, log
/// origin bound as associated data) so the client can present it on
/// retry to recover the pending state without keeping it in DO storage.
/// If sealing fails (operator misconfigured `MIRROR_TICKET_KEY`), the
/// response still carries an empty ticket; the client falls back to a
/// `(0, 0)` initial query.
///
/// Two status codes use this shape (see [`mirror_info_409`] /
/// [`mirror_info_202`]):
///
///   * `409 Conflict`: the request could not be applied (stale
///     `upload_start`/`upload_end`, no matching pending). `next_entry`
///     reports the persisted frontier so the client can resume.
///   * `202 Accepted`: a partial run of packages was persisted;
///     `next_entry` reports the *advanced* frontier so the client
///     continues from there.
fn mirror_info_response(
    env: &Env,
    snapshot: &MirrorStateSnapshot,
    origin: &str,
    status: StatusCode,
    next_entry: u64,
) -> axum::response::Response {
    let ticket = if snapshot.pending.signed_note_bytes.is_empty() {
        Vec::new()
    } else {
        match load_ticket_sealer(env) {
            // Bind the log origin as associated data so the ticket can
            // only be reopened for the same log.
            Ok(m) => m.seal(&snapshot.pending.signed_note_bytes, origin.as_bytes()),
            Err(e) => {
                log::error!("add-entries: cannot seal ticket: {e:?}");
                Vec::new()
            }
        }
    };
    let info = MirrorInfo {
        tree_size: snapshot.pending.size,
        next_entry,
        ticket,
    };
    (
        status,
        [(CONTENT_TYPE, MIRROR_INFO_CONTENT_TYPE)],
        info.to_body(),
    )
        .into_response()
}

/// 409 Conflict carrying the mirror's current state. Advertises the
/// persisted frontier (`next_entry.size`) as the resume point.
fn mirror_info_409(
    env: &Env,
    snapshot: &MirrorStateSnapshot,
    origin: &str,
) -> axum::response::Response {
    mirror_info_response(
        env,
        snapshot,
        origin,
        StatusCode::CONFLICT,
        snapshot.next_entry.size,
    )
}

/// 202 Accepted after a partial persist. Advertises the freshly-advanced
/// persisted frontier so the client resumes appending from there.
fn mirror_info_202(
    env: &Env,
    snapshot: &MirrorStateSnapshot,
    origin: &str,
    next_entry: u64,
) -> axum::response::Response {
    mirror_info_response(env, snapshot, origin, StatusCode::ACCEPTED, next_entry)
}

/// A [`HashReader`] backed by a sparse `HashMap<u64, Hash>` indexed
/// by absolute stored-hash index. Used during package verification
/// to reconstruct the subtree hash from leaves we just received,
/// without needing access to the mirror's full storage backend.
struct MapReader<'a> {
    store: &'a HashMap<u64, Hash>,
}

impl HashReader for MapReader<'_> {
    fn read_hashes(&self, indexes: &[u64]) -> std::result::Result<Vec<Hash>, TlogError> {
        indexes
            .iter()
            .map(|i| {
                self.store
                    .get(i)
                    .copied()
                    .ok_or(TlogError::IndexesNotInTree)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{MapReader, verify_package};
    use crate::mirror_state_do::PendingCheckpoint;
    use std::collections::HashMap;
    use tlog_core::{Hash, Subtree, stored_hash_index, stored_hashes, tree_hash};
    use tlog_mirror::EntryPackage;

    /// Deterministic distinct entry bytes for leaf `i`.
    fn entry(i: u64) -> Vec<u8> {
        format!("entry-{i}").into_bytes()
    }

    /// Build a full in-memory stored-hash store for the first `n` leaves.
    fn build_store(n: u64) -> HashMap<u64, Hash> {
        let mut store: HashMap<u64, Hash> = HashMap::new();
        for i in 0..n {
            let hashes = stored_hashes(i, &entry(i), &MapReader { store: &store }).unwrap();
            for (j, h) in hashes.iter().enumerate() {
                store.insert(stored_hash_index(0, i) + j as u64, *h);
            }
        }
        store
    }

    /// Construct the target pending checkpoint and a verified package for
    /// the subtree `[subtree_start, pkg_end)` of a tree of size `target`.
    /// `pkg_start` is where the *uploaded* entries begin, so leaves
    /// `[subtree_start, pkg_start)` become the committed prefix.
    fn fixture(
        target: u64,
        subtree_start: u64,
        pkg_start: u64,
        pkg_end: u64,
    ) -> (Vec<Vec<u8>>, EntryPackage, PendingCheckpoint) {
        let store = build_store(target);
        let reader = MapReader { store: &store };
        let target_hash = tree_hash(target, &reader).unwrap();
        let subtree = Subtree::new(subtree_start, pkg_end).unwrap();
        let proof = tlog_core::subtree_consistency_proof(target, &subtree, &reader).unwrap();

        let prefix: Vec<Vec<u8>> = (subtree_start..pkg_start).map(entry).collect();
        let pkg = EntryPackage {
            entries: (pkg_start..pkg_end).map(entry).collect(),
            proof,
        };
        let cp = PendingCheckpoint {
            size: target,
            hash: target_hash,
            signed_note_bytes: Vec::new(),
        };
        (prefix, pkg, cp)
    }

    #[test]
    fn verify_aligned_package_ok() {
        // Aligned first package: no committed prefix.
        let (prefix, pkg, cp) = fixture(1000, 256, 256, 512);
        assert!(prefix.is_empty());
        verify_package(&prefix, &pkg, 256, 512, &cp).expect("aligned package verifies");
    }

    #[test]
    fn verify_nonaligned_first_package_with_prefix_ok() {
        // upload_start = 300 (non-aligned): subtree starts at 256, and the
        // committed leaves [256, 300) are supplied as the prefix.
        let (prefix, pkg, cp) = fixture(1000, 256, 300, 512);
        assert_eq!(prefix.len(), 44);
        verify_package(&prefix, &pkg, 256, 512, &cp).expect("non-aligned package verifies");
    }

    #[test]
    fn verify_first_ever_package_from_zero_ok() {
        // Subtree rooted at 0 (first bundle), partial last package.
        let (prefix, pkg, cp) = fixture(300, 0, 0, 256);
        verify_package(&prefix, &pkg, 0, 256, &cp).expect("first bundle verifies");
    }

    #[test]
    fn verify_rejects_wrong_prefix() {
        // A prefix leaf that doesn't match the committed entry yields the
        // wrong subtree hash, so proof verification must fail.
        let (mut prefix, pkg, cp) = fixture(1000, 256, 300, 512);
        prefix[0] = b"tampered".to_vec();
        assert!(verify_package(&prefix, &pkg, 256, 512, &cp).is_err());
    }

    #[test]
    fn verify_rejects_wrong_target_hash() {
        let (prefix, pkg, mut cp) = fixture(1000, 256, 300, 512);
        cp.hash = Hash([0xab; tlog_core::HASH_SIZE]);
        assert!(verify_package(&prefix, &pkg, 256, 512, &cp).is_err());
    }

    #[test]
    fn verify_rejects_entry_count_mismatch() {
        let (prefix, mut pkg, cp) = fixture(1000, 256, 300, 512);
        pkg.entries.push(entry(999)); // one too many
        assert_eq!(
            verify_package(&prefix, &pkg, 256, 512, &cp),
            Err("package entry count != range size")
        );
    }

    #[test]
    fn verify_rejects_tampered_entry() {
        let (prefix, mut pkg, cp) = fixture(1000, 256, 300, 512);
        pkg.entries[0] = b"not the real entry".to_vec();
        assert!(verify_package(&prefix, &pkg, 256, 512, &cp).is_err());
    }
}
