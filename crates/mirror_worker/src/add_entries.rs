// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! `POST /add-entries` handler.
//!
//! Implements the [c2sp.org/tlog-mirror `add-entries`][add-e] endpoint:
//! stream the (optionally gzip) request body, verify each [`EntryPackage`]
//! against the target pending checkpoint with a subtree consistency proof,
//! and incrementally persist the verified entries as bundles and hash
//! tiles (see [`crate::commit`]), advancing the persisted-entry frontier.
//!
//! Packages are committed in chunks of `commit_packages` (config,
//! default 32) rather than buffering the whole body: every
//! `commit_packages` verified packages are flushed to storage and the
//! frontier is advanced, bounding in-memory buffering and giving durable
//! mid-request progress, per the tlog-mirror streaming model. The mirror
//! checkpoint is cosigned only once the whole upload is durably committed.
//!
//! A complete upload writes the cosigned checkpoint and returns 200 with
//! the mirror's [cosignature][cosig] line(s); a client-truncated upload
//! keeps the flushed prefix and returns 202 with the advanced next entry
//! so the client can resume (see [Processing][proc]).
//!
//! [add-e]: https://c2sp.org/tlog-mirror#add-entries
//! [proc]: https://c2sp.org/tlog-mirror#processing
//! [cosig]: https://c2sp.org/tlog-cosignature
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

use generic_log_worker::{ObjectBackend, util::now_millis};

use crate::{
    body::{self, BodyError},
    commit,
    frontend_worker::{ApiResult, AppError},
    load_mirror_signer, load_ticket_sealer, log_verifiers,
    mirror_state_do::{
        AdvanceNextEntryRequest, CommitRequest, CommittedCheckpoint, MirrorStateSnapshot,
        NextEntry, PendingCheckpoint, state_stub,
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
    // Spec: the add-entries request body MUST have Content-Type
    // application/octet-stream. Reject anything else up front (before
    // spending time reading or decoding the body).
    let (parts, body) = req.into_parts();
    if !content_type_is_octet_stream(&parts.headers) {
        return Err(AppError::UnsupportedMediaType(
            "add-entries requires Content-Type: application/octet-stream".to_owned(),
        ));
    }

    // No DefaultBodyLimit: Cloudflare enforces a request-body cap at the
    // edge (100 MB, higher on paid plans) and 413s oversized bodies there.
    // Clients on body-limited platforms truncate at a package boundary and
    // resume via the 202 + advanced next_entry (tlog-mirror "Implementation
    // Considerations"). The Workers runtime does not decompress request
    // bodies, so gzip-encoded bodies are gunzipped here; unknown encodings
    // are 415'd (see `crate::body`).
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
    // add-checkpoint (tlog-mirror "Processing"). Empty pending signed-note bytes
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

    // Spec (add-entries "Processing"): reject when excess_entries is too
    // large. These are entries in [upload_start, next_entry) that are
    // already persisted, so they are re-verified (subtree consistency) but
    // not re-saved. Without a bound a client could set upload_start=0 and
    // force the mirror to re-verify the entire persisted prefix on every
    // request (a cheap DoS). A legitimate resume sets upload_start to the
    // persisted frontier, or, when the frontier is mid-tile, to the
    // frontier rounded down to a 256 boundary; excess_entries is then at
    // most one package (256), which is our threshold.
    let excess = excess_entries(
        header.upload_start,
        header.upload_end,
        snapshot.next_entry.size,
    );
    if excess > PACKAGE_ALIGNMENT {
        log::info!(
            "add-entries: rejecting upload_start={us} with excess_entries {excess} > {PACKAGE_ALIGNMENT} (next_entry={ne})",
            us = header.upload_start,
            ne = snapshot.next_entry.size,
        );
        return Ok(mirror_info_409(&env, &snapshot, &header.log_origin));
    }

    let first_prefix = first_package_prefix(
        &env,
        &header,
        snapshot.next_entry.size,
        snapshot.next_entry.hash,
    )
    .await?;

    stream_and_commit(&env, &header, &snapshot, &target, &mut buf, &first_prefix).await
}

/// Return true iff the request's `Content-Type` is
/// `application/octet-stream`, ignoring any parameters (e.g. charset).
fn content_type_is_octet_stream(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        == "application/octet-stream"
}

/// Stream, verify, and incrementally persist the entry packages for
/// `[upload_start, upload_end)`, then produce the HTTP response.
///
/// Packages are read and verified in canonical order and buffered until
/// `commit_packages` (config, default 32) have accumulated, then flushed
/// as entry bundles + hash tiles with the persisted-entry frontier
/// advanced in the DO (see [`flush_chunk`]). This bounds in-memory
/// buffering and gives durable mid-request progress rather than deferring
/// every write to the end of the body. Entries below the frontier at
/// request start are already persisted, so they are verified but not
/// re-saved (spec: "skip saving already-written entries").
///
/// The running frontier `(size, hash)` is threaded locally across flushes
/// from each [`commit::persist_entries`] result, so the DO is not
/// re-queried between chunks. Because tiles are immutable and
/// content-addressed and the DO advance is a monotone compare-and-swap, a
/// repeated or concurrent flush of the same range is harmless.
///
/// Response cases (see [Processing][proc]):
///
///   * every package received and the recomputed tree matches the target:
///     cosign the mirror checkpoint, advance it, and return 200 with the
///     cosignature line(s).
///   * client truncation after at least one complete package: return 202
///     with the advanced next entry so the client resumes.
///   * truncation before the first complete package, or a malformed body:
///     400. A package that fails subtree-consistency verification: 422.
///
/// # Errors
///
/// Returns an error on a transport failure reading the body stream, a
/// storage failure while flushing, or (500) if the recomputed root of a
/// complete upload disagrees with the target checkpoint.
///
/// [proc]: https://c2sp.org/tlog-mirror#processing
async fn stream_and_commit<S>(
    env: &Env,
    header: &AddEntriesRequestHeader,
    snapshot: &MirrorStateSnapshot,
    target: &PendingCheckpoint,
    buf: &mut StreamBuffer<S>,
    first_prefix: &[Vec<u8>],
) -> ApiResult<axum::response::Response>
where
    S: futures_util::Stream<Item = std::result::Result<Vec<u8>, BodyError>> + Unpin,
{
    let bucket = load_origin_bucket(env, &header.log_origin)?;

    let result = persist_packages(
        env,
        header,
        target,
        buf,
        first_prefix,
        &bucket,
        &snapshot.next_entry,
    )
    .await?;

    let persisted_new = result.frontier_size > snapshot.next_entry.size;

    if result.truncated {
        log::info!(
            "add-entries: client-truncated after {} complete packages; persisted through {}",
            result.packages_received,
            result.frontier_size,
        );
        return Ok(mirror_info_202(
            env,
            snapshot,
            &header.log_origin,
            result.frontier_size,
        ));
    }

    // Spec: the mirror updates its checkpoint to `upload_end` only once
    // "the next entry will be greater or equal to `upload_end`", i.e. all
    // entries up to `upload_end` are durably persisted. A request that
    // persists nothing (e.g. an empty body, or one whose packages are all
    // already-persisted) must not let us cosign past our frontier: without
    // this guard `upload_end` above `next_entry` would sign a checkpoint at
    // a size we never wrote tiles for. When the frontier has not reached
    // `upload_end`, treat it like a truncated upload and 202 so the client
    // resumes from the advertised next entry.
    if result.frontier_size < header.upload_end {
        log::info!(
            "add-entries: frontier {} below upload_end {}; nothing to persist this request, \
             returning 202 to resume",
            result.frontier_size,
            header.upload_end,
        );
        return Ok(mirror_info_202(
            env,
            snapshot,
            &header.log_origin,
            result.frontier_size,
        ));
    }

    // Every canonical package was received. Any bytes still in the stream
    // are discarded, not rejected: the spec says "the mirror discards any
    // partial bytes after the last successfully authenticated entry
    // package", and the only defined 400 is when no package authenticated
    // at all (handled in persist_packages). Rejecting here would also be
    // dishonest, since the entries were already persisted and the frontier
    // advanced.

    // When we persisted new entries, the recomputed tree MUST match the
    // pending checkpoint the packages were proven against. A mismatch
    // means proof verification and tile computation disagree: an internal
    // error, never a client fault. When nothing new was persisted (a
    // re-upload of an already-persisted range), the log-signed target is
    // trusted directly: pending checkpoints are consistency-chained on the
    // add-checkpoint path and tickets only revive our own past pendings, so
    // the target is on the same branch as the persisted tree by
    // construction.
    if persisted_new
        && (result.frontier_size != header.upload_end || result.frontier_hash != target.hash)
    {
        log::error!(
            "add-entries: recomputed frontier ({}, {}) != target ({}, {})",
            result.frontier_size,
            result.frontier_hash,
            target.size,
            target.hash,
        );
        return Err(AppError::InternalServerError(
            "recomputed root mismatch".to_owned(),
        ));
    }

    // Frontier ahead of `upload_end` (a prior upload persisted past it, or a
    // racing client): the edge tiles were written at the larger frontier, so
    // the narrower "cut" tiles a tree of size `upload_end` needs may be
    // missing and a cosignature at `upload_end` would be unverifiable against
    // our own tiles. Spec requires the tree at `upload_end` be servable before
    // cosigning, so synthesize those cut tiles first.
    if result.frontier_size > header.upload_end {
        commit::ensure_cut_tiles(
            &bucket,
            header.upload_end,
            result.frontier_size,
            result.frontier_hash,
        )
        .await?;
    }

    cosign_and_serve(env, header, target, snapshot).await
}

/// The persisted-entry frontier reached by [`persist_packages`], plus
/// whether the client truncated the stream and how many complete packages
/// were verified.
struct StreamResult {
    frontier_size: u64,
    frontier_hash: Hash,
    packages_received: u64,
    truncated: bool,
}

/// Read, verify, and incrementally flush the entry packages for
/// `[upload_start, upload_end)`, resuming from the frontier `start`.
///
/// Verified entries are buffered until `commit_packages` (config, default
/// 32) packages have accumulated, then flushed to storage with the
/// frontier advanced in the DO (see [`flush_chunk`]); the trailing partial
/// chunk is flushed before returning. Entries below `start.size` are
/// already persisted and skipped (spec: "skip saving already-written
/// entries"). The frontier `(size, hash)` is threaded locally across
/// flushes, so the DO is not re-queried between chunks.
///
/// # Errors
///
/// 400 if the body is malformed or truncates before the first complete
/// package, 422 if a package fails subtree-consistency verification, or a
/// transport/storage error from reading the body or flushing a chunk.
async fn persist_packages<S, O>(
    env: &Env,
    header: &AddEntriesRequestHeader,
    target: &PendingCheckpoint,
    buf: &mut StreamBuffer<S>,
    first_prefix: &[Vec<u8>],
    bucket: &O,
    start: &NextEntry,
) -> ApiResult<StreamResult>
where
    S: futures_util::Stream<Item = std::result::Result<Vec<u8>, BodyError>> + Unpin,
    O: ObjectBackend,
{
    // config.schema.json caps commit_packages (max 1024), enforced by the
    // build script, so this always fits usize; the fallback is unreachable.
    let commit_packages = usize::try_from(crate::CONFIG.commit_packages()).unwrap_or(usize::MAX);
    // Byte ceiling on buffered entries; flush early when reached so peak
    // memory is bounded regardless of package sizes. Saturating to
    // usize::MAX on a 32-bit target just means "never trip the byte cap",
    // leaving the package-count cap in force.
    let max_chunk_bytes = usize::try_from(crate::CONFIG.max_chunk_bytes()).unwrap_or(usize::MAX);

    // Entries below the request-start frontier are already persisted; new
    // persistence begins at this fixed boundary.
    let initial_next = start.size;

    // Running persisted-entry frontier, threaded locally across flushes.
    let mut frontier_size = start.size;
    let mut frontier_hash = start.hash;

    // Entries buffered for the next flush, the leaf index one past the last
    // buffered entry (the flush target), and how many packages are buffered.
    let mut chunk: Vec<Vec<u8>> = Vec::new();
    let mut chunk_end = frontier_size;
    let mut chunk_pkgs = 0usize;
    let mut chunk_bytes = 0usize;
    let mut packages_received: u64 = 0;
    let mut truncated = false;

    for (pkg_start, pkg_end) in package_ranges(header.upload_start, header.upload_end) {
        let num_entries = pkg_end - pkg_start;
        let pkg = match parse_next_package(buf, num_entries).await? {
            ParseOutcome::Ok(pkg) => pkg,
            // Clean and mid-package EOF are both client truncation: keep
            // whatever complete packages were already flushed/buffered.
            ParseOutcome::CleanEof | ParseOutcome::MidPackageEof => {
                truncated = true;
                break;
            }
            ParseOutcome::Err(e) => {
                // Spec: once at least one package has been authenticated
                // and saved the mirror MUST respond 202, not 400. Treat a
                // malformed later package like truncation so the verified
                // prefix is kept and the client resumes from the advanced
                // frontier; a malformed *first* package still 400s below.
                if packages_received > 0 {
                    log::info!(
                        "add-entries: malformed package [{pkg_start}, {pkg_end}) after \
                         {packages_received} authenticated; treating as truncation: {e:?}"
                    );
                    truncated = true;
                    break;
                }
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
        packages_received += 1;

        // Buffer only the not-yet-persisted tail of this package. Packages
        // wholly below the request-start frontier are already persisted, so
        // they contribute no entries and don't count toward a chunk flush;
        // `chunk_pkgs` therefore tracks only packages that added buffered
        // entries.
        if pkg_end > initial_next {
            let skip = usize::try_from(initial_next.saturating_sub(pkg_start))
                .map_err(|_| Error::from("skip count overflows usize"))?;
            let tail = pkg.entries.into_iter().skip(skip);
            for entry in tail {
                chunk_bytes = chunk_bytes.saturating_add(entry.len());
                chunk.push(entry);
            }
            chunk_end = pkg_end;
            chunk_pkgs += 1;

            // Flush when either cap trips: `commit_packages` bounds the
            // package count, `max_chunk_bytes` bounds peak memory when
            // individual packages are large. `commit_packages >= 1`
            // (config), so a full chunk always holds at least one package's
            // entries; the byte cap only fires after entries were buffered,
            // so neither branch can flush an empty chunk.
            if chunk_pkgs == commit_packages || chunk_bytes >= max_chunk_bytes {
                (frontier_size, frontier_hash) = flush_chunk(
                    bucket,
                    env,
                    &header.log_origin,
                    frontier_size,
                    frontier_hash,
                    chunk_end,
                    &mut chunk,
                )
                .await?;
                chunk_pkgs = 0;
                chunk_bytes = 0;
            }
        }
    }

    // Truncation before the first complete package is a hard 400.
    if truncated && packages_received == 0 {
        log::warn!("add-entries: stream truncated before the first complete package");
        return Err(AppError::BadRequest(
            "no complete entry package received".to_owned(),
        ));
    }

    // Flush the trailing partial chunk.
    if !chunk.is_empty() {
        (frontier_size, frontier_hash) = flush_chunk(
            bucket,
            env,
            &header.log_origin,
            frontier_size,
            frontier_hash,
            chunk_end,
            &mut chunk,
        )
        .await?;
    }

    Ok(StreamResult {
        frontier_size,
        frontier_hash,
        packages_received,
        truncated,
    })
}

/// The spec's `excess_entries = min(upload_end, next_entry) -
/// upload_start`: the count of already-persisted entries a request
/// re-verifies without re-saving (see add-entries "Processing").
///
/// Saturates at 0 so an `upload_start` above the frontier (rejected
/// separately) can't underflow.
fn excess_entries(upload_start: u64, upload_end: u64, next_entry: u64) -> u64 {
    next_entry.min(upload_end).saturating_sub(upload_start)
}

/// Cosign the target checkpoint with the mirror key, advance the durable
/// mirror checkpoint via the DO, and return the 200 response carrying the
/// mirror cosignature line(s).
///
/// Called only once the whole upload is durably committed (spec: the
/// mirror MUST NOT sign until all entries are committed).
///
/// The DO's `/commit` both advances the durable checkpoint and writes the
/// served checkpoint object to R2, serialized under its commit lock, so
/// concurrent commits cannot rewind the served checkpoint. The frontend
/// therefore does not write R2 itself.
///
/// If the DO reports a committed size ahead of `upload_end`, a concurrent
/// `add-entries` already advanced the mirror checkpoint past this upload.
/// Per the spec's final step ("If `upload_end` was too small, the mirror
/// MUST respond with a 409 Conflict") this returns a 409 with mirror-info
/// so the client resyncs, rather than a 200 that would falsely claim the
/// client's smaller checkpoint is being served.
///
/// # Errors
///
/// Returns an error if the target note/checkpoint fails to parse, signing
/// fails, or the DO commit fails.
async fn cosign_and_serve(
    env: &Env,
    header: &AddEntriesRequestHeader,
    target: &PendingCheckpoint,
    snapshot: &MirrorStateSnapshot,
) -> ApiResult<axum::response::Response> {
    // The checkpoint text comes from the log-signed pending note; the
    // response is the bare cosignature line(s), identical to a witness's
    // add-checkpoint response.
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

    // The served checkpoint is the log's signed note with the mirror's
    // cosignature appended. Build it once so both the early-return and the
    // `/commit` paths use the same bytes.
    let checkpoint_obj = [target.signed_note_bytes.as_slice(), &cosig_body].concat();

    // When the upload only reaches the mirror checkpoint's current size,
    // the checkpoint at that size is already committed and served. There
    // is nothing to advance, and re-committing would redundantly rewrite
    // R2 and append a duplicate cosignature line to the served note, so
    // return a fresh cosignature without dispatching `/commit`. (Committed
    // is monotonic, so a stale-low snapshot only skips this optimization,
    // never the other way.)
    //
    // Note: this also means a previously-failed R2 checkpoint write won't
    // self-heal at the same size; it heals on the next larger commit. That
    // is acceptable because the durable committed state advanced before the
    // R2 write, and duplicate cosignatures are worse than a lagging object.
    if header.upload_end <= snapshot.committed.size {
        return Ok((
            StatusCode::OK,
            [(CONTENT_TYPE, "text/plain; charset=utf-8")],
            cosig_body,
        )
            .into_response());
    }

    // The DO writes the cosigned checkpoint to R2 while advancing the
    // durable checkpoint under its commit lock.
    let committed = dispatch_commit(
        env,
        &header.log_origin,
        &CommitRequest {
            size: header.upload_end,
            hash: target.hash,
            signed_note_bytes: checkpoint_obj.clone(),
        },
    )
    .await?;

    debug_assert_eq!(
        committed.signed_note_bytes, checkpoint_obj,
        "DO returned checkpoint bytes that do not match the cosigned note we sent"
    );

    if committed.size != header.upload_end {
        // The DO refused to rewind: a concurrent commit already advanced
        // the mirror checkpoint past upload_end, so ours was skipped.
        // Fetch the latest state so the 409 mirror-info body advertises
        // the current pending size and next entry, not the stale snapshot
        // from the start of this request.
        log::info!(
            "add-entries: commit skipped, mirror checkpoint {} already past upload_end {}; \
             returning 409",
            committed.size,
            header.upload_end,
        );
        let fresh_snapshot = match fetch_snapshot(env, &header.log_origin).await {
            Ok(s) => s,
            Err(e) => {
                log::warn!(
                    "add-entries: failed to fetch fresh snapshot for 409; using stale: {e:?}"
                );
                snapshot.clone()
            }
        };
        return Ok(mirror_info_409(env, &fresh_snapshot, &header.log_origin));
    }

    Ok((
        StatusCode::OK,
        [(CONTENT_TYPE, "text/plain; charset=utf-8")],
        cosig_body,
    )
        .into_response())
}

/// Persist the buffered `chunk` (the entries `[frontier_size, chunk_end)`)
/// as entry bundles + hash tiles resuming from the current frontier,
/// advance the persisted-entry frontier in the DO, and return the new
/// frontier `(chunk_end, root)`. Clears `chunk`.
///
/// [`commit::persist_entries`] writes immutable, content-addressed tiles
/// and the DO advance is a monotone compare-and-swap, so a repeated or
/// concurrent flush of the same range is a harmless no-op.
///
/// # Errors
///
/// Returns an error on a storage failure or if the DO advance RPC fails.
async fn flush_chunk<O: ObjectBackend>(
    bucket: &O,
    env: &Env,
    origin: &str,
    frontier_size: u64,
    frontier_hash: Hash,
    chunk_end: u64,
    chunk: &mut Vec<Vec<u8>>,
) -> Result<(u64, Hash)> {
    let root =
        commit::persist_entries(bucket, frontier_size, frontier_hash, chunk_end, chunk).await?;
    advance_next_entry(env, origin, chunk_end, root).await?;
    chunk.clear();
    Ok((chunk_end, root))
}

/// Read the persisted-leaf prefix required to verify a non-256-aligned
/// first package: the leaves `[subtree_start, upload_start)` where
/// `subtree_start` is `upload_start` rounded down to a 256 boundary.
///
/// Returns an empty vec when `upload_start` is already 256-aligned (the
/// common case and every non-first package). Because `upload_start <=
/// next_entry.size` is enforced upstream, the requested leaves are always
/// present in storage.
///
/// The prefix is authenticated against the frontier hash tiles inside
/// [`commit::read_persisted_leaves`]; `persisted_hash` is the frontier
/// root at `persisted_size`.
///
/// # Errors
///
/// Returns an error if opening the origin bucket or reading the persisted
/// entry bundle fails, or the reloaded leaves fail authentication.
async fn first_package_prefix(
    env: &Env,
    header: &AddEntriesRequestHeader,
    persisted_size: u64,
    persisted_hash: Hash,
) -> Result<Vec<Vec<u8>>> {
    let subtree_start = (header.upload_start / PACKAGE_ALIGNMENT) * PACKAGE_ALIGNMENT;
    if header.upload_start == subtree_start {
        return Ok(Vec::new());
    }
    let bucket = load_origin_bucket(env, &header.log_origin)?;
    commit::read_persisted_leaves(
        &bucket,
        subtree_start,
        header.upload_start - subtree_start,
        persisted_size,
        persisted_hash,
    )
    .await
}

/// POST the [`CommitRequest`] to the per-origin DO, advancing the mirror
/// checkpoint, and return the DO's resulting [`CommittedCheckpoint`].
///
/// The returned checkpoint may be ahead of `commit_req` when a concurrent
/// `add-entries` already advanced past it (the DO refuses to rewind); the
/// caller compares sizes to detect that skip. A non-200 status (a
/// `/commit` beyond the persisted frontier) is a frontend/mirror bug,
/// surfaced as a transport error that the handler maps to 500.
async fn dispatch_commit(
    env: &Env,
    origin: &str,
    commit_req: &CommitRequest,
) -> Result<CommittedCheckpoint> {
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
        200 => Ok(resp.json().await?),
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
/// stream errors. Returns the parsed header, or
/// [`AppError::BadRequest`] (400) if the input is malformed or truncated
/// before the header is complete.
///
/// The header has a bounded maximum size (u16 origin + u64s + u16
/// ticket + hash + u8 proof-size + 63 hashes <= ~131 KB), so the
/// retry-on-`UnexpectedEof` loop terminates.
async fn parse_header<S>(buf: &mut StreamBuffer<S>) -> ApiResult<AddEntriesRequestHeader>
where
    S: futures_util::Stream<Item = std::result::Result<Vec<u8>, BodyError>> + Unpin,
{
    loop {
        let mut cursor = Cursor::new(buf.buffered());
        match AddEntriesRequestHeader::read_from(&mut cursor) {
            Ok(header) => {
                let consumed = usize::try_from(cursor.position()).unwrap_or(usize::MAX);
                buf.consume(consumed);
                return Ok(header);
            }
            // Short read: the whole header is not buffered yet. Pull more
            // and retry; a real EOF here means a truncated header.
            Err(ParseError::Io(ref e)) if e.kind() == ErrorKind::UnexpectedEof => {
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
async fn parse_next_package<S>(
    buf: &mut StreamBuffer<S>,
    num_entries: u64,
) -> ApiResult<ParseOutcome>
where
    S: futures_util::Stream<Item = std::result::Result<Vec<u8>, BodyError>> + Unpin,
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
                    // Stream ended mid-parse. An empty buffer means the
                    // previous package consumed exactly all buffered bytes
                    // and this call started a fresh (never-arriving)
                    // package: a clean between-package truncation. A
                    // non-empty buffer holds a partial package.
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
/// request is uploading toward. Any of:
///
///  * `upload_end == snapshot.pending.size`: use the current pending.
///  * `upload_end == snapshot.committed.size`: use the mirror
///    checkpoint, which the spec requires the mirror to accept as a
///    valid `upload_end` independent of any ticket.
///  * The ticket round-trips and yields a past pending whose
///    embedded checkpoint has size `upload_end` and verifies against
///    the trusted log keys: use that.
///
/// Returns `Err(reason)` (a static `&str` describing why) when
/// none of these produce a target. The frontend turns the error into
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

    // Spec: the mirror MUST also accept `upload_end` equal to the mirror
    // checkpoint's tree size, whatever the ticket says. Everything up to
    // it is already committed and served, so the committed checkpoint is
    // the target and nothing new is persisted; `cosign_and_serve` returns
    // a fresh cosignature without re-advancing.
    if snapshot.committed.size > 0 && header.upload_end == snapshot.committed.size {
        return Ok(PendingCheckpoint {
            size: snapshot.committed.size,
            hash: snapshot.committed.hash,
            signed_note_bytes: snapshot.committed.signed_note_bytes.clone(),
        });
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
    // over its `count = prefix_len + received` leaves (persisted
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
    use super::{
        CONTENT_TYPE, MapReader, content_type_is_octet_stream, excess_entries, parse_header,
        verify_package,
    };
    use crate::body::BodyError;
    use crate::mirror_state_do::PendingCheckpoint;
    use crate::stream_buffer::StreamBuffer;
    use std::collections::HashMap;
    use tlog_core::{Hash, Subtree, stored_hash_index, stored_hashes, tree_hash};
    use tlog_mirror::EntryPackage;
    use tlog_mirror::{AddEntriesRequestHeader, PACKAGE_ALIGNMENT};

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
    /// `[subtree_start, pkg_start)` become the persisted prefix.
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
        // Aligned first package: no persisted prefix.
        let (prefix, pkg, cp) = fixture(1000, 256, 256, 512);
        assert!(prefix.is_empty());
        verify_package(&prefix, &pkg, 256, 512, &cp).expect("aligned package verifies");
    }

    #[test]
    fn verify_nonaligned_first_package_with_prefix_ok() {
        // upload_start = 300 (non-aligned): subtree starts at 256, and the
        // persisted leaves [256, 300) are supplied as the prefix.
        let (prefix, pkg, cp) = fixture(1000, 256, 300, 512);
        assert_eq!(prefix.len(), 44);
        verify_package(&prefix, &pkg, 256, 512, &cp).expect("non-aligned package verifies");
    }

    #[test]
    fn verify_nonaligned_first_package_max_prefix_ok() {
        // Largest prefix a non-aligned first package can carry: upload_start
        // = 511 leaves persisted [256, 511) as a 255-leaf prefix, with a
        // single uploaded entry [511, 512) closing the subtree.
        let (prefix, pkg, cp) = fixture(1000, 256, 511, 512);
        assert_eq!(prefix.len(), 255);
        assert_eq!(pkg.entries.len(), 1);
        verify_package(&prefix, &pkg, 256, 512, &cp).expect("max-prefix package verifies");
    }

    #[test]
    fn verify_first_ever_package_from_zero_ok() {
        // Subtree rooted at 0 (first bundle), partial last package.
        let (prefix, pkg, cp) = fixture(300, 0, 0, 256);
        verify_package(&prefix, &pkg, 0, 256, &cp).expect("first bundle verifies");
    }

    #[test]
    fn verify_rejects_wrong_prefix() {
        // A prefix leaf that doesn't match the persisted entry yields the
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

    #[test]
    fn excess_entries_resume_at_frontier_is_zero() {
        // The common resume: upload_start == next_entry, no overlap.
        assert_eq!(excess_entries(2816, 3000, 2816), 0);
    }

    #[test]
    fn excess_entries_mid_tile_resume_within_one_package() {
        // Mid-tile frontier: client rounds upload_start down to the 256
        // boundary, so overlap is the sub-256 tail and is accepted.
        let next_entry = 600;
        let upload_start = 512; // 600 rounded down to a 256 boundary
        assert_eq!(
            excess_entries(upload_start, 1000, next_entry),
            next_entry - upload_start
        );
        assert!(excess_entries(upload_start, 1000, next_entry) <= PACKAGE_ALIGNMENT);
    }

    #[test]
    fn excess_entries_from_zero_reverifies_whole_prefix() {
        // The DoS case: upload_start=0 against a large frontier forces
        // re-verification of the entire persisted prefix, well over the
        // one-package threshold.
        let excess = excess_entries(0, 10_000, 5_000);
        assert_eq!(excess, 5_000);
        assert!(excess > PACKAGE_ALIGNMENT);
    }

    #[test]
    fn excess_entries_bounded_by_upload_end() {
        // Only entries below upload_end count as already-persisted overlap.
        assert_eq!(excess_entries(100, 300, 5_000), 200);
    }

    #[test]
    fn excess_entries_saturates_above_frontier() {
        // upload_start past the frontier (rejected separately) must not
        // underflow.
        assert_eq!(excess_entries(5_000, 6_000, 4_000), 0);
    }

    #[test]
    fn content_type_octet_stream_accepted() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/octet-stream".parse().unwrap());
        assert!(content_type_is_octet_stream(&headers));
    }

    #[test]
    fn content_type_octet_stream_with_params_accepted() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            "application/octet-stream; charset=binary".parse().unwrap(),
        );
        assert!(content_type_is_octet_stream(&headers));
    }

    #[test]
    fn content_type_missing_rejected() {
        let headers = axum::http::HeaderMap::new();
        assert!(!content_type_is_octet_stream(&headers));
    }

    #[test]
    fn content_type_non_octet_stream_rejected() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(!content_type_is_octet_stream(&headers));
    }

    fn header_bytes() -> Vec<u8> {
        let header = AddEntriesRequestHeader {
            log_origin: "rome.ct.example.com/2026h1".to_owned(),
            upload_start: 256,
            upload_end: 512,
            ticket: b"opaque-ticket".to_vec(),
        };
        let mut buf = Vec::new();
        header.write_to(&mut buf).unwrap();
        buf
    }

    fn stream_buffer(
        chunks: Vec<Vec<u8>>,
    ) -> StreamBuffer<impl futures_util::Stream<Item = Result<Vec<u8>, BodyError>> + Unpin> {
        StreamBuffer::new(futures_util::stream::iter(
            chunks.into_iter().map(Ok::<_, BodyError>),
        ))
    }

    // A header delivered as single-byte chunks must reassemble.
    #[tokio::test(flavor = "current_thread")]
    async fn parse_header_reassembles_byte_by_byte() {
        let bytes = header_bytes();
        let chunks: Vec<Vec<u8>> = bytes.iter().map(|b| vec![*b]).collect();
        let mut buf = stream_buffer(chunks);
        let Ok(header) = parse_header(&mut buf).await else {
            panic!("header reassembles");
        };
        assert_eq!(header.log_origin, "rome.ct.example.com/2026h1");
        assert_eq!(header.upload_start, 256);
        assert_eq!(header.upload_end, 512);
        assert_eq!(header.ticket, b"opaque-ticket");
    }

    // A header split partway through log_origin must reassemble.
    #[tokio::test(flavor = "current_thread")]
    async fn parse_header_split_inside_log_origin() {
        let bytes = header_bytes();
        let (first, rest) = bytes.split_at(3);
        let mut buf = stream_buffer(vec![first.to_vec(), rest.to_vec()]);
        let Ok(header) = parse_header(&mut buf).await else {
            panic!("header reassembles");
        };
        assert_eq!(header.log_origin, "rome.ct.example.com/2026h1");
    }

    // A stream that ends partway through log_origin is genuinely truncated
    // and must be a 400, not an endless pull loop.
    #[tokio::test(flavor = "current_thread")]
    async fn parse_header_truncated_in_log_origin_is_bad_request() {
        let bytes = header_bytes();
        let truncated = bytes[..5].to_vec();
        let mut buf = stream_buffer(vec![truncated]);
        assert!(matches!(
            parse_header(&mut buf).await,
            Err(super::AppError::BadRequest(_))
        ));
    }
}
