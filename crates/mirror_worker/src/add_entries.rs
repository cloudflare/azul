// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! `POST /add-entries` handler — slice C4a (parse + verify only).
//!
//! Implements the parse-and-verify portion of [c2sp.org/tlog-mirror's
//! `add-entries`][add-e] endpoint. The handler:
//!
//! 1. Reads the request body, capped at [`MAX_ADD_ENTRIES_BODY_SIZE`].
//! 2. Parses the [`AddEntriesRequestHeader`].
//! 3. Looks up the log by `log_origin`; 404 on unknown.
//! 4. Snapshots the per-origin DO state via `POST /get-state`.
//! 5. Resolves the *target pending checkpoint* — either the current
//!    pending state or, when `upload_end` doesn't match, a past
//!    pending checkpoint recovered from the [ticket][ticket]. 409
//!    with `text/x.tlog.mirror-info` body if neither matches.
//! 6. Validates `upload_start` and `upload_end` against the committed
//!    state. C4a additionally requires `upload_start` to be aligned
//!    to [`PACKAGE_ALIGNMENT`] (256); non-aligned `upload_start` is a
//!    409 with the current state in the ticket so the client can
//!    retry. (Lifted in C4b once the mirror can read previously
//!    committed leaves from R2.)
//! 7. Iterates each [`EntryPackage`] via [`package_ranges`]:
//!    * Parses the wire bytes.
//!    * Computes the leaf hashes for received entries via
//!      [`tlog_core::record_hash`].
//!    * Reconstructs the package's subtree hash via
//!      [`tlog_core::Subtree::hash`].
//!    * Verifies the subtree consistency proof against the target
//!      pending checkpoint via
//!      [`tlog_core::verify_subtree_consistency_proof`]. 422 on
//!      failure.
//!
//! On success the handler returns 200 with an **empty body**. C4a
//! intentionally does not persist entries, recompute tiles, advance
//! the committed checkpoint, or emit a mirror cosignature; those land
//! in slices C4b and C4c, respectively. Until then a successful
//! `add-entries` is purely a validity check.
//!
//! Slice anchoring: see
//! <https://github.com/cloudflare/azul/issues/186#issuecomment-4381622238>.
//!
//! [add-e]: https://c2sp.org/tlog-mirror#add-entries
//! [ticket]: https://c2sp.org/tlog-mirror#add-entries
//! [`AddEntriesRequestHeader`]: tlog_mirror::AddEntriesRequestHeader
//! [`EntryPackage`]: tlog_mirror::EntryPackage
//! [`package_ranges`]: tlog_mirror::package_ranges
//! [`PACKAGE_ALIGNMENT`]: tlog_mirror::PACKAGE_ALIGNMENT

use std::io::Cursor;

use std::collections::HashMap;

use signed_note::{Note, NoteError};
use tlog_checkpoint::CheckpointText;
use tlog_core::{
    stored_hash_index, stored_hashes_for_record_hash, verify_subtree_consistency_proof, Hash,
    HashReader, Subtree, TlogError,
};
use tlog_mirror::{
    package_ranges, AddEntriesRequestHeader, EntryPackage, MirrorInfo, MIRROR_INFO_CONTENT_TYPE,
    PACKAGE_ALIGNMENT,
};
#[allow(clippy::wildcard_imports)]
use worker::*;

use crate::{
    load_ticket_macer, log_verifiers,
    mirror_state_do::{state_stub, MirrorStateSnapshot, PendingCheckpoint},
};

/// Maximum size we are willing to buffer from an incoming
/// `add-entries` request body. The Workers runtime imposes a separate
/// 100 MB platform cap before any of our code runs; this constant is
/// the worker's tighter bound, sized to fit a comfortably large batch
/// of entry packages without letting a malicious client push the
/// parser into base64-decoding tens of megabytes of garbage.
///
/// The number is a knob, not a spec value. A typical entry package
/// (256 entries × a few KB each + 63 × 32-byte proof hashes) is on
/// the order of a few hundred KB, so 10 MiB comfortably accommodates
/// roughly 30–40 packages per request. Future slices may raise this
/// for fresh mirrors that need to ingest larger backfills.
const MAX_ADD_ENTRIES_BODY_SIZE: usize = 10 * 1_024 * 1_024;

/// Handle `POST /add-entries`.
///
/// See the module-level comment for the full flow. C4a: parse +
/// verify only; persistence and cosignature are future slices.
pub(crate) async fn add_entries(mut req: Request, env: Env) -> Result<Response> {
    // (1) Slurp the body subject to the cap.
    let body = req.bytes().await?;
    if body.len() > MAX_ADD_ENTRIES_BODY_SIZE {
        return Response::error(
            format!("Bad request: body exceeds {MAX_ADD_ENTRIES_BODY_SIZE} bytes"),
            400,
        );
    }

    // (2) Parse the header. The body cursor is left positioned at the
    // first entry package after this returns.
    let mut cursor = Cursor::new(body.as_slice());
    let header = match AddEntriesRequestHeader::read_from(&mut cursor) {
        Ok(h) => h,
        Err(e) => {
            log::warn!("add-entries: malformed header: {e:?}");
            return Response::error(format!("Bad request: {e}"), 400);
        }
    };

    // (3) Look up the log by origin.
    let Some(verifiers) = log_verifiers(&header.log_origin) else {
        return Response::error("Unknown log origin", 404);
    };

    // (4) Snapshot per-origin DO state for the validity checks below.
    let snapshot = match fetch_snapshot(&env, &header.log_origin).await? {
        Ok(s) => s,
        Err(resp) => return Ok(resp),
    };

    // (5) Resolve the target pending checkpoint:
    //
    //  * If `upload_end` matches the current pending size, use it.
    //  * Otherwise try to recover a past pending from the ticket.
    //  * Otherwise 409 with the current state in `text/x.tlog.mirror-info`.
    //
    // The ticket's plaintext is the signed-note bytes of a previously
    // accepted pending checkpoint; we authenticate via [`TicketMacer`]
    // (HMAC-SHA-256 truncated to 128 bits) and re-verify the log's
    // signature against the configured trusted log keys before
    // trusting the embedded `(size, hash)`.
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
            return mirror_info_409(&env, &snapshot);
        }
    };

    // (6) Validate `upload_start` against committed state.
    //
    // Per spec, `upload_start <= mirror_next_entry` (where
    // mirror_next_entry == committed.size; the next index to commit
    // is always the current committed size). C4a additionally
    // requires `upload_start % 256 == 0` because verifying a
    // non-aligned first package's subtree requires reading existing
    // committed leaves from R2 (the C4b work). When this constraint
    // bites in practice it's because a client is retrying a partial
    // upload mid-bundle; surfacing it as 409 with the current state
    // lets the client realign to a 256-boundary by re-fetching.
    //
    // NOTE: the `upload_start > committed.size` case is also caught
    // here (too-far-ahead). The "too-far-below" case isn't relevant
    // yet because we only accept aligned `upload_start`; once C4b
    // lifts that we'll need an explicit tolerance window.
    if header.upload_start > snapshot.committed.size
        || !header.upload_start.is_multiple_of(PACKAGE_ALIGNMENT)
    {
        log::info!(
            "add-entries: rejecting upload_start={us} (committed={cs}, alignment={pa})",
            us = header.upload_start,
            cs = snapshot.committed.size,
            pa = PACKAGE_ALIGNMENT,
        );
        return mirror_info_409(&env, &snapshot);
    }

    // (7) Iterate and verify each entry package against the target
    // pending checkpoint at `upload_end`.
    for (pkg_start, pkg_end) in package_ranges(header.upload_start, header.upload_end) {
        let num_entries = pkg_end - pkg_start;
        let pkg = match EntryPackage::read_from(&mut cursor, num_entries) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("add-entries: malformed package [{pkg_start}, {pkg_end}): {e:?}");
                return Response::error(format!("Bad request: {e}"), 400);
            }
        };
        if let Err(reason) = verify_package(&pkg, pkg_start, pkg_end, &target) {
            log::info!(
                "add-entries: package [{pkg_start}, {pkg_end}) failed verification: {reason}"
            );
            return Response::error(format!("Unprocessable Entity: {reason}"), 422);
        }
    }

    // (8) Sanity check: the body must be fully consumed. Trailing
    // bytes past the last package are a malformed request.
    if usize::try_from(cursor.position()).unwrap_or(usize::MAX) != body.len() {
        log::warn!(
            "add-entries: trailing data: {} bytes after the last package",
            body.len() - usize::try_from(cursor.position()).unwrap_or(usize::MAX),
        );
        return Response::error(
            "Bad request: trailing data after the last entry package",
            400,
        );
    }

    // C4a: success returns empty body. C4c will replace this with
    // mirror cosignature lines once C4b wires up persistence.
    Response::empty()
}

/// Read the per-origin DO state snapshot. Returns the snapshot on
/// success, or `Err(Response)` carrying a fully-formed error
/// response (400/500) on transport-level failure.
async fn fetch_snapshot(
    env: &Env,
    origin: &str,
) -> Result<std::result::Result<MirrorStateSnapshot, Response>> {
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
        return Ok(Err(Response::error(
            format!(
                "Internal error: DO /get-state returned {}",
                resp.status_code()
            ),
            500,
        )?));
    }
    let snapshot: MirrorStateSnapshot = resp.json().await?;
    Ok(Ok(snapshot))
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
    let macer = match load_ticket_macer(env) {
        Ok(m) => m,
        Err(e) => {
            // A missing/malformed MIRROR_TICKET_KEY is an operator
            // misconfiguration, not a client error. Surface as 409
            // (which we'd return anyway) and log so an operator
            // notices.
            log::error!("add-entries: ticket macer unavailable: {e:?}");
            return Err("ticket key unavailable");
        }
    };
    let plaintext = match macer.open(&header.ticket) {
        Ok(p) => p.to_vec(),
        Err(_) => return Err("ticket authentication failed"),
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
/// Returns `Err(reason)` if proof verification fails. C4a only
/// supports packages whose `pkg_start` is aligned to
/// [`PACKAGE_ALIGNMENT`] (256); non-aligned packages are an
/// internal-error case here because the C4a frontend already rejects
/// non-aligned `upload_start` upstream.
fn verify_package(
    pkg: &EntryPackage,
    pkg_start: u64,
    pkg_end: u64,
    target: &PendingCheckpoint,
) -> std::result::Result<(), &'static str> {
    debug_assert!(
        pkg_start.is_multiple_of(PACKAGE_ALIGNMENT),
        "C4a only handles aligned packages; should have been rejected upstream"
    );
    let received = u64::try_from(pkg.entries.len()).map_err(|_| "package has too many entries")?;
    if received != pkg_end - pkg_start {
        return Err("package entry count != range size");
    }

    // Build an in-memory hash store covering the leaves and internal
    // nodes for `[pkg_start, pkg_end)`. We replay each leaf through
    // `stored_hashes_for_record_hash`, which returns the hashes that
    // would be stored when that leaf is appended to a tree of size
    // `i`. Because the package is aligned to `PACKAGE_ALIGNMENT`,
    // the only stored hashes referenced during this replay are
    // hashes we ourselves just produced — no pre-package leaves are
    // needed (which is exactly why C4a requires alignment).
    //
    // Each iteration creates a fresh borrow of `store`; the borrow
    // is dropped before the loop body extends `store` with the new
    // hashes. This pattern keeps the borrow checker happy without
    // an unsafe split_borrow dance.
    let mut store: HashMap<u64, Hash> =
        HashMap::with_capacity(usize::try_from(2 * received).unwrap_or(usize::MAX));
    let mut next_idx = stored_hash_index(0, pkg_start);
    for (offset, entry) in pkg.entries.iter().enumerate() {
        let leaf_index = pkg_start + offset as u64;
        let hashes = {
            let reader = MapReader { store: &store };
            stored_hashes_for_record_hash(leaf_index, tlog_core::record_hash(entry), &reader)
                .map_err(|_| "failed to compute stored hashes for received leaf")?
        };
        for h in hashes {
            // We trust `stored_hashes_for_record_hash`'s contract
            // that the returned hashes correspond to consecutive
            // indexes starting at `stored_hash_index(0, leaf_index)`.
            store.insert(next_idx, h);
            next_idx += 1;
        }
    }

    // The package's subtree is `[pkg_start, pkg_end)`. Build a
    // `Subtree`; this requires `pkg_start` to be aligned to the
    // next-power-of-2 ≥ `pkg_end - pkg_start`. C4a's alignment
    // requirement guarantees this for `pkg_start` (multiple of 256)
    // and any `pkg_end - pkg_start <= 256`.
    let subtree =
        Subtree::new(pkg_start, pkg_end).map_err(|_| "package range is not a valid subtree")?;

    // Reconstruct the subtree hash from the just-built store.
    let reader = MapReader { store: &store };
    let Ok(pkg_hash) = tlog_core::subtree_hash(&subtree, &reader) else {
        return Err("failed to compute package subtree hash");
    };

    // Verify the consistency proof against the target tree size.
    if verify_subtree_consistency_proof(&pkg.proof, target.size, target.hash, &subtree, pkg_hash)
        .is_err()
    {
        return Err("subtree consistency proof failed");
    }

    Ok(())
}

/// Build the 409 response carrying the mirror's current state in
/// `text/x.tlog.mirror-info`. The ticket is sealed via
/// [`TicketMacer`] so the client can present it on retry to recover
/// the pending state without keeping it in DO storage.
///
/// If sealing the ticket fails (operator misconfigured
/// `MIRROR_TICKET_KEY`), we still return 409 but with an empty
/// ticket; the client will fall back to a `(0, 0)` initial query.
fn mirror_info_409(env: &Env, snapshot: &MirrorStateSnapshot) -> Result<Response> {
    let ticket = if snapshot.pending.signed_note_bytes.is_empty() {
        Vec::new()
    } else {
        match load_ticket_macer(env) {
            Ok(m) => m.seal(&snapshot.pending.signed_note_bytes),
            Err(e) => {
                log::error!("add-entries: cannot seal ticket: {e:?}");
                Vec::new()
            }
        }
    };
    let info = MirrorInfo {
        tree_size: snapshot.pending.size,
        next_entry: snapshot.committed.size,
        ticket,
    };
    let body = info.to_body();
    let headers = Headers::new();
    headers.set("content-type", MIRROR_INFO_CONTENT_TYPE)?;
    Ok(Response::from_body(ResponseBody::Body(body))?
        .with_status(409)
        .with_headers(headers))
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
