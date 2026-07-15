// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! `MirrorCleaner` Durable Object: deletes orphaned partial tiles from
//! the mirror's object storage.
//!
//! The commit path writes partial tiles at width-suffixed paths
//! (`.../<tile>.p/<width>`). Because the mirror commits tiles as it
//! ingests, a partial `add-entries` upload (the [C2SP/C2SP#253] 202 path)
//! persists a trailing partial; a later upload extends it with a *new*,
//! wider partial. Partials are immutable and content-addressed, so the
//! narrower ones are never overwritten and orphan, accumulating without
//! bound. This is the mirror's analogue of the garbage
//! [`generic_log_worker`]'s `GenericCleaner` collects, reimplemented for
//! the mirror's prefixed, multi-origin bucket layout (see [`crate::storage`]).
//!
//! One instance per configured origin (keyed by origin string, like
//! `MirrorState`). A self-perpetuating alarm,
//! first armed when the `add-entries` handler [kicks](kick) it after a
//! commit, wakes every `clean_interval_secs` and, for every full tile below
//! the persisted-entry frontier not yet cleaned, batch-deletes that tile's
//! `.p/` partials (plus the entry-bundle partials for a level-0 tile). A
//! per-tile `head` check confirms the full tile exists first, so a partial
//! is never removed before its replacement lands. Progress
//! (`cleaned_size`) is checkpointed after each deletion and each wake is
//! bounded by the Workers subrequest limit, resuming where the last left
//! off.
//!
//! [C2SP/C2SP#253]: https://github.com/C2SP/C2SP/pull/253

use std::{cell::RefCell, mem, time::Duration};

use tlog_tiles::{PathElem, TlogTile};
#[allow(clippy::wildcard_imports)]
use worker::*;

use crate::{
    CONFIG, MIRROR_CLEANER_BINDING,
    mirror_state_do::{MirrorStateSnapshot, state_stub},
    storage::{PUBLIC_BUCKET_BINDING, origin_hash},
};

/// Workers cap each invocation at 1000 subrequests (R2 ops included). We
/// count list/head/delete calls and bail out before crossing the limit;
/// the next alarm resumes from the checkpointed `cleaned_size`.
const SUBREQUEST_LIMIT: usize = 1000;

/// R2 `delete_multiple` accepts at most 1000 keys per call.
/// <https://developers.cloudflare.com/r2/api/workers/workers-api-reference/#bucket-method-definitions>
const MAX_DELETE_BATCH: usize = 1000;

/// One full tile spans 256 entries; the cleaner advances in these steps.
const STEP: u64 = TlogTile::FULL_WIDTH as u64;

/// DO-storage key for the checkpointed high-water mark: entries below this
/// size have had their partial tiles cleaned.
const CLEANED_SIZE_KEY: &str = "cleaned_size";

/// DO-storage key for the last-observed persisted-entry frontier, so a wake
/// that is already caught up skips the cross-DO `next_entry` read.
const CURRENT_SIZE_KEY: &str = "current_size";

/// A full tile whose existence authorizes cleaning the now-orphaned partials
/// listed under [`Self::partial_prefixes`].
struct CleanTarget {
    /// Full-tile object key; `head`-checked before any partial is deleted.
    full_tile_key: String,
    /// `.p/` key prefixes to list and delete once `full_tile_key` exists.
    partial_prefixes: Vec<String>,
}

/// Plan the partial-tile cleaning for the 256-entry tree range
/// `[lo, lo + 256)` under `origin_prefix` (`lo` MUST be 256-aligned).
///
/// For every *full* hash tile this range completes, returns the full
/// tile's object key together with the `.p/` prefixes of the partials it
/// orphans: the hash tile's own partials, plus, for a level-0 tile, the
/// matching entry-bundle (data tile) partials. Higher-level tiles have no
/// data tile, only hash-tile partials.
///
/// Pure and storage-free so it can be unit-tested; the DO layers the
/// existence check, listing, and deletion on top.
fn plan_clean(origin_prefix: &str, lo: u64) -> Vec<CleanTarget> {
    let mut out = Vec::new();
    for tile in TlogTile::new_tiles(lo, lo + STEP) {
        // Only a completed full tile makes its narrower partials garbage.
        if tile.width() != TlogTile::FULL_WIDTH {
            continue;
        }
        let mut partial_prefixes = vec![format!("{origin_prefix}{}.p/", tile.path())];
        if tile.level() == 0 {
            partial_prefixes.push(format!(
                "{origin_prefix}{}.p/",
                tile.with_data_path(PathElem::Entries).path()
            ));
        }
        out.push(CleanTarget {
            full_tile_key: format!("{origin_prefix}{}", tile.path()),
            partial_prefixes,
        });
    }
    out
}

/// A per-origin partial-tile cleaner. See the module comment.
#[durable_object(alarm)]
struct MirrorCleaner {
    state: State,
    env: Env,
    /// The origin this instance cleans, recovered in [`Self::new`].
    origin: &'static str,
    /// `<origin hash>/` key prefix for this origin in the shared bucket.
    prefix: String,
    bucket: Bucket,
    cleaned_size: RefCell<u64>,
    current_size: RefCell<u64>,
    subrequests: RefCell<usize>,
    initialized: RefCell<bool>,
}

// SAFETY: Durable Objects are single-threaded; the `RefUnwindSafe` bound
// is required by `wasm-bindgen` when building with `panic=unwind` (so the
// sentry catch-unwind guard can wrap the fetch/alarm handlers).
impl std::panic::RefUnwindSafe for MirrorCleaner {}

impl DurableObject for MirrorCleaner {
    fn new(state: State, env: Env) -> Self {
        // Recover which origin's instance this is from the DO name the
        // runtime provides, matching it to the served-origin set to get a
        // 'static slice. An MTC CA's log-number window is already expanded
        // to concrete origins by `crate::log_origins`.
        let name = state
            .id()
            .name()
            .expect("durable object name not provided by runtime");
        let origin = crate::log_origins()
            .find(|o| *o == name)
            .expect("durable object name is not a served origin");
        let prefix = format!("{}/", origin_hash(origin));
        let bucket = env
            .bucket(PUBLIC_BUCKET_BINDING)
            .expect("PUBLIC_BUCKET binding must be a configured R2 bucket");
        crate::init_sentry(&env);
        Self {
            bucket,
            origin,
            prefix,
            cleaned_size: RefCell::new(0),
            current_size: RefCell::new(0),
            subrequests: RefCell::new(0),
            initialized: RefCell::new(false),
            state,
            env,
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        generic_log_worker::obs::sentry::catch_unwind_report_and_flush(
            &[("handler", "do_fetch"), ("do_type", "mirror_cleaner")],
            self.fetch_inner(req),
        )
        .await
    }

    async fn alarm(&self) -> Result<Response> {
        generic_log_worker::obs::sentry::catch_unwind_report_and_flush(
            &[("handler", "do_alarm"), ("do_type", "mirror_cleaner")],
            self.alarm_inner(),
        )
        .await
    }
}

impl MirrorCleaner {
    /// Kick handler: ensure the alarm loop is running. Idempotent: the
    /// `add-entries` handler calls this after every commit.
    async fn fetch_inner(&self, _req: Request) -> Result<Response> {
        if !*self.initialized.borrow() {
            self.initialize().await?;
        }
        Response::ok("mirror cleaner started")
    }

    /// Alarm handler: reschedule, then clean one bounded batch of partials.
    async fn alarm_inner(&self) -> Result<Response> {
        *self.subrequests.borrow_mut() = 0;
        if !*self.initialized.borrow() {
            self.initialize().await?;
        }
        // Reschedule first so a mid-clean failure still perpetuates the loop.
        self.storage()
            .set_alarm(Duration::from_secs(CONFIG.clean_interval_secs()))
            .await?;
        if let Err(e) = self.clean().await {
            log::warn!("mirror cleaner [{}]: clean failed: {e}", self.origin);
        } else {
            log::info!(
                "mirror cleaner [{}]: cleaned_size={} current_size={}",
                self.origin,
                self.cleaned_size.borrow(),
                self.current_size.borrow(),
            );
        }
        Response::ok("mirror cleaner alarm done")
    }
}

impl MirrorCleaner {
    fn storage(&self) -> Storage {
        self.state.storage()
    }

    /// Start the alarm loop and load any checkpointed progress.
    async fn initialize(&self) -> Result<()> {
        // OK if an alarm is already set; this just guarantees one exists.
        self.storage()
            .set_alarm(Duration::from_secs(CONFIG.clean_interval_secs()))
            .await?;
        if let Some(cleaned) = self.storage().get::<u64>(CLEANED_SIZE_KEY).await? {
            *self.cleaned_size.borrow_mut() = cleaned;
        }
        if let Some(current) = self.storage().get::<u64>(CURRENT_SIZE_KEY).await? {
            *self.current_size.borrow_mut() = current;
        }
        *self.initialized.borrow_mut() = true;
        Ok(())
    }

    /// Clean orphaned partials up to the persisted-entry frontier, stopping
    /// at the frontier or the subrequest budget, checkpointing progress.
    async fn clean(&self) -> Result<()> {
        // Refresh the frontier once we've caught up to the last-seen value.
        if *self.current_size.borrow() < *self.cleaned_size.borrow() + STEP {
            let frontier = self.frontier_size().await?;
            *self.current_size.borrow_mut() = frontier;
            self.storage().put(CURRENT_SIZE_KEY, frontier).await?;
        }

        // Reserve one subrequest for the final delete.
        self.checked_add_subrequests(1)?;

        let mut pending_cleaned = *self.cleaned_size.borrow();
        let mut batch: Vec<String> = Vec::with_capacity(MAX_DELETE_BATCH);
        while pending_cleaned + STEP <= *self.current_size.borrow() {
            if let Err(e) = self.clean_range(pending_cleaned, &mut batch).await {
                // Failed to enqueue more deletions (e.g. hit the subrequest
                // budget). Stop enqueuing but still flush what we have.
                log::warn!("mirror cleaner [{}]: stopping early: {e}", self.origin);
                break;
            }
            pending_cleaned += STEP;
        }

        if !batch.is_empty() {
            self.bucket.delete_multiple(batch).await?;
        }
        *self.cleaned_size.borrow_mut() = pending_cleaned;
        self.storage()
            .put(CLEANED_SIZE_KEY, pending_cleaned)
            .await?;
        Ok(())
    }

    /// Enqueue for deletion the orphaned partials completed by the range
    /// `[lo, lo + 256)`, flushing full delete batches as they fill.
    async fn clean_range(&self, lo: u64, batch: &mut Vec<String>) -> Result<()> {
        for target in plan_clean(&self.prefix, lo) {
            // Only clean once the full tile is present, so we never delete a
            // partial before its wider replacement exists.
            self.checked_add_subrequests(1)?;
            if self.bucket.head(&target.full_tile_key).await?.is_none() {
                return Err(format!("full tile absent: {}", target.full_tile_key).into());
            }
            for prefix in &target.partial_prefixes {
                for key in self.list_prefix(prefix).await? {
                    batch.push(key);
                    if batch.len() == MAX_DELETE_BATCH {
                        self.checked_add_subrequests(1)?;
                        self.bucket.delete_multiple(mem::take(batch)).await?;
                        *self.cleaned_size.borrow_mut() = lo;
                        self.storage().put(CLEANED_SIZE_KEY, lo).await?;
                    }
                }
            }
        }
        Ok(())
    }

    /// List every object key under `prefix` (one page; a single tile's
    /// partials number at most 255, well under the 1000-key page limit).
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        self.checked_add_subrequests(1)?;
        Ok(self
            .bucket
            .list()
            .prefix(prefix.to_owned())
            .execute()
            .await?
            .objects()
            .iter()
            .map(Object::key)
            .collect())
    }

    /// Read the persisted-entry frontier `next_entry.size` from the origin's
    /// `MirrorState` DO, the width up to which full tiles are known to
    /// exist, and thus the ceiling for cleaning.
    async fn frontier_size(&self) -> Result<u64> {
        self.checked_add_subrequests(1)?;
        let stub = state_stub(&self.env, self.origin)?;
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
            return Err(format!("state DO /get-state returned {}", resp.status_code()).into());
        }
        let snapshot: MirrorStateSnapshot = resp.json().await?;
        Ok(snapshot.next_entry.size)
    }

    /// Add `n` to the subrequest tally, erroring if it would exceed the
    /// per-invocation limit.
    fn checked_add_subrequests(&self, n: usize) -> Result<()> {
        if *self.subrequests.borrow() + n > SUBREQUEST_LIMIT {
            return Err("reached subrequest limit".into());
        }
        *self.subrequests.borrow_mut() += n;
        Ok(())
    }
}

/// Get a stub for the `MirrorCleaner` instance serving `origin`.
fn cleaner_stub(env: &Env, origin: &str) -> Result<Stub> {
    env.durable_object(MIRROR_CLEANER_BINDING)?
        .id_from_name(origin)?
        .get_stub()
}

/// Kick the per-origin `MirrorCleaner` so its alarm loop is running.
///
/// Called by the `add-entries` handler after a successful commit, the
/// moment new partial tiles may have been written. Best-effort: the actual
/// cleaning happens on the self-perpetuating alarm, and cleanup is a
/// storage-hygiene concern that must never fail an `add-entries` response,
/// so a failure here is logged and swallowed.
pub(crate) async fn kick(env: &Env, origin: &str) {
    let result = async {
        cleaner_stub(env, origin)?
            .fetch_with_str("http://do/start")
            .await
    }
    .await;
    if let Err(e) = result {
        log::warn!("add-entries: failed to kick mirror cleaner for {origin:?}: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::{STEP, plan_clean};

    /// A 256-aligned range starting at 0 completes exactly the level-0
    /// tile `[0, 256)`. We expect one clean target whose partial prefixes
    /// cover both the hash tile and the entry (data) tile, each ending in
    /// `.p/`, and all under the given origin prefix.
    #[test]
    fn plan_clean_first_tile_covers_hash_and_data() {
        let targets = plan_clean("abcd/", 0);
        assert_eq!(targets.len(), 1, "one full tile completed at [0, 256)");
        let t = &targets[0];
        assert!(
            t.full_tile_key.starts_with("abcd/"),
            "full-tile key must carry the origin prefix: {}",
            t.full_tile_key
        );
        assert!(
            !t.full_tile_key.contains(".p/"),
            "the clean gate is the *full* tile, not a partial: {}",
            t.full_tile_key
        );
        assert_eq!(
            t.partial_prefixes.len(),
            2,
            "level-0 tile cleans both its hash-tile and data-tile partials",
        );
        for p in &t.partial_prefixes {
            assert!(
                p.starts_with("abcd/"),
                "partial prefix needs origin prefix: {p}"
            );
            assert!(
                p.ends_with(".p/"),
                "partial prefix must select the .p/ namespace: {p}"
            );
        }
        // The hash-tile and data-tile prefixes must differ, or we'd only
        // list one of the two partial namespaces.
        assert_ne!(t.partial_prefixes[0], t.partial_prefixes[1]);
    }

    /// A range whose upper end crosses a level-1 boundary completes both a
    /// full level-0 tile *and* a full level-1 tile. `[65280, 65536)` ends
    /// exactly at 256*256, completing the level-1 tile `[0, 65536)`. The
    /// higher-level tile has no data tile, so it contributes only its own
    /// hash-tile partial prefix.
    #[test]
    fn plan_clean_higher_level_has_no_data_partials() {
        let lo = STEP * (STEP - 1); // 65280: [65280, 65536) closes a level-1 tile.
        let targets = plan_clean("ff/", lo);
        assert_eq!(targets.len(), 2, "level-0 and level-1 tiles both complete");
        let higher = targets
            .iter()
            .find(|t| t.partial_prefixes.len() == 1)
            .expect("a higher-level tile contributes only its hash-tile partials");
        assert!(higher.partial_prefixes[0].ends_with(".p/"));
        let level0 = targets
            .iter()
            .find(|t| t.partial_prefixes.len() == 2)
            .expect("the level-0 tile contributes hash + data partials");
        assert!(level0.full_tile_key.starts_with("ff/"));
    }

    /// An aligned 256-span that stays within a single level-1 tile
    /// completes exactly one (level-0) full tile, so it yields one clean
    /// target with both the hash-tile and data-tile partial prefixes and
    /// no higher-level target.
    #[test]
    fn plan_clean_interior_range_is_single_level0_tile() {
        let targets = plan_clean("x/", STEP); // [256, 512): interior of level-1 tile 0.
        assert_eq!(targets.len(), 1, "only the level-0 tile completes");
        assert_eq!(
            targets[0].partial_prefixes.len(),
            2,
            "level-0 target cleans hash-tile and data-tile partials",
        );
    }
}
