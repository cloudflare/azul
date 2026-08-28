// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! `MirrorCleaner` Durable Object: deletes orphaned partial tiles from
//! the mirror's object storage.
//!
//! The mirror's analogue of [`generic_log_worker`]'s `GenericCleaner`,
//! reimplemented for the prefixed, multi-origin bucket layout (see
//! [`crate::storage`]).
//!
//! One instance per configured origin (keyed by origin string, like
//! `MirrorState`). A self-perpetuating alarm, first armed when the
//! `add-entries` handler [kicks](kick) it after a commit, wakes every
//! `clean_interval_secs` and, for every full tile below the mirror
//! checkpoint size not yet cleaned, batch-deletes that tile's `.p/`
//! partials (plus the entry-bundle partials for a level-0 tile). A
//! per-tile `head` check confirms the full tile exists first, so a
//! partial is never removed before its replacement lands. Progress
//! (`cleaned_size`) is checkpointed after each deletion and each wake is
//! bounded by the Workers subrequest limit, resuming where the last left
//! off.

use std::{cell::RefCell, time::Duration};

use futures_util::future::try_join_all;
use tlog_tiles::{PathElem, TlogTile};
#[allow(clippy::wildcard_imports)]
use worker::*;

use crate::{
    CONFIG, MIRROR_CLEANER_BINDING,
    mirror_state_do::{MirrorStateSnapshot, state_stub},
    storage::{PUBLIC_BUCKET_BINDING, origin_hash},
};

/// Workers cap each invocation at 1000 subrequests, R2 ops included.
/// Cleaning bails out before crossing the limit; the next alarm resumes
/// from the checkpointed `cleaned_size`.
const SUBREQUEST_LIMIT: usize = 1000;

/// R2 `delete_multiple` accepts at most 1000 keys per call.
/// <https://developers.cloudflare.com/r2/api/workers/workers-api-reference/#bucket-method-definitions>
const MAX_DELETE_BATCH: usize = 1000;

/// One full tile spans 256 entries; the cleaner advances in these steps.
const STEP: u64 = TlogTile::FULL_WIDTH as u64;

/// DO-storage key for the checkpointed high-water mark: entries below this
/// size have had their partial tiles cleaned.
const CLEANED_SIZE_KEY: &str = "cleaned_size";

/// DO-storage key for the last-observed `committed.size`, so a restart
/// with a backlog resumes cleaning without the cross-DO read.
const COMMITTED_SIZE_KEY: &str = "committed_size";

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
/// For every full hash tile the range completes, returns the full tile's
/// object key and the `.p/` prefixes of the partials it orphans: the hash
/// tile's own, plus the entry-bundle (data tile) partials for a level-0
/// tile. Higher-level tiles have no data tile.
fn plan_clean(origin_prefix: &str, lo: u64) -> Vec<CleanTarget> {
    debug_assert_eq!(lo % STEP, 0, "block start must be 256-aligned");
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

/// The origin an instance cleans, resolved from the DO name in
/// [`MirrorCleaner::new`].
struct Served {
    origin: &'static str,
    /// `<origin hash>/` key prefix for this origin in the shared bucket.
    prefix: String,
}

/// A per-origin partial-tile cleaner. See the module comment.
#[durable_object(alarm)]
struct MirrorCleaner {
    state: State,
    env: Env,
    /// `None` when the DO name is outside the served-origin set, which a
    /// config change produces: an MTC CA log-number window advancing
    /// leaves the dropped origin's alarm scheduled.
    served: Option<Served>,
    bucket: Bucket,
    cleaned_size: RefCell<u64>,
    /// Cache of what [`Self::committed_size`] last read.
    committed_size: RefCell<u64>,
    subrequests: RefCell<usize>,
    initialized: RefCell<bool>,
}

// SAFETY: Durable Objects are single-threaded. The `RefUnwindSafe` bound
// is required by `wasm-bindgen` under `panic=unwind`, for the sentry
// catch-unwind guard around the fetch/alarm handlers.
impl std::panic::RefUnwindSafe for MirrorCleaner {}

impl DurableObject for MirrorCleaner {
    fn new(state: State, env: Env) -> Self {
        // Recover the origin from the runtime-provided DO name, matching
        // the served-origin set for a 'static slice. `crate::log_origins`
        // has already expanded any MTC CA log-number window. A name
        // outside that set is left for the handlers: `new` runs outside
        // the catch-unwind guard, so panicking here would surface as an
        // uncaught exception on every retry of the orphaned alarm.
        let name = state
            .id()
            .name()
            .expect("durable object name not provided by runtime");
        let served = crate::log_origins()
            .find(|o| *o == name)
            .map(|origin| Served {
                origin,
                prefix: format!("{}/", origin_hash(origin)),
            });
        let bucket = env
            .bucket(PUBLIC_BUCKET_BINDING)
            .expect("PUBLIC_BUCKET binding must be a configured R2 bucket");
        crate::init_sentry(&env);
        Self {
            bucket,
            served,
            cleaned_size: RefCell::new(0),
            committed_size: RefCell::new(0),
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
        if self.served.is_none() {
            return Response::error("origin not served by this mirror", 404);
        }
        if !*self.initialized.borrow() {
            self.initialize().await?;
        }
        Response::ok("mirror cleaner started")
    }

    /// Alarm handler: reschedule, then clean one bounded batch of partials.
    async fn alarm_inner(&self) -> Result<Response> {
        *self.subrequests.borrow_mut() = 0;
        let Some(served) = self.served.as_ref() else {
            // The origin left the served set while this alarm was
            // pending. Drop the alarm instead of waking forever with
            // nothing to clean.
            self.storage().delete_alarm().await?;
            return Response::ok("mirror cleaner origin no longer served");
        };
        if !*self.initialized.borrow() {
            self.initialize().await?;
        }
        // Reschedule first so the loop continues even if cleaning fails.
        self.storage()
            .set_alarm(Duration::from_secs(CONFIG.clean_interval_secs()))
            .await?;
        if let Err(e) = self.clean(served).await {
            log::warn!("mirror cleaner [{}]: clean failed: {e}", served.origin);
        } else {
            log::info!(
                "mirror cleaner [{}]: cleaned_size={} committed_size={}",
                served.origin,
                self.cleaned_size.borrow(),
                self.committed_size.borrow(),
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
        // OK if an alarm is already set; this guarantees one exists.
        self.storage()
            .set_alarm(Duration::from_secs(CONFIG.clean_interval_secs()))
            .await?;
        if let Some(cleaned) = self.storage().get::<u64>(CLEANED_SIZE_KEY).await? {
            *self.cleaned_size.borrow_mut() = cleaned;
        }
        if let Some(committed) = self.storage().get::<u64>(COMMITTED_SIZE_KEY).await? {
            *self.committed_size.borrow_mut() = committed;
        }
        *self.initialized.borrow_mut() = true;
        Ok(())
    }

    /// Clean orphaned partials below `committed.size`, stopping there or
    /// at the subrequest budget, and checkpoint progress.
    async fn clean(&self, served: &Served) -> Result<()> {
        // Refresh the ceiling once cleaning has caught up to the
        // last-seen value.
        if *self.committed_size.borrow() < *self.cleaned_size.borrow() + STEP {
            let committed = self.committed_size(served.origin).await?;
            *self.committed_size.borrow_mut() = committed;
            self.storage().put(COMMITTED_SIZE_KEY, committed).await?;
        }

        // Reserve one subrequest for the final delete.
        self.checked_add_subrequests(1)?;

        let mut pending_cleaned = *self.cleaned_size.borrow();
        let mut batch: Vec<String> = Vec::with_capacity(MAX_DELETE_BATCH);
        // A block is eligible only once it lies wholly below
        // `committed.size`, which spares the block holding a mid-tile
        // `committed.size` and the narrow partials `ensure_cut_tiles`
        // wrote there for the served checkpoint.
        while pending_cleaned + STEP <= *self.committed_size.borrow() {
            if let Err(e) = self.clean_range(served, pending_cleaned, &mut batch).await {
                // Out of subrequest budget, or a listing failed. Stop
                // enqueuing, but flush what was collected.
                log::warn!("mirror cleaner [{}]: stopping early: {e}", served.origin);
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
    async fn clean_range(&self, served: &Served, lo: u64, batch: &mut Vec<String>) -> Result<()> {
        let mut prefixes = Vec::new();
        for target in plan_clean(&served.prefix, lo) {
            // A partial may only be deleted once the full tile exists.
            self.checked_add_subrequests(1)?;
            if self.bucket.head(&target.full_tile_key).await?.is_none() {
                return Err(format!("full tile absent: {}", target.full_tile_key).into());
            }
            prefixes.extend(target.partial_prefixes);
        }
        for key in try_join_all(prefixes.iter().map(|prefix| self.list_prefix(prefix)))
            .await?
            .into_iter()
            .flatten()
        {
            batch.push(key);
            if batch.len() == MAX_DELETE_BATCH {
                self.checked_add_subrequests(1)?;
                self.bucket
                    .delete_multiple(batch.iter().map(String::as_str).collect::<Vec<_>>())
                    .await?;
                batch.clear();
                *self.cleaned_size.borrow_mut() = lo;
                self.storage().put(CLEANED_SIZE_KEY, lo).await?;
            }
        }
        Ok(())
    }

    /// List every object key under `prefix`.
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut cursor = None;
        loop {
            self.checked_add_subrequests(1)?;
            let mut list = self.bucket.list().prefix(prefix);
            if let Some(cursor) = cursor {
                list = list.cursor(cursor);
            }
            let page = list.execute().await?;
            keys.extend(page.objects().iter().map(Object::key));
            if !page.truncated() {
                return Ok(keys);
            }
            cursor = Some(
                page.cursor()
                    .ok_or("truncated R2 listing did not include a cursor")?,
            );
        }
    }

    /// Read the cleaning ceiling from the origin's `MirrorState` DO.
    ///
    /// This is `committed.size` rather than `next_entry.size`:
    /// `ensure_cut_tiles` writes narrow partials at `committed.size` for
    /// the served checkpoint, and the full-tile test treats those as
    /// orphans as soon as the frontier passes their block.
    /// `committed.size <= next_entry.size`, so this only cleans less.
    async fn committed_size(&self, origin: &str) -> Result<u64> {
        self.checked_add_subrequests(1)?;
        let stub = state_stub(&self.env, origin)?;
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
        Ok(snapshot.committed.size)
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
/// Called by the `add-entries` handler after a commit. Best-effort:
/// cleaning runs on the alarm, and a failure here is logged and swallowed
/// rather than failing the `add-entries` response.
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

    /// A 256-aligned range starting at 0 completes the level-0 tile
    /// `[0, 256)`, yielding one target whose `.p/` prefixes cover both the
    /// hash tile and the entry (data) tile, under the origin prefix.
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
            "the clean gate must be the full tile rather than a partial: {}",
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
        // The hash-tile and data-tile prefixes must differ, or only one of
        // the two partial namespaces would be listed.
        assert_ne!(t.partial_prefixes[0], t.partial_prefixes[1]);
    }

    /// A range crossing a level-1 boundary completes both a full level-0
    /// and a full level-1 tile. `[65280, 65536)` ends at 256*256, closing
    /// level-1 tile `[0, 65536)`, which has no data tile and so
    /// contributes only its hash-tile prefix.
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

    /// An aligned 256-span inside a single level-1 tile completes exactly
    /// one (level-0) full tile, so it yields one target with both prefixes
    /// and no higher-level target.
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

    /// A misaligned block start would target the full tile below `lo`
    /// rather than the block itself, drifting `cleaned_size` off-boundary.
    /// Gated on `debug_assertions`, matching `plan_clean`'s
    /// `debug_assert_eq!`.
    #[test]
    #[should_panic(expected = "256-aligned")]
    #[cfg(debug_assertions)]
    fn plan_clean_rejects_a_misaligned_block_start() {
        plan_clean("x/", 100);
    }
}
