// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Cleaner removes no-longer-needed partial tiles from the object backend.

use futures_util::future::try_join_all;
use signed_note::{KeyName, VerifierList};
use std::{cell::RefCell, mem, time::Duration};
use tlog_tiles::{PathElem, TlogTile};
use worker::{Bucket, Env, Error as WorkerError, Object, Request, Response, State, Storage};

use crate::{load_public_bucket, log_ops::CHECKPOINT_KEY, util::now_millis};

// Workers are limited to 1000 subrequests per invocation (including R2 operations).
// For each log, we'll need to perform the following subrequests:
// - Get old and new log sizes (2 ops)
// - List partials for full tree, data, and (optional) aux tiles (2-3 ops per 256 entries, plus logarithmic level-1+ tree tiles)
// - Delete partials for full tree, data, and (optional) aux tiles (0-3 ops per 256 entries, after <https://github.com/cloudflare/workers-rs/issues/780>)
// - Save new tree size (1 op)
// We track subrequest to avoid going over the limit, but can still limit the range of entries.
const SUBREQUEST_LIMIT: usize = 1000;
// Up to 1000 objects can be delete from an R2 bucket in a single call.
// <https://developers.cloudflare.com/r2/api/workers/workers-api-reference/#bucket-method-definitions>
const MAX_DELETE_BATCH: usize = 1000;
const STEP: u64 = TlogTile::FULL_WIDTH as u64;
const CLEANED_SIZE_KEY: &str = "cleaned_size";
const CURRENT_SIZE_KEY: &str = "current_size";

pub struct CleanerConfig {
    pub name: String,
    pub origin: KeyName,
    pub data_path: PathElem,
    pub aux_path: Option<PathElem>,
    pub verifiers: VerifierList,
    pub clean_interval: Duration,
}

pub struct GenericCleaner {
    pub config: CleanerConfig,
    pub env: Env,
    pub storage: Storage,
    pub bucket: Bucket,
    cleaned_size: RefCell<u64>,
    current_size: RefCell<u64>,
    subrequests: RefCell<usize>,
    initialized: RefCell<bool>,
}

impl GenericCleaner {
    /// Return a new partial tile cleaner.
    ///
    /// # Panics
    ///
    /// Panics if we can't get a handle for the public bucket.
    pub fn new(state: &State, env: Env, config: CleanerConfig) -> Self {
        let bucket = load_public_bucket(&env, &config.name).unwrap();
        Self {
            env,
            storage: state.storage(),
            config,
            bucket,
            cleaned_size: RefCell::new(0),
            current_size: RefCell::new(0),
            subrequests: RefCell::new(0),
            initialized: RefCell::new(false),
        }
    }

    /// Initialize the partial tile cleaner by loading a previously-saved
    /// `cleaned_size` and starting an alarm that will trigger every
    /// `clean_interval` and attempt to do log cleanup.
    ///
    /// # Errors
    /// Will return an error if the alarm cannot be initialized.
    async fn initialize(&self) -> Result<(), WorkerError> {
        // Start the cleaner loop (OK if alarm is already set).
        self.storage.set_alarm(self.config.clean_interval).await?;

        // Load the cleaned size, if it has been previously saved.
        if let Ok(cleaned_size) = self.storage.get::<u64>(CLEANED_SIZE_KEY).await {
            *self.cleaned_size.borrow_mut() = cleaned_size;
        }

        // Load the current log size, if it has been previously saved.
        if let Ok(current_size) = self.storage.get::<u64>(CURRENT_SIZE_KEY).await {
            *self.current_size.borrow_mut() = current_size;
        }

        *self.initialized.borrow_mut() = true;

        Ok(())
    }

    /// Fetch handler for the partial tile cleaner. This should only ever need
    /// to be called once to trigger initial alarm creation (but OK to call
    /// multiple times).
    ///
    /// # Errors
    /// Will return an error if initialization fails.
    pub async fn fetch(&self, _req: Request) -> Result<Response, WorkerError> {
        if !*self.initialized.borrow() {
            self.initialize().await?;
        }
        Response::ok("Started cleaner")
    }

    /// Alarm handler for the partial tile cleaner. This runs in a loop
    /// iterating over the log contents and removing partial tiles whose
    /// corresponding full tiles are already available.
    ///
    /// # Errors
    /// Will return an error if initialization or cleaning fails.
    pub async fn alarm(&self) -> Result<(), WorkerError> {
        // Reset the subrequest count.
        *self.subrequests.borrow_mut() = 0;

        let name = &self.config.name;
        if !*self.initialized.borrow() {
            log::info!("{name}: Initializing cleaner from alarm handler",);
            self.initialize().await?;
        }
        // Schedule the next cleaning.
        self.storage.set_alarm(self.config.clean_interval).await?;

        // Clean partial tiles from the log.
        if let Err(e) = self.clean_log().await {
            log::warn!("{name}: Error cleaning log: {e}");
        } else {
            log::info!(
                "{name}: Cleaned log (cleaned_size={}, current_size={})",
                self.cleaned_size.borrow(),
                self.current_size.borrow()
            );
        }
        Ok(())
    }

    // Clean up partial tiles from a log, stopping either when the current log
    // size is reached or the subrequest limit is reached. After each deletion
    // operation, save the new cleaned size to durable storage.
    async fn clean_log(&self) -> Result<(), WorkerError> {
        // Update the current log size if we're caught up to the previous
        // current log size.
        if *self.current_size.borrow() < *self.cleaned_size.borrow() + STEP {
            let new_size = self.current_size().await?;
            *self.current_size.borrow_mut() = new_size;
            self.storage.put(CURRENT_SIZE_KEY, new_size).await?;
        }

        // Reserve subrequest to delete the final batch.
        self.checked_add_subrequests(1)?;

        let mut pending_cleaned_size = *self.cleaned_size.borrow();
        let mut batch: Vec<String> = Vec::with_capacity(MAX_DELETE_BATCH);

        while pending_cleaned_size + STEP <= *self.current_size.borrow() {
            match self
                .clean_partials_in_range(pending_cleaned_size, &mut batch)
                .await
            {
                Ok(()) => (),
                Err(e) => {
                    // An error here means we failed to add new partial tiles to
                    // the batch to be deleted. Log the error without returning
                    // immediately since we still want to try to delete the
                    // final batch below.
                    log::warn!("{}: Cleaner exiting early: {e}", self.config.name);
                    break;
                }
            }

            pending_cleaned_size += STEP;
        }

        // Delete final batch (using reserved subreqeust).
        if !batch.is_empty() {
            self.bucket.delete_multiple(batch).await?;
        }

        // Save progress after deleting final batch.
        *self.cleaned_size.borrow_mut() = pending_cleaned_size;
        self.storage
            .put(CLEANED_SIZE_KEY, pending_cleaned_size)
            .await?;

        Ok(())
    }

    // List and queue for deletion all partial tiles corresponding to full tree
    // tiles that would be generated between the old and new tree sizes.
    async fn clean_partials_in_range(
        &self,
        pending_cleaned_size: u64,
        batch: &mut Vec<String>,
    ) -> Result<(), WorkerError> {
        let mut prefixes = Vec::new();
        for tile in TlogTile::new_tiles(pending_cleaned_size, pending_cleaned_size + STEP) {
            // Full tiles only. If the full tile exists, the corresponding
            // partial tiles can be deleted.
            if tile.width() == TlogTile::FULL_WIDTH {
                // SAFETY: Check that at least the level-0 tile exists.
                self.checked_add_subrequests(1)?;
                if self.bucket.head(tile.path()).await?.is_none() {
                    return Err(format!("tile does not exist: {}", tile.path()).into());
                }

                prefixes.push(format!("{}.p/", tile.path()));
                if tile.level() == 0 {
                    // For level-0 tree tiles, also delete the corresponding
                    // data and (optional) aux files.
                    prefixes.push(format!(
                        "{}.p/",
                        tile.with_data_path(self.config.data_path).path()
                    ));
                    if let Some(aux_path) = self.config.aux_path {
                        prefixes.push(format!("{}.p/", tile.with_data_path(aux_path).path()));
                    }
                }
            }
        }
        for partial_tile in try_join_all(prefixes.iter().map(|prefix| self.list_prefix(prefix)))
            .await?
            .into_iter()
            .flatten()
        {
            batch.push(partial_tile);

            if batch.len() == MAX_DELETE_BATCH {
                // Delete full batch.
                self.checked_add_subrequests(1)?;
                self.bucket.delete_multiple(mem::take(batch)).await?;

                // Save progress.
                *self.cleaned_size.borrow_mut() = pending_cleaned_size;
                self.storage
                    .put(CLEANED_SIZE_KEY, pending_cleaned_size)
                    .await?;
            }
        }

        Ok(())
    }

    // List files with the specified prefix.
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, WorkerError> {
        self.checked_add_subrequests(1)?;
        Ok(self
            .bucket
            .list()
            .prefix(prefix)
            .execute()
            .await?
            .objects()
            .iter()
            .map(Object::key)
            .collect::<Vec<_>>())
    }

    /// Get the latest log size by retrieving the checkpoint from object
    /// storage.
    ///
    /// # Errors
    ///
    /// Will return an error if the checkpoint cannot be retrieved or is
    /// invalid.
    pub async fn current_size(&self) -> Result<u64, WorkerError> {
        self.checked_add_subrequests(1)?;
        let checkpoint_bytes = self
            .bucket
            .get(CHECKPOINT_KEY)
            .execute()
            .await?
            .ok_or("failed to retrieve checkpoint from object storage")?
            .body()
            .ok_or("missing object body")?
            .bytes()
            .await?;
        let checkpoint = tlog_tiles::open_checkpoint(
            self.config.origin.as_str(),
            &self.config.verifiers,
            now_millis(),
            &checkpoint_bytes,
        )
        .map_err(|e| e.to_string())?
        .0;

        Ok(checkpoint.size())
    }

    /// Add to the subrequest count after checking that the new subrequests will not
    /// put the worker over the limit.
    ///
    /// # Errors
    /// Will return `CleanupError::Subrequests` if the additional subreqeusts would
    /// cause the limit to be exceeded.
    pub fn checked_add_subrequests(&self, new: usize) -> Result<(), WorkerError> {
        if *self.subrequests.borrow() + new > SUBREQUEST_LIMIT {
            return Err("reached subrequest limit".into());
        }
        *self.subrequests.borrow_mut() += new;
        Ok(())
    }
}
