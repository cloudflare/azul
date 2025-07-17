use futures_util::future::join_all;
use generic_log_worker::{load_public_bucket, log_ops::CHECKPOINT_KEY, util::now_millis};
use signed_note::{KeyName, NoteVerifier, VerifierList};
use static_ct_api::StaticCTPendingLogEntry;
use tlog_tiles::{PendingLogEntry, TlogTile};
use worker::{event, Bucket, Env, ScheduleContext, ScheduledEvent};

use crate::{load_checkpoint_signers, load_origin, CONFIG};

// Workers are limited to 1000 subrequests per invocation (including R2 operations).
// For each log, we'll need to perform the following subrequests:
// - Get old and new log sizes (2 ops)
// - List partials for full tree, data, and (optional) aux tiles (2-3 ops per 256 entries, plus logarithmic level-1+ tree tiles)
// - Delete partials for full tree, data, and (optional) aux tiles (0-3 ops per 256 entries, after <https://github.com/cloudflare/workers-rs/issues/780>)
// - Save new tree size (1 op)
// We track subrequest to avoid going over the limit, but can still limit the range of entries.
const SUBREQUEST_LIMIT: usize = 1000;
const STEP: u64 = TlogTile::FULL_WIDTH as u64;
const CLEANED_SIZE_KEY: &str = "_cleanup_cron_progress";

#[derive(thiserror::Error, Debug)]
enum CleanupError {
    #[error(transparent)]
    Worker(#[from] worker::Error),
    #[error("subrequest limit")]
    Subrequests,
}

/// Partial tile cleanup cron job periodically does the following:
///
/// for each configured log:
///   1. set new_size to the current (verified) checkpoint size
///   2. set old_size to the checkpoint size when the cron job previously successfully ran
///   3. get the list of tiles created between old_size and new_size (via `TlogTile::new_tiles(old_size, new_size)`)
///   4. for each full tile:
///     a. list the corresponding partial tiles (matching the prefix "<full tile key>.p/")
///     b. delete the partial tiles
#[event(scheduled)]
pub async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let mut subrequests = 0;
    for name in CONFIG.logs.keys() {
        if checked_add_subrequests(&mut subrequests, 3).is_err() {
            // We need three subrequests to check and set the log size. If we've
            // already reached the subrequest limit, stop now.
            return;
        }

        let origin = &load_origin(name);
        let verifiers = &VerifierList::new(
            load_checkpoint_signers(&env, name)
                .iter()
                .map(|s| s.verifier())
                .collect::<Vec<Box<dyn NoteVerifier>>>(),
        );
        let bucket = &load_public_bucket(&env, name).unwrap();
        let current_log_size = current_log_size(origin, verifiers, bucket).await.unwrap();
        let old_cleaned_size = cleaned_size(bucket).await.unwrap();
        log::debug!("cleaning {name}: {old_cleaned_size} to {current_log_size}");
        match clean_log(old_cleaned_size, current_log_size, bucket, &mut subrequests).await {
            Ok(cleaned_size) => {
                // Save progress on cleaning the log.
                if cleaned_size > old_cleaned_size {
                    let _ = set_cleaned_size(cleaned_size, bucket)
                        .await
                        .inspect_err(|e| log::warn!("failed to update cleaned size: {name}: {e}"));
                }
            }
            Err(e) => log::warn!("failed to clean log: {name}: {e}"),
        }
    }
}

// Clean up partial tiles from a log, stopping either when the current log size
// is reached or the subrequest limit is reached. Returns the size of the tree
// that has been cleaned so partial progress can be saved.
async fn clean_log(
    old_size: u64,
    new_size: u64,
    bucket: &Bucket,
    subrequests: &mut usize,
) -> Result<u64, CleanupError> {
    let mut cleaned_size = old_size;
    loop {
        if cleaned_size + STEP > new_size {
            // We've already cleaned the last full tile, so nothing else to do.
            break;
        }
        match clean_log_range(cleaned_size, cleaned_size + STEP, subrequests, bucket).await {
            Ok(()) => cleaned_size += STEP,
            Err(e) => {
                return match e {
                    CleanupError::Subrequests => Ok(cleaned_size),
                    CleanupError::Worker(_) => Err(e),
                }
            }
        }
    }
    Ok(cleaned_size)
}

// Attempt to clean up all partial tiles within the specified range. Any failure
// will require the full range to be retried later.
//
// # Errors
// Will return `CleanupError::Subrequests` if the operation cannot be completed
// because it would run into subrequest limits, and will return a
// `CleanupError::Worker` if any other error occurs.
async fn clean_log_range(
    start_size: u64,
    end_size: u64,
    subrequests: &mut usize,
    bucket: &Bucket,
) -> Result<(), CleanupError> {
    // Get tree tiles between the start and end sizes.
    for tile in TlogTile::new_tiles(start_size, end_size) {
        // Full tiles only. If the full tile exists, the corresponding partial tiles can be deleted.
        if tile.width() == 1 << tile.height() {
            if tile.level() == 0 {
                // for level-0 tree tiles, delete the corresponding data and (optional) aux files.
                delete_dir(
                    &format!(
                        "{}.p/",
                        tile.with_data_path(StaticCTPendingLogEntry::DATA_TILE_PATH)
                            .path()
                    ),
                    bucket,
                    subrequests,
                )
                .await?;
                if let Some(aux_path) = StaticCTPendingLogEntry::AUX_TILE_PATH {
                    delete_dir(
                        &format!("{}.p/", tile.with_data_path(aux_path).path()),
                        bucket,
                        subrequests,
                    )
                    .await?;
                }
            }
            delete_dir(&format!("{}.p/", tile.path()), bucket, subrequests).await?;
        }
    }
    Ok(())
}

// Delete all files in the specified directory.
//
// # Errors
// Will return `CleanupError::Subrequests` and abort early if the subrequest
// limit is reached before successfully deleting the directory, and will return
// a `CleanupError::Worker` if any other error occurs.
async fn delete_dir(
    prefix: &str,
    bucket: &Bucket,
    subrequests: &mut usize,
) -> Result<(), CleanupError> {
    log::debug!("deleting {prefix}");
    checked_add_subrequests(subrequests, 1)?;
    let objects = bucket.list().prefix(prefix).execute().await?;
    // TODO add binding to delete multiple keys from R2 bucket. Otherwise, we'll
    // quickly hit workers subrequest limits.
    // Tracking issue: <https://github.com/cloudflare/workers-rs/issues/780>
    checked_add_subrequests(subrequests, objects.objects().len())?;
    let futures = objects
        .objects()
        .iter()
        .map(|obj| bucket.delete(obj.key()))
        .collect::<Vec<_>>();
    join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, worker::Error>>()?;
    Ok(())
}

async fn cleaned_size(bucket: &Bucket) -> Result<u64, worker::Error> {
    Ok(match bucket.get(CLEANED_SIZE_KEY).execute().await? {
        Some(obj) => u64::from_be_bytes(
            obj.body()
                .ok_or("missing object body")?
                .bytes()
                .await?
                .try_into()
                .map_err(|_| "failed to read u64")?,
        ),
        None => 0,
    })
}

async fn set_cleaned_size(size: u64, bucket: &Bucket) -> Result<(), worker::Error> {
    bucket
        .put(CLEANED_SIZE_KEY, size.to_be_bytes().to_vec())
        .execute()
        .await
        .map(|_| ())
}

async fn current_log_size(
    origin: &KeyName,
    verifiers: &VerifierList,
    bucket: &Bucket,
) -> Result<u64, worker::Error> {
    let checkpoint_bytes = bucket
        .get(CHECKPOINT_KEY)
        .execute()
        .await?
        .ok_or("failed to retrieve checkpoint from object storage")?
        .body()
        .ok_or("missing object body")?
        .bytes()
        .await?;
    let checkpoint =
        tlog_tiles::open_checkpoint(origin.as_str(), verifiers, now_millis(), &checkpoint_bytes)
            .map_err(|e| e.to_string())?
            .0;

    Ok(checkpoint.size())
}

// Add to the subrequest count after checking that the new subrequests will not
// put the worker over the limit.
//
// # Errors
// Will return `CleanupError::Subrequests` if the additional subreqeusts would
// cause the limit to be exceeded.
fn checked_add_subrequests(subrequests: &mut usize, new: usize) -> Result<(), CleanupError> {
    if *subrequests + new > SUBREQUEST_LIMIT {
        return Err(CleanupError::Subrequests);
    }
    *subrequests += new;
    Ok(())
}
