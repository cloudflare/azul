use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};

use crate::{load_checkpoint_signers, load_origin, load_roots, CONFIG};
use futures_util::future::try_join_all;
use generic_log_worker::{
    get_durable_object_name, log_ops::OPTS_DATA_TILE, CleanerConfig, GenericCleaner, ObjectBackend,
    ObjectBucket, CLEANER_BINDING,
};
use sha2::{Digest, Sha256};
use signed_note::VerifierList;
use static_ct_api::{is_link_valid, StaticCTLogEntry, StaticCTPendingLogEntry};
use tlog_tiles::{LogEntry, PathElem, PendingLogEntry, TileIterator, TlogTile};
#[allow(clippy::wildcard_imports)]
use worker::*;
use x509_cert::{
    der::{Decode, Encode},
    Certificate,
};
use x509_util::CertPool;

#[durable_object(alarm)]
struct Cleaner(GenericCleaner);

impl DurableObject for Cleaner {
    fn new(state: State, env: Env) -> Self {
        let name = get_durable_object_name(
            &env,
            &state,
            CLEANER_BINDING,
            &mut CONFIG.logs.keys().map(|name| (name.as_str(), 0)),
        );
        let params = &CONFIG.logs[name];

        let config = CleanerConfig {
            name: name.to_string(),
            origin: load_origin(name),
            data_path: StaticCTPendingLogEntry::DATA_TILE_PATH,
            aux_path: StaticCTPendingLogEntry::AUX_TILE_PATH,
            verifiers: VerifierList::new(
                load_checkpoint_signers(&env, name)
                    .iter()
                    .map(|s| s.verifier())
                    .collect(),
            ),
            clean_interval: Duration::from_secs(params.clean_interval_secs),
        };

        Cleaner(GenericCleaner::new(&state, env, config))
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.0.fetch(req).await
    }

    async fn alarm(&self) -> Result<Response> {
        self.0.alarm().await?;

        // Rewrite data tiles to fix issue99.
        if let Err(e) = self.fix_issue99().await {
            log::warn!("{}: Error fixing issue99: {e}", self.0.config.name);
        }

        Response::ok("Alarm done")
    }
}

// Rewrite data tiles to ensure that all entries include the root fingerprint in
// the chain. As new entries are being correctly written, we can just iterate to
// the current log size at the time this is initially deployed. Once we've
// reached that target, we can remove this logic.
// <https://github.com/cloudflare/azul/issues/99>
const ISSUE99_SIZE_KEY: &str = "issue99_size";
const ISSUE99_TARGET_KEY: &str = "issue99_target";

impl Cleaner {
    // Rewrite data tiles up to `issue99_target` to fix
    // <https://github.com/cloudflare/azul/issues/99>. After each tile rewrite,
    // save the new `issue99_size` to durable storage.
    async fn fix_issue99(&self) -> Result<()> {
        // Load the current size, if it has been previously saved.
        let mut current_size = self
            .0
            .storage
            .get::<u64>(ISSUE99_SIZE_KEY)
            .await
            .unwrap_or_default();

        // Load the target size if it has been previously saved, or otherwise
        // set it based on the current log size.
        let target_size = if let Ok(t) = self.0.storage.get::<u64>(ISSUE99_TARGET_KEY).await {
            t
        } else {
            // Set the target to a multiple of the tile size greater or equal to
            // the current log size, since we're not rewriting partials.
            //
            // Note: `current_size()` will update the subrequest count, so we
            // don't have to do it explicitly here.
            let t = self
                .0
                .current_size()
                .await?
                .div_ceil(u64::from(TlogTile::FULL_WIDTH))
                * u64::from(TlogTile::FULL_WIDTH);
            self.0.storage.put(ISSUE99_TARGET_KEY, t).await?;
            t
        };

        if current_size >= target_size {
            // All caught up. Once all logs have reached this state, we can
            // remove the fix.
            log::info!(
                "{}: Fix issue99 complete (size={current_size})",
                self.0.config.name
            );
            return Ok(());
        }

        self.0.checked_add_subrequests(1)?;
        let roots = load_roots(&self.0.env, &self.0.config.name).await?;

        let issuer_root_cache = Arc::new(RwLock::new(HashMap::new()));
        let changed_tiles = AtomicUsize::default();
        let changed_entries = AtomicUsize::default();

        let mut futures = Vec::new();

        while current_size < target_size {
            if self.0.checked_add_subrequests(4).is_err() {
                // We need up to 4 subrequests per tile: (1) fetch tile, (2) (if
                // not cached) fetch missing issuer, (3) (if changed) back up
                // old tile, (4) (if changed) write new tile. Stop now if we
                // don't have enough budget within this Workers invocation.
                break;
            }

            // Don't attempt to clean the last tile if the log hasn't caught up
            // to the target yet.
            if current_size + u64::from(TlogTile::FULL_WIDTH) == target_size {
                let current_size = self.0.current_size().await?;
                if current_size < target_size {
                    break;
                }
            }

            futures.push(fix_issue99_tile(
                &self.0.config.name,
                self.0.bucket.clone(),
                current_size,
                &roots,
                issuer_root_cache.clone(),
                &changed_tiles,
                &changed_entries,
            ));

            current_size += u64::from(TlogTile::FULL_WIDTH);
        }

        try_join_all(futures).await?;

        // The updates were successful. Update the stored size.
        self.0
            .storage
            .put::<u64>(ISSUE99_SIZE_KEY, current_size)
            .await?;

        log::info!(
                    "{}: Fix issue99 progress (size/target={current_size}/{target_size}, changed entries/tiles={}/{})",
                    self.0.config.name,
                    changed_entries.load(Ordering::Relaxed),
                    changed_tiles.load(Ordering::Relaxed),
                );

        Ok(())
    }
}

// Get the full data tile `[current_size, current_size+256)`, check and fix
// the contents, and write the result back if the tile is changed.
//
// # Errors
//
// Returns an error if the tile is not successfully fixed. This could be
// because of a transient error, or because the full tile doesn't yet exist
// since the target size is greater than the current log size.
//
// # Panics
//
// Will panic if `current_size` is not a multiple of 256.
#[allow(clippy::too_many_lines)]
async fn fix_issue99_tile(
    name: &str,
    bucket: Bucket,
    current_size: u64,
    roots: &CertPool,
    issuer_root_cache: Arc<RwLock<HashMap<[u8; 32], [u8; 32]>>>,
    changed_tiles: &AtomicUsize,
    changed_entries: &AtomicUsize,
) -> Result<()> {
    assert_eq!(current_size % u64::from(TlogTile::FULL_WIDTH), 0);

    // Fetch the full data tile for the entries starting at `current_size`.
    let data_tile = TlogTile::from_leaf_index(current_size + u64::from(TlogTile::FULL_WIDTH) - 1)
        .with_data_path(<StaticCTLogEntry as LogEntry>::Pending::DATA_TILE_PATH);

    assert_eq!(
        data_tile.width(),
        TlogTile::FULL_WIDTH,
        "expected data tile to be full"
    );

    let object = ObjectBucket::new(bucket);
    let Some(old_data_tile) = object.fetch(data_tile.path()).await? else {
        // We'll return this error if the tree size hasn't grown past the
        // target by the time the target is reached. The fix is to manually
        // grow the log.
        return Err(format!(
            "{name}: tile {} not present in object storage",
            data_tile.path()
        )
        .into());
    };

    let mut new_data_tile = Vec::new();
    let iter: TileIterator<StaticCTLogEntry> =
        TileIterator::new(old_data_tile.as_slice(), TlogTile::FULL_WIDTH as usize);

    let mut changed = 0;
    for entry in iter {
        let mut entry = entry.map_err(|e| e.to_string())?;

        // Check if the last entry in chain fingerprints is an accepted
        // root.
        let issuer_hash = entry
            .inner
            .chain_fingerprints
            .last()
            .ok_or("chain fingerprints is empty")?;

        if roots.by_fingerprint(issuer_hash).is_none() {
            // The last issuer in the chain is not an accepted root. Find an
            // accepted root and append its hash to the chain.
            let root_hash_opt = issuer_root_cache.read().unwrap().get(issuer_hash).copied();
            let root_hash = if let Some(h) = root_hash_opt {
                h
            } else {
                let path = format!("issuer/{}", hex::encode(issuer_hash));
                let issuer_bytes = object
                    .fetch(&path)
                    .await?
                    .ok_or("unable to retrieve issuer cert")?;
                let issuer = &Certificate::from_der(&issuer_bytes).map_err(|e| e.to_string())?;

                // The last certificate in the chain is either a root certificate
                // or a certificate that chains to a known root certificate.
                let Some(root_hash) = roots
                    .find_potential_parents(issuer)
                    .map_err(|e| e.to_string())?
                    .iter()
                    .find_map(|idx| {
                        if is_link_valid(issuer, &roots.certs[*idx]) {
                            Some(Sha256::digest(roots.certs[*idx].to_der().unwrap()).into())
                        } else {
                            None
                        }
                    })
                else {
                    // If we reach here, we may have removed a root since the
                    // entry was added. The fix is to add back the root.
                    return Err(format!("failed to find accepted root for {path}").into());
                };

                // Add the validated issuer to root hash mapping to the cache.
                issuer_root_cache
                    .write()
                    .unwrap()
                    .insert(*issuer_hash, root_hash);

                root_hash
            };

            entry.inner.chain_fingerprints.push(root_hash);
            changed += 1;
        }
        new_data_tile.append(&mut entry.to_data_tile_entry());
    }

    if old_data_tile == new_data_tile {
        // No changes to the data tile. We can exit here.
        return Ok(());
    }

    // SAFETY: At this point, the new tile must be strictly larger than the
    // old one (equal sizes would mean that we changed data without appending).
    assert!(
        new_data_tile.len() > old_data_tile.len(),
        "expected new data tile to be strictly larger than old data tile"
    );

    // SAFETY: Double-check that the hashes match.
    let old_iter: TileIterator<StaticCTLogEntry> =
        TileIterator::new(old_data_tile.as_slice(), TlogTile::FULL_WIDTH as usize);
    let new_iter: TileIterator<StaticCTLogEntry> =
        TileIterator::new(new_data_tile.as_slice(), TlogTile::FULL_WIDTH as usize);
    assert_eq!(
        old_iter.len(),
        new_iter.len(),
        "expected old and new tiles to have the same number of entries"
    );
    for (old, new) in old_iter.zip(new_iter) {
        assert_eq!(
            old.map_err(|e| e.to_string())?.merkle_tree_leaf(),
            new.map_err(|e| e.to_string())?.merkle_tree_leaf(),
            "expected old and new entries to have the same merkle tree hash"
        );
    }

    changed_entries.fetch_add(changed, Ordering::Relaxed);
    changed_tiles.fetch_add(1, Ordering::Relaxed);

    // Back up the old tile to the '/tile/issue99' path. This will allow us
    // to recover the original tile if needed, and also to easily add a
    // bucket lifecycle rule based on the prefix to delete the backups when
    // they are no longer deemed useful.
    let backup_tile = data_tile.with_data_path(PathElem::Custom("issue99_backups"));
    object
        .upload(backup_tile.path(), old_data_tile, &OPTS_DATA_TILE)
        .await?;

    // Write the new tile.
    object
        .upload(data_tile.path(), new_data_tile, &OPTS_DATA_TILE)
        .await?;

    Ok(())
}
