// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Commit path for `add-entries`: persist verified entries as
//! [tlog-tiles][tiles] entry bundles and (re)compute the Merkle hash
//! tiles, growing the mirrored copy of a log from its persisted frontier
//! up to a pending checkpoint.
//!
//! One commit maps to one `add-entries` request: [`persist_entries`] runs
//! once per request over the full batch of entries received across that
//! request's packages, so the persisted frontier is read from R2 once per
//! request (see [`read_edge_tiles`]), not once per package or entry.
//!
//! This mirrors the sequencer's append path
//! ([`generic_log_worker::log_ops`]'s `sequence_entries`), with two
//! differences: the mirror is stateless between requests, so
//! [`persist_entries`] re-reads and authenticates the persisted frontier
//! from R2 on every commit rather than caching it; and it stores the
//! tlog-tiles entry-bundle framing directly (each leaf `uint16_be(len) ||
//! entry`, leaf hash `record_hash(entry)`) instead of owning an
//! application entry type.
//!
//! Commits are safe to interrupt and repeat: entry bundles and hash tiles
//! are immutable and content-addressed, so re-uploading one is a harmless
//! identical overwrite. The caller advances the durable mirror checkpoint
//! only after [`persist_entries`] returns and the recomputed root matches.
//!
//! [tiles]: https://c2sp.org/tlog-tiles

use std::collections::HashMap;

use futures_util::{
    future::try_join_all,
    stream::{StreamExt as _, TryStreamExt as _, iter as stream_iter},
};
use generic_log_worker::{
    ObjectBackend,
    log_ops::{HashReaderWithOverlay, TileWithBytes, UploadOptions, read_edge_tiles},
};
use length_prefixed::{ReadLengthPrefixedBytesExt as _, WriteLengthPrefixedBytesExt as _};
use tlog_core::{
    HASH_SIZE, Hash, HashReader, TlogError, record_hash, stored_hash_index,
    stored_hashes_for_record_hash,
};
use tlog_tiles::{PathElem, PreloadedTlogTileReader, TileHashReader, TlogTile, TlogTileRecorder};
#[allow(clippy::wildcard_imports)]
use worker::*;

/// tlog-tiles fixes a tile height of 8, i.e. 256 entries per full tile.
const TILE_WIDTH: u64 = TlogTile::FULL_WIDTH as u64;

/// Max in-flight R2 uploads per commit. A single `add-entries` request is
/// bounded only by the request-body size, so uploading every entry bundle
/// and hash tile at once could open thousands of connections and hold all
/// their bytes in memory. Workers allows only six connections to be waiting
/// on response headers at a time, so a small bound captures the concurrency
/// win without the unbounded fan-out.
const UPLOAD_CONCURRENCY: usize = 6;

/// Object key for the (cosigned) checkpoint the mirror serves at
/// `<monitoring>/<origin hash>/checkpoint`. Matches
/// [`generic_log_worker::log_ops::CHECKPOINT_KEY`].
pub(crate) const CHECKPOINT_KEY: &str = "checkpoint";

/// Read `count` already-persisted log entries starting at leaf index
/// `start` back out of their entry bundle in object storage.
///
/// `start` MUST be aligned to a 256-entry bundle boundary and `start +
/// count` MUST NOT exceed `persisted_size`, so the requested leaves all
/// live in the single entry bundle beginning at `start` (a package's
/// subtree spans at most 256 leaves). Returns the entries in order,
/// stripped of their uint16 length prefixes.
///
/// Used by [`crate::add_entries`] to reconstruct the subtree hash of a
/// non-256-aligned first package, whose leading leaves `[subtree_start,
/// upload_start)` are already in the log and therefore absent from the
/// uploaded package.
///
/// The reloaded bytes are untrusted storage output, so each decoded entry
/// is authenticated against the hash tiles committed at the persisted
/// frontier (`persisted_hash` is the frontier root, used to authenticate
/// the edge tiles via [`read_edge_tiles`]). Without this a corrupted or
/// stale bundle would flow into package verification and surface as a
/// client "422 Unprocessable Entity" for what is actually a mirror
/// storage fault.
///
/// # Errors
///
/// Returns an error if the bundle is missing from storage, is shorter than
/// `count` entries, or a decoded entry does not match its authenticated
/// leaf hash.
pub(crate) async fn read_persisted_leaves(
    object: &impl ObjectBackend,
    start: u64,
    count: u64,
    persisted_size: u64,
    persisted_hash: Hash,
) -> Result<Vec<Vec<u8>>> {
    debug_assert!(
        start.is_multiple_of(TILE_WIDTH),
        "start must be bundle-aligned"
    );
    debug_assert!(start + count <= persisted_size, "leaves must be persisted");

    // The bundle's stored width is 256 if the whole tile is persisted,
    // otherwise the trailing partial width `persisted_size - start`. The
    // data-tile path encodes that width (`from_index` derives it from the
    // last stored leaf), so pick the last persisted leaf in this tile.
    let stored_width = TILE_WIDTH.min(persisted_size - start);
    let last_leaf = start + stored_width - 1;
    let tile =
        TlogTile::from_index(stored_hash_index(0, last_leaf)).with_data_path(PathElem::Entries);
    let bytes = object
        .fetch(tile.path())
        .await?
        .ok_or_else(|| Error::from(format!("persisted entry bundle missing: {}", tile.path())))?;

    // Authenticate the decoded leaves against the frontier hash tiles.
    // Leaves below the frontier's edge tile are not covered by
    // `read_edge_tiles`, and the `excess_entries` bound lets a resume land
    // in the tile just before the edge, so authenticate against the tree
    // root via the full tile-hash reader instead.
    let indexes: Vec<u64> = (start..start + count)
        .map(|leaf| stored_hash_index(0, leaf))
        .collect();
    let want = authenticated_leaf_hashes(object, persisted_size, persisted_hash, &indexes).await?;

    let mut cur: &[u8] = &bytes;
    let mut out = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for i in 0..count {
        let leaf = start + i;
        let entry = cur
            .read_length_prefixed(2)
            .map_err(|e| Error::from(format!("persisted bundle leaf {leaf} truncated: {e}")))?;
        let idx = usize::try_from(i).unwrap_or(usize::MAX);
        if record_hash(&entry) != want[idx] {
            return Err(Error::from(format!(
                "persisted bundle leaf {leaf} does not match its authenticated hash"
            )));
        }
        out.push(entry);
    }
    Ok(out)
}

/// Fetch and authenticate the record hashes for `indexes` (level-0 leaf
/// stored-hash indexes) against the frontier `(tree_size, tree_hash)`.
///
/// Runs the standard tlog-tiles two-pass [`TileHashReader`] protocol: a
/// recording pass discovers the hash tiles needed to prove the requested
/// leaves, they are fetched from storage, then a verifying pass
/// authenticates them against `tree_hash`. A storage fault (missing,
/// stale, or tampered tile) therefore surfaces as an error here rather
/// than as a spurious client rejection downstream.
///
/// # Errors
///
/// Returns an error if a required hash tile is missing from storage or the
/// fetched tiles do not authenticate against `tree_hash`.
async fn authenticated_leaf_hashes(
    object: &impl ObjectBackend,
    tree_size: u64,
    tree_hash: Hash,
    indexes: &[u64],
) -> Result<Vec<Hash>> {
    let tiles = fetch_authenticated_tiles(object, tree_size, indexes).await?;
    let reader = PreloadedTlogTileReader(tiles);
    TileHashReader::new(tree_size, tree_hash, &reader)
        .read_hashes(indexes)
        .map_err(|e| Error::from(format!("authenticate persisted leaf hashes: {e:?}")))
}

/// Fetch (from storage) the hash tiles needed to prove `indexes` against
/// `(tree_size, tree_hash)`. The returned map feeds a [`TileHashReader`] whose
/// verifying pass authenticates them; a missing or stale tile surfaces as an
/// error rather than a downstream client rejection.
///
/// # Errors
///
/// Returns an error if a required hash tile is missing from storage.
async fn fetch_authenticated_tiles(
    object: &impl ObjectBackend,
    tree_size: u64,
    indexes: &[u64],
) -> Result<HashMap<TlogTile, Vec<u8>>> {
    // Recording pass: `TlogTileRecorder` short-circuits `read_hashes` with
    // `RecordedTilesOnly` after collecting the tiles it would need.
    let recorder = TlogTileRecorder::default();
    match TileHashReader::new(tree_size, Hash::default(), &recorder).read_hashes(indexes) {
        Err(TlogError::RecordedTilesOnly) => {}
        other => {
            return Err(Error::from(format!(
                "expected RecordedTilesOnly while recording hash tiles, got {other:?}"
            )));
        }
    }

    let tile_futures = recorder.0.into_inner().into_iter().map(|tile| {
        let path = tile.path();
        async move {
            let bytes = object
                .fetch(path.clone())
                .await?
                .ok_or_else(|| Error::from(format!("persisted hash tile missing: {path}")))?;
            Ok::<(TlogTile, Vec<u8>), Error>((tile, bytes))
        }
    });
    Ok(try_join_all(tile_futures).await?.into_iter().collect())
}

/// Authenticate a reloaded partial entry bundle before it is extended and
/// re-served.
///
/// The bytes come back from object storage untrusted. New-leaf hashes are
/// computed only from the freshly-uploaded entries and the authenticated
/// edge tiles, and the recomputed root never reads the reloaded bundle
/// bytes, so a corrupted or tampered partial bundle would otherwise be
/// silently re-uploaded and served.
///
/// Confirms the bundle decodes to exactly the `[subtree_start,
/// persisted_size)` leaves as length-prefixed entries with no trailing
/// bytes, and that each decoded entry's `record_hash` matches the
/// authenticated leaf hash from `edge_tiles`.
///
/// # Errors
///
/// Returns an error if the bundle is truncated, carries trailing bytes, a
/// leaf hash is unavailable, or a decoded entry does not match its
/// authenticated leaf hash.
fn verify_partial_bundle(
    bytes: &[u8],
    subtree_start: u64,
    persisted_size: u64,
    edge_tiles: &HashMap<u8, TileWithBytes>,
) -> Result<()> {
    let overlay = HashMap::new();
    let reader = HashReaderWithOverlay {
        edge_tiles,
        overlay: &overlay,
    };
    let mut cur: &[u8] = bytes;
    for leaf in subtree_start..persisted_size {
        let entry = cur
            .read_length_prefixed(2)
            .map_err(|e| Error::from(format!("partial entry bundle leaf {leaf} truncated: {e}")))?;
        let want = reader
            .read_hashes(&[stored_hash_index(0, leaf)])
            .map_err(|e| Error::from(format!("missing persisted leaf hash {leaf}: {e:?}")))?;
        if record_hash(&entry) != want[0] {
            return Err(Error::from(format!(
                "partial entry bundle leaf {leaf} does not match its authenticated hash"
            )));
        }
    }
    if !cur.is_empty() {
        return Err(Error::from(
            "partial entry bundle has trailing bytes past the persisted frontier",
        ));
    }
    Ok(())
}

/// Serialize one entry into its tlog-tiles entry-bundle framing (a
/// big-endian uint16 length prefix followed by the entry bytes) and
/// append it to `buf`. Matches `tlog_entry`'s `to_data_tile_entry` so
/// the mirror's bundles are byte-identical to a native tlog-tiles log's.
///
/// # Errors
///
/// Returns an error if `entry` exceeds 65535 bytes (the u16 length
/// prefix limit). Entries were parsed off the wire with the same uint16
/// framing, so in practice this never fires.
fn push_tile_leaf(buf: &mut Vec<u8>, entry: &[u8]) -> Result<()> {
    buf.write_length_prefixed(entry, 2)
        .map_err(|e| Error::from(format!("entry too large for tile bundle: {e}")))
}

/// The `UploadOptions` for an immutable, content-addressed tile (entry
/// bundle or hash tile).
fn immutable_tile_opts() -> UploadOptions {
    UploadOptions {
        content_type: Some("application/octet-stream".to_owned()),
        immutable: true,
    }
}

/// Persist entries `[persisted_size, target_size)` into object storage,
/// growing the mirrored tree and returning the recomputed root hash.
///
/// Called once per `add-entries` request; `entries` spans all packages
/// received in that request. `entries[i]` MUST be the raw log-entry bytes
/// (no length prefix) for leaf `persisted_size + i`, covering exactly
/// `[persisted_size, target_size)`.
///
/// Reads the persisted frontier from R2 (skipped at size 0), replays each
/// leaf through [`stored_hashes_for_record_hash`] while flushing full and
/// trailing-partial entry bundles, then (re)computes and uploads every
/// hash tile in [`TlogTile::new_tiles`]`(persisted_size, target_size)`.
///
/// It does not write the checkpoint object or advance the mirror
/// checkpoint; the caller does that after verifying the returned root.
///
/// # Errors
///
/// Returns an error on any storage failure, if a persisted tile is
/// missing or fails authentication, or if `entries.len()` does not equal
/// `target_size - persisted_size`.
pub(crate) async fn persist_entries(
    object: &impl ObjectBackend,
    persisted_size: u64,
    persisted_hash: Hash,
    target_size: u64,
    entries: &[Vec<u8>],
) -> Result<Hash> {
    let expected = target_size
        .checked_sub(persisted_size)
        .ok_or_else(|| Error::from("target_size < persisted_size"))?;
    if entries.len() as u64 != expected {
        return Err(Error::from(format!(
            "commit entry count {} != range {persisted_size}..{target_size}",
            entries.len()
        )));
    }
    if expected == 0 {
        return Ok(persisted_hash);
    }

    // Genesis (persisted_size 0): no persisted frontier exists yet, so there
    // are no edge tiles to read; start from an empty overlay.
    let mut edge_tiles = if persisted_size == 0 {
        HashMap::new()
    } else {
        read_edge_tiles(object, persisted_size, &persisted_hash).await?
    };

    // Load the current partial entry bundle so we extend rather than
    // overwrite it. Only exists when the frontier is mid-tile. The reloaded
    // bytes are untrusted (storage could return corrupted or tampered
    // data), so authenticate them before extending and re-serving them.
    let mut data_tile = Vec::new();
    if persisted_size > 0 && !persisted_size.is_multiple_of(TILE_WIDTH) {
        let subtree_start = (persisted_size / TILE_WIDTH) * TILE_WIDTH;
        let partial = TlogTile::from_index(stored_hash_index(0, persisted_size - 1))
            .with_data_path(PathElem::Entries);
        data_tile = object.fetch(partial.path()).await?.ok_or_else(|| {
            Error::from(format!("partial entry bundle missing: {}", partial.path()))
        })?;
        verify_partial_bundle(&data_tile, subtree_start, persisted_size, &edge_tiles)?;
    }

    // Replay leaves, buffering entry-bundle uploads until the end so they
    // can be issued with bounded concurrency. Bundles are immutable and
    // idempotent, so overlapping them is safe.
    let mut overlay: HashMap<u64, Hash> = HashMap::new();
    let mut n = persisted_size;
    let mut bundle_uploads = Vec::new();
    for entry in entries {
        push_tile_leaf(&mut data_tile, entry)?;
        let hashes = stored_hashes_for_record_hash(
            n,
            record_hash(entry),
            &HashReaderWithOverlay {
                edge_tiles: &edge_tiles,
                overlay: &overlay,
            },
        )
        .map_err(|e| Error::from(format!("couldn't compute hashes for leaf {n}: {e}")))?;
        for (i, h) in hashes.iter().enumerate() {
            overlay.insert(stored_hash_index(0, n) + i as u64, *h);
        }
        n += 1;
        if n.is_multiple_of(TILE_WIDTH) {
            bundle_uploads.push(upload_entry_bundle(
                object,
                n,
                std::mem::take(&mut data_tile),
            ));
        }
    }
    debug_assert_eq!(n, target_size);
    // Trailing partial entry bundle.
    if !target_size.is_multiple_of(TILE_WIDTH) {
        bundle_uploads.push(upload_entry_bundle(
            object,
            target_size,
            std::mem::take(&mut data_tile),
        ));
    }
    stream_iter(bundle_uploads)
        .buffer_unordered(UPLOAD_CONCURRENCY)
        .try_collect::<()>()
        .await?;

    // (Re)compute hash tiles, then upload them with bounded concurrency
    // while keeping edge_tiles current for the final root hash.
    let tile_opts = immutable_tile_opts();
    let mut hash_uploads = Vec::new();
    for tile in TlogTile::new_tiles(persisted_size, target_size) {
        let bytes = tile
            .read_data(&HashReaderWithOverlay {
                edge_tiles: &edge_tiles,
                overlay: &overlay,
            })
            .map_err(|e| Error::from(format!("couldn't build hash tile {tile:?}: {e}")))?;
        edge_tiles.insert(
            tile.level(),
            TileWithBytes {
                tile,
                b: bytes.clone(),
            },
        );
        hash_uploads.push(object.upload(tile.path(), bytes, &tile_opts));
    }
    stream_iter(hash_uploads)
        .buffer_unordered(UPLOAD_CONCURRENCY)
        .try_collect::<()>()
        .await?;

    // Recompute the root hash from the frontier we just built.
    tlog_core::tree_hash(
        target_size,
        &HashReaderWithOverlay {
            edge_tiles: &edge_tiles,
            overlay: &overlay,
        },
    )
    .map_err(|e| Error::from(format!("couldn't compute root hash: {e}")))
}

/// Write the mirror's served checkpoint object. Unlike tiles the
/// checkpoint is mutable (it advances as the mirror commits), so it is
/// stored with `no-store` caching (`immutable: false`).
///
/// `bytes` MUST be the checkpoint note the mirror serves at
/// `<monitoring>/<origin hash>/checkpoint`: the origin log's signed
/// checkpoint with the mirror's own cosignature line(s) appended.
///
/// # Errors
///
/// Returns an error if the storage write fails.
pub(crate) async fn write_checkpoint(object: &impl ObjectBackend, bytes: Vec<u8>) -> Result<()> {
    object
        .upload(
            CHECKPOINT_KEY,
            bytes,
            &UploadOptions {
                content_type: Some("text/plain; charset=utf-8".to_owned()),
                immutable: false,
            },
        )
        .await
}

/// Ensure the partial "cut" tiles for a tree of size `cut_size` exist, so a
/// checkpoint at `cut_size` is servable per [tlog-tiles][tiles].
///
/// Needed when the persisted frontier advanced past `cut_size` (a prior
/// upload, or a racing client): the frontier wrote wider partial tiles, so the
/// narrower ones `cut_size` requires (the level-0 data bundle when mid-tile,
/// and the partial hash tile at every level) may be missing.
///
/// A hash tile stores fixed-size hashes of complete subtrees, so its contents
/// do not depend on the tree size and the narrow tile is a byte prefix of the
/// wider stored one. Each level is therefore produced by truncating the widest
/// stored tile, located with [`TlogTile::parent`] at `frontier_size` (the
/// upper bound on everything persisted). The data bundle holds variable-length
/// entries instead, so it is reframed from the authenticated leaves.
///
/// The wide hash tiles are authenticated against `frontier_hash` before being
/// truncated, so a corrupted tile is not propagated into a cut a cosignature
/// then vouches for. Re-uploads are idempotent, so racing a concurrent commit
/// is safe.
///
/// # Errors
///
/// Returns an error on a storage fault, if a tile the cut needs has no stored
/// counterpart, or if the stored tiles fail authentication.
pub(crate) async fn ensure_cut_tiles(
    object: &impl ObjectBackend,
    cut_size: u64,
    frontier_size: u64,
    frontier_hash: Hash,
) -> Result<()> {
    if cut_size == 0 || cut_size >= frontier_size {
        return Ok(());
    }
    let last_leaf = stored_hash_index(0, cut_size - 1);

    // Authenticate the stored tiles along the cut's right edge against the
    // frontier root. These are the same (level, index) pairs the cut needs,
    // just at the frontier's wider widths.
    let wide = fetch_authenticated_tiles(object, frontier_size, &[last_leaf]).await?;
    let reader = PreloadedTlogTileReader(wide.clone());
    TileHashReader::new(frontier_size, frontier_hash, &reader)
        .read_hashes(&[last_leaf])
        .map_err(|e| Error::from(format!("authenticate frontier tiles for cut: {e:?}")))?;

    let leaf_tile = TlogTile::from_index(last_leaf);
    let opts = immutable_tile_opts();
    let mut uploads: Vec<(String, Vec<u8>)> = Vec::new();

    for level in 0.. {
        let Some(need) = leaf_tile.parent(level, cut_size) else {
            break;
        };
        let have = leaf_tile.parent(level, frontier_size).ok_or_else(|| {
            Error::from(format!(
                "no stored tile at level {level} for frontier {frontier_size}"
            ))
        })?;
        // Same width at both sizes: the tile the cut needs is the stored one.
        if need.path() == have.path() {
            continue;
        }
        let bytes = wide.get(&have).ok_or_else(|| {
            Error::from(format!("frontier tile missing for cut: {}", have.path()))
        })?;
        let want = need.width() as usize * HASH_SIZE;
        if bytes.len() < want {
            return Err(Error::from(format!(
                "stored tile {} is {} bytes, need {want} to cut",
                have.path(),
                bytes.len()
            )));
        }
        uploads.push((need.path(), bytes[..want].to_vec()));

        // The level-0 data bundle is not fixed-stride, so reframe it from the
        // leaves rather than truncating bytes.
        if level == 0 {
            let base = (cut_size - 1) / TILE_WIDTH * TILE_WIDTH;
            let leaves =
                read_persisted_leaves(object, base, cut_size - base, frontier_size, frontier_hash)
                    .await?;
            let mut bundle = Vec::new();
            for entry in &leaves {
                push_tile_leaf(&mut bundle, entry)?;
            }
            uploads.push((need.with_data_path(PathElem::Entries).path(), bundle));
        }
    }

    stream_iter(
        uploads
            .into_iter()
            .map(|(path, bytes)| object.upload(path, bytes, &opts)),
    )
    .buffer_unordered(UPLOAD_CONCURRENCY)
    .try_collect::<()>()
    .await
}

/// Upload one entry bundle (data tile). `n` is the tree size after the
/// bundle's last entry, so the bundle covers leaves ending at `n - 1`.
async fn upload_entry_bundle(object: &impl ObjectBackend, n: u64, bytes: Vec<u8>) -> Result<()> {
    let tile = TlogTile::from_index(stored_hash_index(0, n - 1)).with_data_path(PathElem::Entries);
    object
        .upload(tile.path(), bytes, &immutable_tile_opts())
        .await
}

#[cfg(test)]
mod tests {
    // The in-memory test backend implements the async ObjectBackend trait
    // without awaiting; the trait signature is `async fn`, so the impl must
    // stay `async` to match.
    #![allow(clippy::unused_async_trait_impl)]

    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use tlog_core::{EMPTY_HASH, HashReader, TlogError, stored_hashes};
    use tlog_tiles::{PreloadedTlogTileReader, TileHashReader, TlogTileRecorder};

    /// In-memory [`ObjectBackend`] for exercising the commit path without
    /// a live R2 bucket.
    #[derive(Default)]
    struct MemBackend {
        store: RefCell<HashMap<String, Vec<u8>>>,
    }

    impl ObjectBackend for MemBackend {
        async fn upload<S: AsRef<str>, D: Into<Vec<u8>>>(
            &self,
            key: S,
            data: D,
            _opts: &UploadOptions,
        ) -> Result<()> {
            self.store
                .borrow_mut()
                .insert(key.as_ref().to_owned(), data.into());
            Ok(())
        }

        async fn fetch<S: AsRef<str>>(&self, key: S) -> Result<Option<Vec<u8>>> {
            Ok(self.store.borrow().get(key.as_ref()).cloned())
        }
    }

    /// Deterministic distinct entry bytes for leaf `i`.
    fn entry(i: u64) -> Vec<u8> {
        format!("entry-{i}").into_bytes()
    }

    /// A [`HashReader`] over an in-memory stored-hash map, used to build
    /// the reference tree hash independently of the commit path.
    struct MapReader<'a>(&'a HashMap<u64, Hash>);
    impl HashReader for MapReader<'_> {
        fn read_hashes(&self, idx: &[u64]) -> std::result::Result<Vec<Hash>, TlogError> {
            idx.iter()
                .map(|i| self.0.get(i).copied().ok_or(TlogError::IndexesNotInTree))
                .collect()
        }
    }

    /// Compute the reference tree hash for the first `n` leaves by
    /// building a full in-memory stored-hash map with [`tlog_core`], so
    /// we can check that what the commit path stored is correct.
    fn reference_root(n: u64) -> Hash {
        let mut store: HashMap<u64, Hash> = HashMap::new();
        for i in 0..n {
            let hashes = stored_hashes(i, &entry(i), &MapReader(&store)).unwrap();
            for (j, h) in hashes.iter().enumerate() {
                store.insert(stored_hash_index(0, i) + j as u64, *h);
            }
        }
        tlog_core::tree_hash(n, &MapReader(&store)).unwrap()
    }

    fn leaves(range: std::ops::Range<u64>) -> Vec<Vec<u8>> {
        range.map(entry).collect()
    }

    #[tokio::test]
    async fn commit_from_empty_matches_reference() {
        let obj = MemBackend::default();
        // 300 leaves crosses one full tile (256) + a 44-wide partial.
        let root = persist_entries(&obj, 0, EMPTY_HASH, 300, &leaves(0..300))
            .await
            .unwrap();
        assert_eq!(root, reference_root(300));
    }

    #[tokio::test]
    async fn incremental_commit_reads_persisted_frontier() {
        let obj = MemBackend::default();
        // First commit to a mid-tile size (300).
        let root0 = persist_entries(&obj, 0, EMPTY_HASH, 300, &leaves(0..300))
            .await
            .unwrap();
        assert_eq!(root0, reference_root(300));

        // Second commit continues from the mid-tile frontier, exercising
        // read_edge_tiles + partial-entry-bundle reload from storage.
        let root1 = persist_entries(&obj, 300, root0, 800, &leaves(300..800))
            .await
            .unwrap();
        assert_eq!(root1, reference_root(800));
    }

    #[tokio::test]
    async fn incremental_commit_rejects_tampered_partial_bundle() {
        let obj = MemBackend::default();
        // First commit to a mid-tile size (300), leaving a partial bundle
        // [256, 300) that the next commit reloads and extends.
        let root0 = persist_entries(&obj, 0, EMPTY_HASH, 300, &leaves(0..300))
            .await
            .unwrap();

        // Corrupt a byte inside an entry of the persisted partial bundle
        // while keeping its length framing valid, so it still decodes but no
        // longer matches its authenticated leaf hash.
        let key = TlogTile::from_index(stored_hash_index(0, 299))
            .with_data_path(PathElem::Entries)
            .path();
        let mut bytes = obj
            .fetch(&key)
            .await
            .unwrap()
            .expect("partial bundle stored");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        obj.upload(&key, bytes, &immutable_tile_opts())
            .await
            .unwrap();

        // The next incremental commit reloads the tampered bundle and must
        // reject it rather than re-serve unverified bytes.
        assert!(
            persist_entries(&obj, 300, root0, 800, &leaves(300..800))
                .await
                .is_err(),
            "tampered partial bundle must be rejected"
        );
    }

    #[tokio::test]
    async fn incremental_commit_rejects_truncated_partial_bundle() {
        let obj = MemBackend::default();
        let root0 = persist_entries(&obj, 0, EMPTY_HASH, 300, &leaves(0..300))
            .await
            .unwrap();

        // Drop the trailing bytes of the partial bundle: it no longer
        // decodes to the full [256, 300) range.
        let key = TlogTile::from_index(stored_hash_index(0, 299))
            .with_data_path(PathElem::Entries)
            .path();
        let mut bytes = obj
            .fetch(&key)
            .await
            .unwrap()
            .expect("partial bundle stored");
        bytes.truncate(bytes.len() - 3);
        obj.upload(&key, bytes, &immutable_tile_opts())
            .await
            .unwrap();

        assert!(
            persist_entries(&obj, 300, root0, 800, &leaves(300..800))
                .await
                .is_err(),
            "truncated partial bundle must be rejected"
        );
    }

    #[tokio::test]
    async fn entry_bundles_roundtrip() {
        use length_prefixed::ReadLengthPrefixedBytesExt as _;
        let obj = MemBackend::default();
        persist_entries(&obj, 0, EMPTY_HASH, 260, &leaves(0..260))
            .await
            .unwrap();

        // First full bundle: leaves [0, 256).
        let full = TlogTile::from_index(stored_hash_index(0, 255))
            .with_data_path(PathElem::Entries)
            .path();
        let bytes = obj.fetch(&full).await.unwrap().expect("full bundle stored");
        let mut cur: &[u8] = &bytes;
        for i in 0..256u64 {
            let got = cur.read_length_prefixed(2).unwrap();
            assert_eq!(got, entry(i), "leaf {i} mismatch in full bundle");
        }
        assert!(cur.is_empty(), "full bundle has trailing bytes");

        // Trailing partial bundle: leaves [256, 260).
        let partial = TlogTile::from_index(stored_hash_index(0, 259))
            .with_data_path(PathElem::Entries)
            .path();
        let bytes = obj
            .fetch(&partial)
            .await
            .unwrap()
            .expect("partial bundle stored");
        let mut cur: &[u8] = &bytes;
        for i in 256..260u64 {
            let got = cur.read_length_prefixed(2).unwrap();
            assert_eq!(got, entry(i), "leaf {i} mismatch in partial bundle");
        }
        assert!(cur.is_empty(), "partial bundle has trailing bytes");
    }

    #[tokio::test]
    async fn read_persisted_leaves_from_full_and_partial_bundles() {
        let obj = MemBackend::default();
        // 300 leaves: one full bundle [0,256) + a partial bundle [256,300).
        let root = persist_entries(&obj, 0, EMPTY_HASH, 300, &leaves(0..300))
            .await
            .unwrap();

        // Prefix within the full bundle (persisted_size 300 -> stored
        // width 256 for tile 0).
        let got = read_persisted_leaves(&obj, 0, 44, 300, root).await.unwrap();
        assert_eq!(got, leaves(0..44));

        // Whole full bundle.
        let got = read_persisted_leaves(&obj, 0, 256, 300, root)
            .await
            .unwrap();
        assert_eq!(got, leaves(0..256));

        // Prefix within the trailing partial bundle (tile 1, stored width
        // 300 - 256 = 44).
        let got = read_persisted_leaves(&obj, 256, 20, 300, root)
            .await
            .unwrap();
        assert_eq!(got, leaves(256..276));
    }

    #[tokio::test]
    async fn read_persisted_leaves_missing_bundle_errors() {
        let obj = MemBackend::default();
        assert!(
            read_persisted_leaves(&obj, 0, 10, 300, EMPTY_HASH)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn read_persisted_leaves_rejects_tampered_bundle() {
        let obj = MemBackend::default();
        let root = persist_entries(&obj, 0, EMPTY_HASH, 300, &leaves(0..300))
            .await
            .unwrap();

        // Corrupt a byte inside the full bundle [0,256) while keeping the
        // length framing valid, so it still decodes but no longer matches
        // its authenticated leaf hash.
        let key = TlogTile::from_index(stored_hash_index(0, 255))
            .with_data_path(PathElem::Entries)
            .path();
        let mut bytes = obj.fetch(&key).await.unwrap().expect("full bundle stored");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        obj.upload(&key, bytes, &immutable_tile_opts())
            .await
            .unwrap();

        assert!(
            read_persisted_leaves(&obj, 0, 256, 300, root)
                .await
                .is_err(),
            "tampered persisted bundle must be rejected"
        );
    }

    /// Assert a checkpoint at `size` is servable: the stored tiles
    /// authenticate the last leaf against `reference_root(size)`, and the cut
    /// data bundle decodes to the expected leaves.
    async fn assert_servable_at(obj: &MemBackend, size: u64) {
        use length_prefixed::ReadLengthPrefixedBytesExt as _;
        let root = reference_root(size);

        let idx = [stored_hash_index(0, size - 1)];
        let tiles = fetch_authenticated_tiles(obj, size, &idx).await.unwrap();
        let reader = PreloadedTlogTileReader(tiles);
        let got = TileHashReader::new(size, root, &reader)
            .read_hashes(&idx)
            .expect("tiles authenticate against root");
        assert_eq!(got[0], record_hash(&entry(size - 1)));

        // For a mid-tile size, the cut data bundle must decode to exactly the
        // trailing leaves [subtree_start, size).
        if !size.is_multiple_of(TILE_WIDTH) {
            let subtree_start = (size / TILE_WIDTH) * TILE_WIDTH;
            let data_key = TlogTile::from_index(stored_hash_index(0, size - 1))
                .with_data_path(PathElem::Entries)
                .path();
            let bytes = obj
                .fetch(&data_key)
                .await
                .unwrap()
                .expect("cut data bundle stored");
            let mut cur: &[u8] = &bytes;
            for i in subtree_start..size {
                let got = cur.read_length_prefixed(2).unwrap();
                assert_eq!(got, entry(i), "leaf {i} mismatch in cut bundle");
            }
            assert!(cur.is_empty(), "cut bundle has trailing bytes");
        }
    }

    #[tokio::test]
    async fn ensure_cut_tiles_first_block() {
        let obj = MemBackend::default();
        // Frontier at 300; a checkpoint at 100 (mid-tile, first block) needs
        // its width-100 data bundle synthesized. The frontier only wrote the
        // width-300 partial (a full width-256 tile 0 + width-44 tile 1).
        let frontier = persist_entries(&obj, 0, EMPTY_HASH, 300, &leaves(0..300))
            .await
            .unwrap();
        ensure_cut_tiles(&obj, 100, 300, frontier).await.unwrap();
        assert_servable_at(&obj, 100).await;
    }

    #[tokio::test]
    async fn ensure_cut_tiles_aligned_below_frontier() {
        let obj = MemBackend::default();
        // Frontier at 768; a checkpoint at a tile-aligned 256 still needs the
        // upper-level partial hash tile (tile/1/000.p/1) synthesized: the
        // frontier wrote tile/1/000.p/3, never the .p/1 a tree of 256 needs.
        let frontier = persist_entries(&obj, 0, EMPTY_HASH, 768, &leaves(0..768))
            .await
            .unwrap();
        ensure_cut_tiles(&obj, 256, 768, frontier).await.unwrap();
        assert_servable_at(&obj, 256).await;
    }

    #[tokio::test]
    async fn ensure_cut_tiles_later_block() {
        let obj = MemBackend::default();
        // Frontier at 1024, a checkpoint at 900. The level-1 width differs
        // (4 vs 3), so the cut needs tile/1/000.p/3, which the frontier
        // never wrote. A frontier of 1000 would share width 3 and pass
        // without exercising the upper level at all.
        let frontier = persist_entries(&obj, 0, EMPTY_HASH, 1024, &leaves(0..1024))
            .await
            .unwrap();
        ensure_cut_tiles(&obj, 900, 1024, frontier).await.unwrap();
        assert_servable_at(&obj, 900).await;
    }

    #[tokio::test]
    async fn ensure_cut_tiles_frontier_far_ahead() {
        let obj = MemBackend::default();
        // One commit 0 -> 2000 writes only the widest partial at each level
        // (level-1 width 7). Cutting at 900 needs width 3, six blocks back.
        let frontier = persist_entries(&obj, 0, EMPTY_HASH, 2000, &leaves(0..2000))
            .await
            .unwrap();
        ensure_cut_tiles(&obj, 900, 2000, frontier).await.unwrap();
        assert_servable_at(&obj, 900).await;
    }

    #[tokio::test]
    async fn ensure_cut_tiles_aligned_cut_far_below_frontier() {
        let obj = MemBackend::default();
        // A 256-aligned cut needs no data bundle, but still needs the
        // level-1 partial at width 2 against a frontier of width 7.
        let frontier = persist_entries(&obj, 0, EMPTY_HASH, 2000, &leaves(0..2000))
            .await
            .unwrap();
        ensure_cut_tiles(&obj, 512, 2000, frontier).await.unwrap();
        assert_servable_at(&obj, 512).await;
    }

    #[tokio::test]
    async fn ensure_cut_tiles_spans_three_levels() {
        let obj = MemBackend::default();
        // Past 65536 the cut also needs a level-2 tile, so the truncation
        // walks every level rather than stopping at level 1.
        let frontier = persist_entries(&obj, 0, EMPTY_HASH, 70000, &leaves(0..70000))
            .await
            .unwrap();
        ensure_cut_tiles(&obj, 66000, 70000, frontier)
            .await
            .unwrap();
        assert_servable_at(&obj, 66000).await;
    }

    #[tokio::test]
    async fn ensure_cut_tiles_is_idempotent() {
        let obj = MemBackend::default();
        let frontier = persist_entries(&obj, 0, EMPTY_HASH, 2000, &leaves(0..2000))
            .await
            .unwrap();
        ensure_cut_tiles(&obj, 900, 2000, frontier).await.unwrap();
        ensure_cut_tiles(&obj, 900, 2000, frontier).await.unwrap();
        assert_servable_at(&obj, 900).await;
    }

    #[tokio::test]
    async fn ensure_cut_tiles_rejects_wrong_frontier_hash() {
        let obj = MemBackend::default();
        persist_entries(&obj, 0, EMPTY_HASH, 300, &leaves(0..300))
            .await
            .unwrap();
        // A frontier hash that doesn't match storage must fail authentication
        // rather than write mismatched tiles.
        assert!(
            ensure_cut_tiles(&obj, 100, 300, Hash([0xab; tlog_core::HASH_SIZE]))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn hash_tiles_authenticate_against_root() {
        let obj = MemBackend::default();
        let root = persist_entries(&obj, 0, EMPTY_HASH, 500, &leaves(0..500))
            .await
            .unwrap();

        // A TileHashReader over the stored tiles must authenticate an
        // arbitrary leaf hash against the recomputed root.
        let idx = [stored_hash_index(0, 499)];
        let recorder = TlogTileRecorder::default();
        let probe = TileHashReader::new(500, root, &recorder);
        assert!(matches!(
            probe.read_hashes(&idx),
            Err(TlogError::RecordedTilesOnly)
        ));
        let mut fetched: HashMap<TlogTile, Vec<u8>> = HashMap::new();
        for tile in recorder.0.into_inner() {
            let bytes = obj.fetch(tile.path()).await.unwrap().expect("tile stored");
            fetched.insert(tile, bytes);
        }
        let reader = PreloadedTlogTileReader(fetched);
        let hash_reader = TileHashReader::new(500, root, &reader);
        let got = hash_reader.read_hashes(&idx).expect("authenticates");
        assert_eq!(got[0], record_hash(&entry(499)));
    }
}
