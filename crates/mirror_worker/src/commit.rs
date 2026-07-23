// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Commit path for `add-entries`: persist verified entries as
//! [tlog-tiles][tiles] entry bundles and (re)compute the Merkle hash
//! tiles, growing the mirrored copy of a log from its committed tree size
//! up to a pending checkpoint.
//!
//! This mirrors the sequencer's append path
//! ([`generic_log_worker::log_ops`]'s `sequence_entries`), with two
//! differences: the mirror is stateless between requests, so
//! [`persist_entries`] re-reads and authenticates the committed frontier
//! from R2 on every commit (see [`read_edge_tiles`]) rather than caching
//! it; and it stores the tlog-tiles entry-bundle framing directly (each
//! leaf `uint16_be(len) || entry`, leaf hash `record_hash(entry)`) instead
//! of owning an application entry type.
//!
//! Commits are safe to interrupt and repeat: entry bundles and hash tiles
//! are immutable and content-addressed, so re-uploading one is a harmless
//! identical overwrite. The caller advances the durable mirror checkpoint
//! only after [`persist_entries`] returns and the recomputed root matches.
//!
//! [tiles]: https://c2sp.org/tlog-tiles

use std::collections::HashMap;

use generic_log_worker::{ObjectBackend, log_ops::UploadOptions};
use length_prefixed::{ReadLengthPrefixedBytesExt as _, WriteLengthPrefixedBytesExt as _};
use tlog_core::{
    Hash, HashReader, TlogError, record_hash, stored_hash_index, stored_hashes_for_record_hash,
};
use tlog_tiles::{PathElem, PreloadedTlogTileReader, TileHashReader, TlogTile, TlogTileRecorder};
#[allow(clippy::wildcard_imports)]
use worker::*;

/// tlog-tiles fixes a tile height of 8, i.e. 256 entries per full tile.
const TILE_WIDTH: u64 = TlogTile::FULL_WIDTH as u64;

/// Object key for the (cosigned) checkpoint the mirror serves at
/// `<monitoring>/<origin hash>/checkpoint`. Matches
/// [`generic_log_worker::log_ops::CHECKPOINT_KEY`].
pub(crate) const CHECKPOINT_KEY: &str = "checkpoint";

/// A right-edge hash tile fetched from committed storage, paired with its
/// coordinate so [`EdgeOverlayReader`] can index into it.
///
/// Port of `generic_log_worker`'s private `TileWithBytes`.
struct EdgeTile {
    tile: TlogTile,
    bytes: Vec<u8>,
}

/// [`HashReader`] over the committed right-edge tiles plus an overlay of
/// hashes freshly computed for the entries being committed.
///
/// Faithful port of `generic_log_worker`'s private `HashReaderWithOverlay`:
/// a requested stored-hash index is served from the `overlay` (new
/// hashes) if present, otherwise from the committed edge tile at that
/// index's level.
struct EdgeOverlayReader<'a> {
    edge_tiles: &'a HashMap<u8, EdgeTile>,
    overlay: &'a HashMap<u64, Hash>,
}

impl HashReader for EdgeOverlayReader<'_> {
    fn read_hashes(&self, indexes: &[u64]) -> std::result::Result<Vec<Hash>, TlogError> {
        let mut out = Vec::with_capacity(indexes.len());
        for &id in indexes {
            if let Some(h) = self.overlay.get(&id) {
                out.push(*h);
                continue;
            }
            let level = TlogTile::from_index(id).level();
            let Some(edge) = self.edge_tiles.get(&level) else {
                return Err(TlogError::IndexesNotInTree);
            };
            out.push(edge.tile.hash_at_index(&edge.bytes, id)?);
        }
        Ok(out)
    }
}

/// Read and verify the right-edge hash tiles of the committed tree from
/// object storage, keyed by tile level.
///
/// Port of `generic_log_worker`'s private `read_edge_tiles`: it reads the
/// last committed leaf through a [`TileHashReader`], which fetches and
/// authenticates every tile on the path to the root against
/// `committed_hash` as a side effect. Only the rightmost tile per level is
/// retained (the frontier).
///
/// # Errors
///
/// Returns an error if a required tile is missing from storage or fails
/// authentication against `committed_hash`.
async fn read_edge_tiles(
    object: &impl ObjectBackend,
    committed_size: u64,
    committed_hash: Hash,
) -> Result<HashMap<u8, EdgeTile>> {
    let indexes = [stored_hash_index(0, committed_size - 1)];

    // Discover which tiles are needed to authenticate the last leaf.
    let recorder = TlogTileRecorder::default();
    let probe = TileHashReader::new(committed_size, committed_hash, &recorder);
    match probe.read_hashes(&indexes) {
        Err(TlogError::RecordedTilesOnly) => {}
        Ok(_) => return Err(Error::from("edge-tile probe unexpectedly succeeded")),
        Err(e) => return Err(Error::from(format!("edge-tile probe failed: {e}"))),
    }
    let needed = recorder.0.into_inner();

    // Fetch them from R2.
    let mut fetched: HashMap<TlogTile, Vec<u8>> = HashMap::with_capacity(needed.len());
    for tile in needed {
        let bytes = object.fetch(tile.path()).await?.ok_or_else(|| {
            Error::from(format!(
                "committed tile missing from storage: {}",
                tile.path()
            ))
        })?;
        fetched.insert(tile, bytes);
    }

    // Authenticate the fetched tiles against the committed tree hash.
    let reader = PreloadedTlogTileReader(fetched);
    let hash_reader = TileHashReader::new(committed_size, committed_hash, &reader);
    hash_reader
        .read_hashes(&indexes)
        .map_err(|e| Error::from(format!("committed edge tiles failed authentication: {e}")))?;

    // Keep only the rightmost tile per level.
    let mut edge_tiles: HashMap<u8, EdgeTile> = HashMap::new();
    for (tile, bytes) in reader.0 {
        let keep = edge_tiles.get(&tile.level()).is_none_or(|e| {
            e.tile.level_index() < tile.level_index()
                || (e.tile.level_index() == tile.level_index() && e.tile.width() < tile.width())
        });
        if keep {
            edge_tiles.insert(tile.level(), EdgeTile { tile, bytes });
        }
    }
    Ok(edge_tiles)
}

/// Read `count` already-committed log entries starting at leaf index
/// `start` back out of their entry bundle in object storage.
///
/// `start` MUST be aligned to a 256-entry bundle boundary and `start +
/// count` MUST NOT exceed `committed_size`, so the requested leaves all
/// live in the single entry bundle beginning at `start` (a package's
/// subtree spans at most 256 leaves). Returns the entries in order,
/// stripped of their uint16 length prefixes.
///
/// Used by [`crate::add_entries`] to reconstruct the subtree hash of a
/// non-256-aligned first package, whose leading leaves `[subtree_start,
/// upload_start)` are already in the log and therefore absent from the
/// uploaded package.
///
/// # Errors
///
/// Returns an error if the bundle is missing from storage or is shorter
/// than `count` entries (i.e. the requested leaves were not actually
/// committed).
pub(crate) async fn read_committed_leaves(
    object: &impl ObjectBackend,
    start: u64,
    count: u64,
    committed_size: u64,
) -> Result<Vec<Vec<u8>>> {
    debug_assert!(
        start.is_multiple_of(TILE_WIDTH),
        "start must be bundle-aligned"
    );
    debug_assert!(start + count <= committed_size, "leaves must be committed");

    // The bundle's stored width is 256 if the whole tile is committed,
    // otherwise the trailing partial width `committed_size - start`. The
    // data-tile path encodes that width (`from_index` derives it from the
    // last stored leaf), so pick the last committed leaf in this tile.
    let stored_width = TILE_WIDTH.min(committed_size - start);
    let last_leaf = start + stored_width - 1;
    let tile =
        TlogTile::from_index(stored_hash_index(0, last_leaf)).with_data_path(PathElem::Entries);
    let bytes = object
        .fetch(tile.path())
        .await?
        .ok_or_else(|| Error::from(format!("committed entry bundle missing: {}", tile.path())))?;

    let mut cur: &[u8] = &bytes;
    let mut out = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for i in 0..count {
        let entry = cur.read_length_prefixed(2).map_err(|e| {
            Error::from(format!(
                "committed bundle leaf {} truncated: {e}",
                start + i
            ))
        })?;
        out.push(entry);
    }
    Ok(out)
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

/// Persist entries `[committed_size, target_size)` into object storage,
/// growing the mirrored tree and returning the recomputed root hash.
///
/// `entries[i]` MUST be the raw log-entry bytes (no length prefix) for
/// leaf `committed_size + i`, covering exactly `[committed_size,
/// target_size)`.
///
/// Reads the committed frontier from R2 (skipped at size 0), replays each
/// leaf through [`stored_hashes_for_record_hash`] while flushing full and
/// trailing-partial entry bundles, then (re)computes and uploads every
/// hash tile in [`TlogTile::new_tiles`]`(committed_size, target_size)`.
///
/// It does not write the checkpoint object or advance the mirror
/// checkpoint; the caller does that after verifying the returned root.
///
/// # Errors
///
/// Returns an error on any storage failure, if a committed tile is
/// missing or fails authentication, or if `entries.len()` does not equal
/// `target_size - committed_size`.
pub(crate) async fn persist_entries(
    object: &impl ObjectBackend,
    committed_size: u64,
    committed_hash: Hash,
    target_size: u64,
    entries: &[Vec<u8>],
) -> Result<Hash> {
    let expected = target_size
        .checked_sub(committed_size)
        .ok_or_else(|| Error::from("target_size < committed_size"))?;
    if entries.len() as u64 != expected {
        return Err(Error::from(format!(
            "commit entry count {} != range {committed_size}..{target_size}",
            entries.len()
        )));
    }
    if expected == 0 {
        return Ok(committed_hash);
    }

    let mut edge_tiles = if committed_size == 0 {
        HashMap::new()
    } else {
        read_edge_tiles(object, committed_size, committed_hash).await?
    };

    // Load the current partial entry bundle so we extend rather than
    // overwrite it. Only exists when the frontier is mid-tile.
    let mut data_tile = Vec::new();
    if committed_size > 0 && !committed_size.is_multiple_of(TILE_WIDTH) {
        let partial = TlogTile::from_index(stored_hash_index(0, committed_size - 1))
            .with_data_path(PathElem::Entries);
        data_tile = object.fetch(partial.path()).await?.ok_or_else(|| {
            Error::from(format!("partial entry bundle missing: {}", partial.path()))
        })?;
    }

    // Replay leaves, flushing entry bundles at 256-entry boundaries.
    let mut overlay: HashMap<u64, Hash> = HashMap::new();
    let mut n = committed_size;
    for entry in entries {
        push_tile_leaf(&mut data_tile, entry)?;
        let hashes = stored_hashes_for_record_hash(
            n,
            record_hash(entry),
            &EdgeOverlayReader {
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
            upload_entry_bundle(object, n, std::mem::take(&mut data_tile)).await?;
        }
    }
    debug_assert_eq!(n, target_size);
    // Trailing partial entry bundle.
    if !target_size.is_multiple_of(TILE_WIDTH) {
        upload_entry_bundle(object, target_size, std::mem::take(&mut data_tile)).await?;
    }

    // (Re)compute and upload hash tiles.
    for tile in TlogTile::new_tiles(committed_size, target_size) {
        let bytes = tile
            .read_data(&EdgeOverlayReader {
                edge_tiles: &edge_tiles,
                overlay: &overlay,
            })
            .map_err(|e| Error::from(format!("couldn't build hash tile {tile:?}: {e}")))?;
        object
            .upload(tile.path(), bytes.clone(), &immutable_tile_opts())
            .await?;
        // Keep edge_tiles current so read_data of a higher/next tile can
        // still resolve committed hashes it depends on.
        edge_tiles.insert(tile.level(), EdgeTile { tile, bytes });
    }

    // Recompute the root hash from the frontier we just built.
    tlog_core::tree_hash(
        target_size,
        &EdgeOverlayReader {
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
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use tlog_core::{EMPTY_HASH, stored_hashes};

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
    async fn incremental_commit_reads_committed_frontier() {
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
    async fn read_committed_leaves_from_full_and_partial_bundles() {
        let obj = MemBackend::default();
        // 300 leaves: one full bundle [0,256) + a partial bundle [256,300).
        persist_entries(&obj, 0, EMPTY_HASH, 300, &leaves(0..300))
            .await
            .unwrap();

        // Prefix within the full bundle (committed_size 300 -> stored
        // width 256 for tile 0).
        let got = read_committed_leaves(&obj, 0, 44, 300).await.unwrap();
        assert_eq!(got, leaves(0..44));

        // Whole full bundle.
        let got = read_committed_leaves(&obj, 0, 256, 300).await.unwrap();
        assert_eq!(got, leaves(0..256));

        // Prefix within the trailing partial bundle (tile 1, stored width
        // 300 - 256 = 44).
        let got = read_committed_leaves(&obj, 256, 20, 300).await.unwrap();
        assert_eq!(got, leaves(256..276));
    }

    #[tokio::test]
    async fn read_committed_leaves_missing_bundle_errors() {
        let obj = MemBackend::default();
        assert!(read_committed_leaves(&obj, 0, 10, 300).await.is_err());
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
