// Ported from "mod" (https://pkg.go.dev/golang.org/x/mod)
// Copyright 2009 The Go Authors
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause
//
// This ports code from the original Go project "mod" and adapts it to Rust idioms.
//
// Modifications and Rust implementation Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Provides functionality for a tiled transparency log.
//!
//! This file contains code ported from the original project [tlog](https://pkg.go.dev/golang.org/x/mod/sumdb/tlog).
//!
//! References:
//! - [tile.go](https://cs.opensource.google/go/x/mod/+/refs/tags/v0.21.0:sumdb/tlog/tile.go)
//! - [tile_test.go](https://cs.opensource.google/go/x/mod/+/refs/tags/v0.21.0:sumdb/tlog/tile_test.go)

use crate::tlog::{
    node_hash, split_stored_hash_index, stored_hash_index, tree_hash_indexes, Hash, HashReader,
    TlogError, HASH_SIZE,
};
use std::cell::RefCell;
use std::cmp::max;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

// To limit the size of any particular directory listing, we encode the (possibly very large)
// number N by encoding three digits at a time.  For example, 123456789 encodes as x123/x456/789.
// Each directory has at most 1000 each xNNN, NNN, and NNN.p children, so there are at most 3000
// entries in any one directory.
const PATH_BASE: u64 = 1000;

/// A Tile is a description of a transparency log tile.  A tile of height H at level L offset N
/// lists W consecutive hashes at level `H*L` of the tree starting at offset `N*(2**H)`.  A
/// complete tile lists `2**H` hashes; a partial tile lists fewer.  Note that a tile represents the
/// entire subtree of height `H` with those hashes as the leaves. The levels above `H*L` can be
/// reconstructed by hashing the leaves.
///
/// Each Tile can be encoded as a “tile coordinate path” of the form `tile/H/L/NNN[.p/W]`.  The
/// `.p/W` suffix is present only for partial tiles, meaning `W < 2**H`.  The `NNN` element is an
/// encoding of `N` into 3-digit path elements.  All but the last path element begins with an "x".
/// For example, `Tile{H: 3, L: 4, N: 1234067, W: 1}`'s path is `tile/3/4/x001/x234/067.p/1`, and
/// `Tile{H: 3, L: 4, N: 1234067, W: 8}`'s path is `tile/3/4/x001/x234/067`.  See the [`Tile::path`]
/// method and the [`Tile::from_path`] function.
///
/// The `data_elem` field indicates that the tile holds raw record data instead of hashes, and
/// provides the path element ("data" for static-ct-api or "entries" for tlog-tiles) to use when
/// encoding the level in the tile path.
///
/// See also <https://golang.org/design/25530-sumdb#checksum-database> and
/// <https://research.swtch.com/tlog#tiling_a_log>.
#[derive(Debug, Eq, Hash, PartialEq, Default, Clone, Copy)]
pub struct Tile {
    h: u8,                           // height of tile (1 ≤ H ≤ 30)
    l: u8,                           // level in tiling (0 ≤ L ≤ 63)
    n: u64,                          // number within level (0 ≤ N, unbounded)
    w: u32,                          // width of tile (1 ≤ W ≤ 2**H; 2**H is complete tile)
    data_path_opt: Option<PathElem>, // whether or not this is a data tile, and the data path element to use for encoding
}

#[derive(Debug, Eq, Hash, PartialEq, Clone, Copy)]
pub enum PathElem {
    Data,
    Entries,
    Custom(&'static str),
}

impl fmt::Display for PathElem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Data => "data",
                Self::Entries => "entries",
                Self::Custom(p) => p,
            }
        )
    }
}

impl Tile {
    /// Return a new tile with the given parameters.
    ///
    /// # Panics
    ///
    /// Panics if any of the tile parameters are outside the valid ranges.
    pub fn new(h: u8, l: u8, n: u64, w: u32, data_path_opt: Option<PathElem>) -> Self {
        assert!(
            (1..=30).contains(&h) && l < 64 && (1..=(1 << h)).contains(&w),
            "invalid tile"
        );
        Self {
            h,
            l,
            n,
            w,
            data_path_opt,
        }
    }

    /// Returns the tile's height.
    pub fn height(&self) -> u8 {
        self.h
    }

    /// Returns the tile's level.
    pub fn level(&self) -> u8 {
        self.l
    }

    /// Returns the tile's index within level.
    pub fn level_index(&self) -> u64 {
        self.n
    }

    /// Returns the tile's width.
    pub fn width(&self) -> u32 {
        self.w
    }

    /// Returns whether or not this is a data tile.
    pub fn is_data(&self) -> bool {
        self.data_path_opt.is_some()
    }

    /// Returns the coordinates of the tiles of height `h ≥ 1` that must be published when publishing
    /// from a tree of size `new_tree_size` to replace a tree of size `old_tree_size`.  (No tiles need
    /// to be published for a tree of size zero.)
    ///
    /// # Panics
    ///
    /// Panics if `h = 0`.
    pub fn new_tiles(h: u8, old_tree_size: u64, new_tree_size: u64) -> Vec<Self> {
        let mut tiles = Vec::new();
        let mut l = 0;
        while new_tree_size >> (h * l) > 0 {
            let old_n = old_tree_size >> (h * l);
            let new_n = new_tree_size >> (h * l);
            if old_n != new_n {
                for n in (old_n >> h)..(new_n >> h) {
                    tiles.push(Self::new(h, l, n, 1 << h, None));
                }
                let n = new_n >> h;
                let w = u32::try_from(new_n - (n << h)).unwrap();
                if w > 0 {
                    tiles.push(Self::new(h, l, n, w, None));
                }
            }
            l += 1;
        }

        tiles
    }

    /// Returns the tile of fixed height `h ≥ 1`
    /// and least width storing the given hash storage index.
    ///
    /// # Panics
    ///
    /// Panics if `h = 0`.
    pub fn from_index(h: u8, index: u64) -> Self {
        assert!(h != 0, "invalid height {h}");
        let (t, _, _) = Tile::from_index_internal(h, index);
        t
    }

    // Returns the tile of height `h ≥ 1` storing the given hash index, which can be reconstructed
    // using `tile_hash(data[start:end])`.
    fn from_index_internal(h: u8, index: u64) -> (Self, usize, usize) {
        let (mut level, mut n) = split_stored_hash_index(index);
        let t_l = level / h;
        level -= t_l * h;
        let t_n = n << level >> h; // now level within tile
        n -= t_n << h >> level;
        let w = u32::try_from((n + 1) << level).unwrap(); // now n within tile at level
        let start = usize::try_from(n << level).unwrap() * HASH_SIZE;
        let end = usize::try_from((n + 1) << level).unwrap() * HASH_SIZE;
        (Self::new(h, t_l, t_n, w, None), start, end)
    }

    /// Returns the hash at the given storage index.
    ///
    /// # Errors
    ///
    /// Returns an error if `t` is not `Tile::from_index_internal(t.H,
    /// index)` or a wider version, or `data` is not `t`'s tile data (of length at least `t.W*HASH_SIZE`).
    pub fn hash_at_index(&self, data: &[u8], index: u64) -> Result<Hash, TlogError> {
        if self.data_path_opt.is_some() || data.len() < self.w as usize * HASH_SIZE {
            return Err(TlogError::InvalidTile);
        }

        let (t1, start, end) = Tile::from_index_internal(self.h, index);
        if self.l != t1.l || self.n != t1.n || self.w < t1.w {
            return Err(TlogError::InvalidTile);
        }

        Ok(Tile::subtree_hash(&data[start..end]))
    }

    /// Path returns a tile coordinate path describing t.
    pub fn path(&self, with_height: bool) -> String {
        let mut n = self.n;
        let h_str = if with_height {
            &format!("/{}", self.h)
        } else {
            ""
        };
        let mut parts = vec![format!("/{:03}", n % PATH_BASE)];
        while n >= PATH_BASE {
            n /= PATH_BASE;
            parts.push(format!("/x{:03}", n % PATH_BASE));
        }
        let n_str: &str = &parts.iter().rev().map(String::as_str).collect::<String>();
        let p_str = if self.w == 1 << self.h {
            ""
        } else {
            &format!(".p/{}", self.w)
        };
        let l_str = if let Some(elem) = self.data_path_opt {
            &elem.to_string()
        } else {
            &format!("{}", self.l)
        };
        format!("tile{h_str}/{l_str}{n_str}{p_str}")
    }

    /// Returns the tile's `k`'th tile parent in the tiles for a tree of size `n`.  If there is no such
    /// parent, returns None.
    ///
    /// # Panics
    ///
    /// Panics if integer conversion fails.
    pub fn parent(&self, k: u8, n: u64) -> Option<Self> {
        let mut t = *self;
        t.l += k;
        t.n >>= k * t.h;
        t.w = 1 << t.h;
        let max = n >> (t.l * t.h);
        if ((t.n << t.h) + u64::from(t.w)) >= max {
            if (t.n << t.h) >= max {
                return None;
            }
            t.w = u32::try_from(max - (t.n << t.h)).unwrap();
        }
        Some(t)
    }

    /// Parses a tile coordinate path.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid.
    ///
    /// # Panics
    ///
    /// Panics if there are internal math errors.
    pub fn from_path(
        path: &str,
        with_height: bool,
        data_path: PathElem,
    ) -> Result<Self, BadPathError> {
        // Calculate based on max supported values.
        let max_path_len = "tile/30".len()
            + max(data_path.to_string().len() + 1, "/63".len())
            + "/x018/x446/x744/x073/x709/x551/615.p/1073741823".len();
        if path.len() > max_path_len {
            return Err(BadPathError(path.into()));
        }

        let min_path_elems = if with_height { 3 } else { 2 };

        let mut components: Vec<&str> = path.split('/').collect();
        let len = components.len();

        if len < min_path_elems || components[0] != "tile" {
            return Err(BadPathError(path.into()));
        }

        let mut next_idx = 1;
        let h = if with_height {
            next_idx += 1;
            u8::from_str(components[1]).map_err(|_| BadPathError(path.into()))?
        } else {
            TlogTile::HEIGHT
        };

        let (l, data_path_opt) = if components[next_idx] == data_path.to_string() {
            (0, Some(data_path))
        } else {
            (
                u8::from_str(components[next_idx]).map_err(|_| BadPathError(path.into()))?,
                None,
            )
        };
        if l > 63 {
            return Err(BadPathError(path.into()));
        }

        next_idx += 1;

        if !(1..=30).contains(&h) {
            return Err(BadPathError(path.into()));
        }

        let mut w = 1 << h;
        #[allow(clippy::case_sensitive_file_extension_comparisons)]
        if len > min_path_elems && components[len - 2].ends_with(".p") {
            let ww = u32::from_str(components[len - 1]).map_err(|_| BadPathError(path.into()))?;
            if !(0..w).contains(&ww) {
                return Err(BadPathError(path.into()));
            }
            w = ww;
            components[len - 2] = components[len - 2].strip_suffix(".p").unwrap();
            components.pop();
        }

        components = components[next_idx..].to_vec();

        let mut n = 0_u64;
        for s in components {
            let nn =
                u64::from_str(s.trim_start_matches('x')).map_err(|_| BadPathError(path.into()))?;
            if nn >= PATH_BASE {
                return Err(BadPathError(path.into()));
            }
            // Fuzzing discovered an integer overflow here, triggered by for example
            // 'tile/30/data/x018/x446/x744/x073/x709/x551/616.p/255' where N corresponds to
            // u64::MAX+1. We could safely allow the integer to overflow (which happens in the Go
            // library), as the path != tile.path() check below catches that case, but let's just
            // explicitly fail.
            n = n
                .checked_mul(PATH_BASE)
                .ok_or(BadPathError(path.into()))?
                .checked_add(nn)
                .ok_or(BadPathError(path.into()))?;
        }

        let tile = Self::new(h, l, n, w, data_path_opt);

        if path != tile.path(with_height) {
            return Err(BadPathError(path.into()));
        }

        Ok(tile)
    }

    /// Reads the hashes for the tile from `r` and returns the corresponding tile data.
    ///
    /// # Errors
    ///
    /// Returns an error if `read_hashes` returns an error when attempting to read indexes.
    ///
    /// # Panics
    ///
    /// Panics if `read_hashes` does not return the same number of hashes as passed-in indexes.
    pub fn read_data<R: HashReader>(&self, r: &R) -> Result<Vec<u8>, TlogError> {
        let mut size = self.w as usize;
        if size == 0 {
            size = 1 << self.h;
        }

        let start = self.n << self.h;
        let mut indexes = Vec::with_capacity(size);
        for i in 0..size as u64 {
            indexes.push(stored_hash_index(self.h * self.l, start + i));
        }

        let hashes = r.read_hashes(&indexes)?;
        assert!(
            hashes.len() == indexes.len(),
            "read_hashes returned invalid size"
        );

        let mut tile_data = vec![0u8; size * HASH_SIZE];
        for i in 0..size {
            tile_data[i * HASH_SIZE..(i + 1) * HASH_SIZE].copy_from_slice(&hashes[i].0);
        }

        Ok(tile_data)
    }

    /// Computes the subtree hash corresponding to the `(2^K)-1` hashes in data.
    ///
    /// # Panics
    ///
    /// Panics if data is empty.
    pub fn subtree_hash(data: &[u8]) -> Hash {
        assert!(!data.is_empty(), "bad math in tile hash");

        if data.len() == HASH_SIZE {
            return Hash(data.try_into().unwrap());
        }

        let n = data.len() / 2;
        node_hash(
            Self::subtree_hash(&data[..n]),
            Self::subtree_hash(&data[n..]),
        )
    }
}

/// [`TlogTile`] is a wrapper around [`Tile`] for compatibility with the
/// [tlog-tiles](c2sp.org/tlog-tiles) spec.
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, Hash)]
pub struct TlogTile(Tile);

impl std::ops::Deref for TlogTile {
    type Target = Tile;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for TlogTile {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl TlogTile {
    /// The [tlog-tiles](c2sp.org/tlog-tiles) spec fixes tile height `H = 8`, such that
    /// each full tile contains 256 entries.
    pub const HEIGHT: u8 = 8;
    pub const FULL_WIDTH: u32 = 1 << Self::HEIGHT;

    /// Return a new tile with the given parameters.
    ///
    /// # Panics
    ///
    /// Panics if any of the tile parameters are outside the valid ranges.
    pub fn new(l: u8, n: u64, w: u32, data_elem: Option<PathElem>) -> Self {
        TlogTile(Tile::new(Self::HEIGHT, l, n, w, data_elem))
    }

    /// Returns the tile of fixed height `h = 8`
    /// and least width storing the given hash storage index.
    pub fn from_index(index: u64) -> Self {
        TlogTile(Tile::from_index(Self::HEIGHT, index))
    }

    /// Returns the tile of fixed height `h = 8`
    /// and least width storing the given leaf index.
    pub fn from_leaf_index(leaf_index: u64) -> Self {
        // Convert from leaf index to hash storage index on level 0
        let hash_index = stored_hash_index(0, leaf_index);
        Self::from_index(hash_index)
    }

    /// Returns the coordinates of the tiles of height `h = 8` that must be
    /// published when publishing from a tree of size `new_tree_size` to replace
    /// a tree of size `old_tree_size`.  (No tiles need to be published for a
    /// tree of size zero.)
    pub fn new_tiles(old_tree_size: u64, new_tree_size: u64) -> Vec<Self> {
        Tile::new_tiles(Self::HEIGHT, old_tree_size, new_tree_size)
            .into_iter()
            .map(TlogTile)
            .collect()
    }

    /// Path returns a tile coordinate path describing t, according to
    /// <c2sp.org/tlog-tiles>. It differs from [`tlog_tiles::Tile::path`] in
    /// that it doesn't include an explicit tile height. The `data_path`
    /// parameter should be `"entries"` for tlog-tiles, and `"data"` for
    /// static-ct-api.
    pub fn path(&self) -> String {
        self.0.path(false)
    }

    /// Returns the tile's `k`'th tile parent in the tiles for a tree of size `n`.  If there is no such
    /// parent, returns None.
    pub fn parent(&self, k: u8, n: u64) -> Option<Self> {
        self.0.parent(k, n).map(Self)
    }

    #[must_use]
    pub fn with_data_path(&self, path: PathElem) -> Self {
        Self(Tile {
            l: self.0.l,
            h: self.0.h,
            n: self.0.n,
            w: self.0.w,
            data_path_opt: Some(path),
        })
    }
}

/// An error that can be returned while parsing a tile path.
#[derive(Debug)]
pub struct BadPathError(String);

impl fmt::Display for BadPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed tile path: {}", self.0)
    }
}

/// A `TileReader` reads tiles from a backend database.
#[allow(clippy::module_name_repetitions)]
pub trait TileReader {
    /// Returns the height of the available tiles.
    fn height(&self) -> u8;

    /// Returns the data for each requested tile.  If [`TileReader::read_tiles`] returns a non-error,
    /// it must also return a data record for each tile `data.len() == tiles.len()` and each data
    /// record must be the correct length `(len(data[i]) == tiles[i].W*HashSize)`.
    ///
    /// An implementation of [`TileReader::read_tiles`] typically reads them from an on-disk cache or
    /// else from a remote tile server. Tile data downloaded from a server should be considered
    /// suspect and not saved into a persistent on-disk cache before returning from
    /// [`TileReader::read_tiles`].  When the client confirms the validity of the tile data, it will
    /// call `SaveTiles` to signal that they can be safely written to persistent storage.  See also
    /// <https://research.swtch.com/tlog#authenticating_tiles>.
    ///
    /// # Errors
    ///
    /// Returns an error if unable to read all of the requested tiles.
    fn read_tiles(&self, tiles: &[Tile]) -> Result<Vec<Vec<u8>>, TlogError>;

    /// Informs the [`TileReader`] that the tile data returned by [`TileReader::read_tiles`] has been
    /// confirmed as valid and can be saved in persistent storage (on disk).
    fn save_tiles(&self, tiles: &[Tile], data: &[Vec<u8>]);
}

/// A `TileHashReader` implements the [`HashReader`] trait and satisfies requests by loading
/// tiles of the given tree.
///
/// The returned [`HashReader`] checks that loaded tiles are valid for the given tree.
/// Therefore, any hashes returned by the `HashReader` are already proven to be in the tree.
#[allow(clippy::module_name_repetitions)]
pub struct TileHashReader<'a> {
    tree_size: u64,
    tree_hash: Hash,
    tr: &'a dyn TileReader,
}

impl<'a> TileHashReader<'a> {
    /// Returns a new [`TileHashReader`].
    pub fn new<R: TileReader>(tree_size: u64, tree_hash: Hash, tr: &'a R) -> Self {
        Self {
            tree_size,
            tree_hash,
            tr,
        }
    }
}

impl HashReader for TileHashReader<'_> {
    /// Implements [`HashReader::read_hashes`] by returning the hashes with the
    /// given stored hash indexes in a tiled tree. It may fetch additional tiles
    /// in order to authenticate all tiles against `self.tree_hash`.
    ///
    /// # Errors
    ///
    /// Returns an error if unable to read hashes for all of the requested
    /// indexes.
    ///
    /// # Panics
    ///
    /// Panics if any calls to `Tile::parent` fail to find a parent tile. This
    /// differs from the Go implementation which returns an empty Tile{} when it
    /// fails to find a parent.
    fn read_hashes(&self, indexes: &[u64]) -> Result<Vec<Hash>, TlogError> {
        let h = self.tr.height();

        let mut tile_order = HashMap::new(); // tile_order[tileKey(tiles[i])] = i
        let mut tiles = Vec::new();

        // Plan to fetch tiles necessary to recompute tree hash. If it matches,
        // those tiles are authenticated.
        let stx = tree_hash_indexes(self.tree_size);
        let mut stx_tile_order = vec![0; stx.len()];

        for (i, &x) in stx.iter().enumerate() {
            let tile = Tile::from_index(h, x).parent(0, self.tree_size).unwrap();
            if let Some(&j) = tile_order.get(&tile) {
                stx_tile_order[i] = j;
            } else {
                stx_tile_order[i] = tiles.len();
                tile_order.insert(tile, tiles.len());
                tiles.push(tile);
            }
        }

        // Plan to fetch tiles containing the indexes, along with any parent
        // tiles needed for authentication. For most calls, the parents are
        // being fetched anyway.
        let mut index_tile_order = vec![0; indexes.len()];
        for (i, &x) in indexes.iter().enumerate() {
            if x >= stored_hash_index(0, self.tree_size) {
                return Err(TlogError::IndexesNotInTree);
            }

            let tile = Tile::from_index(h, x);

            // Walk up parent tiles until we find one we've requested.
            // That one will be authenticated.
            let mut k = 0;
            loop {
                let p = tile.parent(k, self.tree_size).unwrap();
                if let Some(&j) = tile_order.get(&p) {
                    if k == 0 {
                        index_tile_order[i] = j;
                    }
                    break;
                }
                k += 1;
            }

            // Walk back down recording child tiles after parents. This loop
            // ends by revisiting the tile for this index (tile.parent(0,
            // r.tree.N)) unless k == 0, in which case the previous loop did it.
            for k in (0..k).rev() {
                let p = tile.parent(k, self.tree_size).unwrap();
                if p.w != (1 << p.h) {
                    // Only full tiles have parents.
                    // This tile has a parent, so it must be full.
                    return Err(TlogError::BadMath);
                }
                tile_order.insert(p, tiles.len());
                if k == 0 {
                    index_tile_order[i] = tiles.len();
                }
                tiles.push(p);
            }
        }

        // Fetch all the tile data.
        let data = self.tr.read_tiles(&tiles)?;
        if data.len() != tiles.len() {
            return Err(TlogError::BadMath);
        }
        for (i, tile) in tiles.iter().enumerate() {
            if data[i].len() != tile.w as usize * HASH_SIZE {
                return Err(TlogError::BadMath);
            }
        }

        // Authenticate the initial tiles against the tree hash.
        // They are arranged so that parents are authenticated before children.
        // First the tiles needed for the tree hash.
        let mut th = tiles[stx_tile_order[stx.len() - 1]]
            .hash_at_index(&data[stx_tile_order[stx.len() - 1]], stx[stx.len() - 1])?;
        for i in (0..stx.len() - 1).rev() {
            let h = tiles[stx_tile_order[i]].hash_at_index(&data[stx_tile_order[i]], stx[i])?;
            th = node_hash(h, th);
        }
        if th != self.tree_hash {
            return Err(TlogError::InconsistentTile);
        }

        // Authenticate full tiles against their parents.
        for i in stx.len()..tiles.len() {
            let tile = tiles[i];
            let p = tile.parent(1, self.tree_size).unwrap();
            let Some(j) = tile_order.get(&p) else {
                return Err(TlogError::BadMath);
            };
            let h = p.hash_at_index(&data[*j], stored_hash_index(p.l * p.h, tile.n))?;
            if h != Tile::subtree_hash(&data[i]) {
                return Err(TlogError::InconsistentTile);
            }
        }

        // Now we have all the tiles needed for the requested hashes,
        // and we've authenticated the full tile set against the trusted tree hash.
        self.tr.save_tiles(&tiles, &data);

        // Pull out the requested hashes.
        let mut hashes = Vec::with_capacity(indexes.len());
        for (i, &x) in indexes.iter().enumerate() {
            let j = index_tile_order[i];
            let h = tiles[j].hash_at_index(&data[j], x)?;
            hashes.push(h);
        }

        Ok(hashes)
    }
}

/// A fake `TileReader` that just records the tiles that are requested, but
/// doesn't actually read the tile data.
#[derive(Default)]
pub struct TlogTileRecorder(pub RefCell<Vec<TlogTile>>);

impl TileReader for TlogTileRecorder {
    fn height(&self) -> u8 {
        TlogTile::HEIGHT
    }

    /// Records the requested tree tiles without actually reading them, and
    /// always returns an error.
    ///
    /// # Errors
    ///
    /// Will return a `TlogError::InvalidInput` if any of the requested tiles is
    /// not a valid `TlogTile`. Otherwise, always returns a
    /// `TlogError::RecordedTilesOnly` in compliance with the `TileReader`
    /// contract.
    fn read_tiles(&self, tiles: &[Tile]) -> Result<Vec<Vec<u8>>, TlogError> {
        // Record the tiles we're meant to read. Convert them to tlog tiles,
        // ensuring their height is always 8
        *self.0.borrow_mut() = tiles
            .iter()
            .map(|t| {
                if t.height() == TlogTile::HEIGHT {
                    Ok(TlogTile::new(t.level(), t.level_index(), t.width(), None))
                } else {
                    Err(TlogError::ConditionNotMet(
                        "TlogTileRecorder cannot read tiles of height not equal to 8".to_string(),
                    ))
                }
            })
            .collect::<Result<Vec<_>, TlogError>>()?;

        // Return an error since we did not actually read the tiles.
        Err(TlogError::RecordedTilesOnly)
    }

    // Do nothing; we only use this struct to record tiles.
    fn save_tiles(&self, _tiles: &[Tile], _data: &[Vec<u8>]) {}
}

/// A thin wrapper around a map of tlog tile ⇒ bytestring. Implements
/// `TileReader` so we can use it within `TileHashReader::read_tiles` to read
/// and verify tiles.
pub struct PreloadedTlogTileReader(pub HashMap<TlogTile, Vec<u8>>);

impl TileReader for PreloadedTlogTileReader {
    fn height(&self) -> u8 {
        TlogTile::HEIGHT
    }

    /// Converts the given tiles into tlog tiles, then reads them from the
    /// internal hashmap.
    ///
    /// # Errors
    /// Errors if any of given tiles hash height != 8, or is a data tile. Also
    /// errors if the hash map is missing tiles from the input here.
    fn read_tiles(&self, tiles: &[Tile]) -> Result<Vec<Vec<u8>>, TlogError> {
        let mut buf = Vec::with_capacity(HASH_SIZE * TlogTile::FULL_WIDTH as usize);

        for tile in tiles {
            // Convert the tile to a tlog-tile, ie one where height=8 and data=false
            if tile.height() != TlogTile::HEIGHT {
                return Err(TlogError::ConditionNotMet(
                    "PreloadedTlogTileReader cannot read tiles of height not equal to 8"
                        .to_string(),
                ));
            }
            if tile.is_data() {
                return Err(TlogError::ConditionNotMet(
                    "PreloadedTlogTileReader cannot read data tiles".to_string(),
                ));
            }
            let tlog_tile = TlogTile::new(tile.level(), tile.level_index(), tile.width(), None);

            // Record the tile's contents
            let Some(contents) = self.0.get(&tlog_tile) else {
                return Err(TlogError::ConditionNotMet(format!(
                    "PreloadedTlogTileReader cannot find {}",
                    tlog_tile.path()
                )));
            };
            buf.push(contents.clone());
        }

        Ok(buf)
    }

    /// Do nothing; we only use this struct to read tiles.
    fn save_tiles(&self, _tiles: &[Tile], _data: &[Vec<u8>]) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_tiles_for_size() {
        let cases = vec![
            (1, 1, 0),
            (100, 101, 1),
            (1023, 1025, 3),
            (1024, 1030, 1),
            (1030, 2000, 1),
            (1030, 10000, 10),
            (49_516_517, 49_516_586, 3),
        ];

        for (old_size, new_size, expected_count) in cases {
            let tiles = Tile::new_tiles(10, old_size, new_size);
            let got = tiles.len();
            assert_eq!(
                got, expected_count,
                "got {got}, want {expected_count}, tiles: {tiles:?}"
            );
        }
    }

    #[test]
    fn test_tile_from_path() {
        let tests = [
            // Valid: minimum params support by library, without height
            ("tile/0/000", false, PathElem::Custom(""), true),
            // Invalid: N not in canonical form
            ("tile/0/00", false, PathElem::Custom(""), false),
            // Invalid: H = 0
            ("tile/0/0/000", true, PathElem::Custom(""), false),
            // Valid: minimum params support by library, with height
            ("tile/1/0/000", true, PathElem::Custom(""), true),
            // Valid: all parameters at max supported by library
            (
                "tile/30/63/x018/x446/x744/x073/x709/x551/615.p/1073741823",
                true,
                PathElem::Data,
                true,
            ),
            // Valid: same as above, with data path
            (
                "tile/30/data/x018/x446/x744/x073/x709/x551/615.p/1073741823",
                true,
                PathElem::Data,
                true,
            ),
            // Invalid: total path too long (also data path element mismatch)
            (
                "tile/too_long/63/x018/x446/x744/x073/x709/x551/615.p/1073741823",
                true,
                PathElem::Data,
                false,
            ),
            // Invalid: non-canonical trailing zero path elements
            ("tile/30/63/x000/615.p/1", true, PathElem::Data, false),
            // Invalid: N > u64::MAX
            (
                "tile/30/data/x018/x446/x744/x073/x709/x551/616.p/1073741823",
                true,
                PathElem::Data,
                false,
            ),
            // Invalid: W > 2**H
            (
                "tile/30/data/x018/x446/x744/x073/x709/x551/615.p/1073741824",
                true,
                PathElem::Data,
                false,
            ),
            // Invalid: H > 30
            (
                "tile/31/data/x018/x446/x744/x073/x709/x551/615.p/1073741824",
                true,
                PathElem::Data,
                false,
            ),
            // Invalid: L > 63
            (
                "tile/30/64/x018/x446/x744/x073/x709/x551/615.p/1073741824",
                true,
                PathElem::Data,
                false,
            ),
            // Valid
            (
                "tile/3/5/x013/x004/x005/x003/x006/x007/005",
                true,
                PathElem::Data,
                true,
            ),
            // Invalid: same as above, but not in canonical form
            ("tile/3/5/x13/x4/5/x3/6/07/5", true, PathElem::Data, false),
            // Invalid: mismatched data path element
            (
                "tile/3/data/x013/x004/x005/x003/x006/x007/005",
                true,
                PathElem::Entries,
                false,
            ),
        ];

        for (path, with_height, path_elem, valid) in tests {
            let result = Tile::from_path(path, with_height, path_elem);
            if valid {
                result.unwrap();
            } else {
                result.unwrap_err();
            }
        }
    }

    #[test]
    fn test_tile_path() {
        let tile_paths = vec![
            ("tile/4/0/001", Some(Tile::new(4, 0, 1, 16, None))),
            ("tile/4/0/001.p/5", Some(Tile::new(4, 0, 1, 5, None))),
            (
                "tile/3/5/x123/x456/078",
                Some(Tile::new(3, 5, 123_456_078, 8, None)),
            ),
            (
                "tile/3/5/x123/x456/078.p/2",
                Some(Tile::new(3, 5, 123_456_078, 2, None)),
            ),
            (
                "tile/1/0/x003/x057/500",
                Some(Tile::new(1, 0, 3_057_500, 2, None)),
            ),
            ("tile/3/5/123/456/078", None),
            ("tile/3/-1/123/456/078", None),
            (
                "tile/1/data/x003/x057/500",
                Some(Tile::new(1, 0, 3_057_500, 2, Some(PathElem::Data))),
            ),
        ];

        for (path, want) in tile_paths {
            let got = Tile::from_path(path, true, PathElem::Data).ok();
            assert_eq!(want, got);
            if let Some(t) = want {
                assert_eq!(t.path(true), path);
            }
        }
    }
}
