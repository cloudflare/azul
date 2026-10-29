//! Landmark sequence management for Merkle Tree Certificates.
//!
//! This module implements the landmark sequence as specified in
//! [draft-ietf-plants-merkle-tree-certs-07, Section 6.4.1](https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs-07#section-6.4.1).
//!
use crate::{MtcError, UINT48_MAX};
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, fmt::Write};
use tlog_core::Subtree;

/// A tree size and its expiration time in POSIX seconds.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct Landmark {
    pub tree_size: u64,
    pub expiration: u64,
}

/// A sequence of landmarks used for constructing landmark certificates.
///
/// Landmarks are numbered consecutively from zero and define subtrees that
/// relying parties can use to optimize certificate validation.
///
/// # Invariants
///
/// - `landmarks.len() <= max_active_landmarks + 1`
/// - Tree sizes are strictly monotonically increasing
/// - Expirations are monotonically increasing
/// - The first entry is the expired predecessor of all remaining, active entries
#[derive(Debug, PartialEq, Clone)]
pub struct LandmarkSequence {
    /// Maximum number of active landmarks (those containing unexpired certificates).
    /// The deque may contain `max_active_landmarks + 1` total landmarks.
    pub max_active_landmarks: usize,
    /// The ID of the most recently added landmark.
    pub last_landmark: u64,
    /// Landmarks from oldest to newest.
    pub landmarks: VecDeque<Landmark>,
}

/// The location in object storage for the landmark sequence, which is also
/// the published `landmarks` resource.
pub const LANDMARKS_KEY: &str = "landmarks";

impl LandmarkSequence {
    /// Create a new landmark sequence with the given `max_active_landmarks` and an
    /// initial landmark with id 0 and tree size 0.
    #[must_use]
    pub fn create(max_active_landmarks: usize) -> Self {
        Self {
            max_active_landmarks,
            last_landmark: 0,
            landmarks: VecDeque::from([Landmark {
                tree_size: 0,
                expiration: 0,
            }]),
        }
    }
    /// Get the first index that is covered by the landmark sequence.
    ///
    /// # Panics
    ///
    /// Panics if the landmark sequence is empty, which should never happen.
    #[must_use]
    pub fn first_index(&self) -> u64 {
        self.landmarks
            .front()
            .expect("landmark sequence is empty")
            .tree_size
    }
    /// Add a landmark and discard all expired landmarks except the predecessor
    /// needed to define the oldest active landmark's subtrees.
    ///
    /// Returns `true` if a new landmark was added, or `false` if the tree size
    /// matches the most recent landmark (no change).
    ///
    /// # Errors
    ///
    /// Returns an error if tree sizes or expirations are nonmonotonic.
    pub fn add(
        &mut self,
        tree_size: u64,
        expiration: u64,
        current_time: u64,
    ) -> Result<bool, MtcError> {
        if let Some(last) = self.landmarks.back() {
            if tree_size == last.tree_size {
                return Ok(false);
            }
            if tree_size < last.tree_size {
                return Err(MtcError::Dynamic(
                    "landmark sequence must be strictly increasing".into(),
                ));
            }
            if expiration < last.expiration {
                return Err(MtcError::Dynamic(
                    "landmark expirations must be nondecreasing".into(),
                ));
            }
        }
        let active_count = self
            .landmarks
            .iter()
            .filter(|landmark| landmark.tree_size != 0 && landmark.expiration >= current_time)
            .count();
        if active_count >= self.max_active_landmarks {
            return Err(MtcError::Dynamic("too many active landmarks".into()));
        }
        let first_active = self
            .landmarks
            .iter()
            .position(|landmark| landmark.expiration >= current_time && landmark.tree_size != 0)
            .unwrap_or(self.landmarks.len());
        if first_active > 1 {
            self.landmarks.drain(..first_active - 1);
        }
        self.landmarks.push_back(Landmark {
            tree_size,
            expiration,
        });
        self.last_landmark = self
            .last_landmark
            .checked_add(1)
            .ok_or_else(|| MtcError::Dynamic("landmark number overflow".into()))?;
        Ok(true)
    }

    /// Return the landmark ID and subtree covering `leaf_index`, or `None` if
    /// the `leaf_index` is not covered by a landmark range.
    ///
    /// # Panics
    ///
    /// Will panic if landmarks are not sorted or are not unique.
    #[must_use]
    pub fn subtree_for_index(&self, leaf_index: u64) -> Option<(u64, Subtree)> {
        // Find the index of the first landmark greater than the leaf index.
        let hi_index = self
            .landmarks
            .partition_point(|landmark| landmark.tree_size <= leaf_index);

        // Get the lower index, if it exists.
        let lo_index = hi_index.checked_sub(1)?;

        // Return the ID of the higher landmark.
        let landmark_id = u64::try_from(hi_index).ok()?
            + (self.last_landmark + 1 - u64::try_from(self.landmarks.len()).ok()?);

        // Get lo and hi landmarks, if they exist.
        let lo = self.landmarks.get(lo_index)?.tree_size;
        let hi = self.landmarks.get(hi_index)?.tree_size;

        // Find which landmark subtree within `[lo, hi)` contains the leaf.
        let (left, right) = Subtree::split_interval(lo, hi).unwrap();
        if left.contains(leaf_index) {
            Some((landmark_id, left))
        } else {
            right.contains(leaf_index).then_some((landmark_id, right))
        }
    }

    /// Serialize the landmark sequence to the wire format.
    ///
    /// The format is defined in
    /// [draft-ietf-plants-merkle-tree-certs-07, Section 6.4.1](https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs-07#section-6.4.1):
    ///
    /// ```text
    /// <latest_landmark>
    /// <tree_size_N> <expiration_N>
    /// <tree_size_N-1> <expiration_N-1>
    /// ...
    /// <tree_size_0> <expiration_0>
    /// ```
    ///
    /// # Errors
    ///
    /// Will return an error if writing to the buffer fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MtcError> {
        if self.last_landmark > UINT48_MAX
            || self
                .landmarks
                .iter()
                .any(|landmark| landmark.tree_size > UINT48_MAX)
        {
            return Err(MtcError::Dynamic(
                "landmark numbers and tree sizes must fit uint48".into(),
            ));
        }
        let mut buffer = format!("{}\n", self.last_landmark);
        for landmark in self.landmarks.iter().rev() {
            writeln!(buffer, "{} {}", landmark.tree_size, landmark.expiration)?;
        }
        Ok(buffer.into_bytes())
    }

    /// Deserialize a landmark sequence from the wire format.
    ///
    /// Expired entries older than the required predecessor are discarded. This
    /// permits a previously valid publication to be decoded after time advances.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file is malformed or too large (`> 10_000` bytes)
    /// - Validation constraints are violated
    /// - Tree sizes or expirations are nonmonotonic
    /// - The active landmark limit is exceeded
    /// - No expired predecessor is present
    pub fn from_bytes(
        data: &[u8],
        max_active_landmarks: usize,
        current_time: u64,
    ) -> Result<Self, MtcError> {
        Self::from_bytes_with_latest_tree_size(data, max_active_landmarks, current_time, None)
    }

    /// Deserialize and optionally validate tree sizes against the latest checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the publication is malformed or a landmark exceeds
    /// `latest_tree_size` when provided.
    pub fn from_bytes_with_latest_tree_size(
        data: &[u8],
        max_active_landmarks: usize,
        current_time: u64,
        latest_tree_size: Option<u64>,
    ) -> Result<Self, MtcError> {
        fn parse_decimal(value: &str, field: &str) -> Result<u64, MtcError> {
            if value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
                || (value.len() > 1 && value.starts_with('0'))
            {
                return Err(MtcError::Dynamic(format!(
                    "{field} must use canonical decimal"
                )));
            }
            Ok(value.parse::<u64>()?)
        }

        fn parse_uint48(value: &str, field: &str) -> Result<u64, MtcError> {
            let value = parse_decimal(value, field)?;
            if value > UINT48_MAX {
                return Err(MtcError::Dynamic(format!("{field} exceeds uint48")));
            }
            Ok(value)
        }

        // Set some upper limit on what we're willing to process.
        if data.len() > 10_000 {
            return Err(MtcError::Dynamic("too much data".into()));
        }
        if !data.ends_with(b"\n") {
            return Err(MtcError::Dynamic("missing final newline".into()));
        }
        let text = std::str::from_utf8(data)?;
        let mut iter = text[..text.len() - 1].split('\n');
        let header = iter
            .next()
            .ok_or(MtcError::Dynamic("missing first line".into()))?;
        let last_landmark = parse_uint48(header, "latest_landmark")?;
        let line_count = iter.clone().count();
        let line_count_u64 = u64::try_from(line_count)
            .map_err(|_| MtcError::Dynamic("too many landmark lines".into()))?;
        if line_count == 0 || line_count_u64 > last_landmark.saturating_add(1) {
            return Err(MtcError::Dynamic(
                "incorrect number of landmark lines".into(),
            ));
        }
        let mut landmarks: VecDeque<Landmark> = VecDeque::with_capacity(line_count);
        for (i, line) in iter.enumerate() {
            let (tree_size, expiration) = line
                .split_once(' ')
                .ok_or(MtcError::Dynamic("malformed landmark line".into()))?;
            let landmark = Landmark {
                tree_size: parse_uint48(tree_size, "tree size")?,
                expiration: parse_decimal(expiration, "expiration")?,
            };
            if latest_tree_size.is_some_and(|latest| landmark.tree_size > latest) {
                return Err(MtcError::Dynamic(
                    "landmark tree size exceeds latest tree size".into(),
                ));
            }
            if i > 0 {
                let newer = landmarks
                    .front()
                    .ok_or_else(|| MtcError::Dynamic("missing newer landmark".into()))?;
                if landmark.tree_size >= newer.tree_size {
                    return Err(MtcError::Dynamic(
                        "landmark tree sizes must be decreasing".into(),
                    ));
                }
                if landmark.expiration > newer.expiration {
                    return Err(MtcError::Dynamic(
                        "landmark expirations must be nonincreasing".into(),
                    ));
                }
            }
            landmarks.push_front(landmark);
        }
        if line_count_u64 == last_landmark.saturating_add(1)
            && landmarks.front()
                != Some(&Landmark {
                    tree_size: 0,
                    expiration: 0,
                })
        {
            return Err(MtcError::Dynamic(
                "landmark zero must have tree size and expiration zero".into(),
            ));
        }
        let first_active = landmarks
            .iter()
            .position(|landmark| landmark.tree_size != 0 && landmark.expiration >= current_time)
            .unwrap_or(landmarks.len());
        if first_active == 0 {
            return Err(MtcError::Dynamic(
                "publication is missing an expired predecessor".into(),
            ));
        }
        if landmarks.len() - first_active > max_active_landmarks {
            return Err(MtcError::Dynamic("too many active landmarks".into()));
        }
        if first_active > 1 {
            landmarks.drain(..first_active - 1);
        }
        Ok(Self {
            max_active_landmarks,
            last_landmark,
            landmarks,
        })
    }

    /// Iterate over the sequence of subtrees determined by the landmark sequence.
    #[must_use]
    pub fn subtrees(&self) -> LandmarkSubtreesIterator<'_> {
        LandmarkSubtreesIterator {
            index: 1,
            landmarks: &self.landmarks,
            next_subtree: None,
        }
    }
}

/// An iterator over the subtrees determined by the landmark sequence.
pub struct LandmarkSubtreesIterator<'a> {
    index: usize,
    landmarks: &'a VecDeque<Landmark>,
    next_subtree: Option<Subtree>,
}

impl Iterator for LandmarkSubtreesIterator<'_> {
    type Item = Subtree;

    fn next(&mut self) -> Option<Subtree> {
        if self.landmarks.len() < 2 {
            return None;
        }

        if let Some(subtree) = self.next_subtree.take() {
            self.next_subtree = None;
            return Some(subtree);
        }

        if self.index == self.landmarks.len() {
            return None;
        }

        let (subtree, next_subtree) = Subtree::split_interval(
            self.landmarks[self.index - 1].tree_size,
            self.landmarks[self.index].tree_size,
        )
        .unwrap();
        self.next_subtree = Some(next_subtree);

        self.index += 1;
        Some(subtree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_and_subtrees() {
        let mut seq = LandmarkSequence::create(10);
        assert_eq!(seq.first_index(), 0);
        assert!(seq.subtree_for_index(0).is_none());
        for i in 1..=5 {
            seq.add(i * 10, 100 + i, 50).unwrap();
        }
        assert_eq!(
            seq.subtree_for_index(0),
            Some((1, Subtree::new(0, 8).unwrap()))
        );
        assert!(seq.subtree_for_index(50).is_none());
        assert_eq!(
            seq.subtree_for_index(31),
            Some((4, Subtree::new(30, 32).unwrap()))
        );
        assert_eq!(
            seq.subtree_for_index(12),
            Some((2, Subtree::new(8, 16).unwrap()))
        );
        assert_eq!(
            seq.subtree_for_index(33),
            Some((4, Subtree::new(32, 40).unwrap()))
        );

        let old_seq = seq.clone();
        seq.add(50, 999, 50).unwrap();
        assert_eq!(seq, old_seq);
        assert!(seq.add(49, 106, 50).is_err());
        assert!(seq.add(60, 104, 50).is_err());

        let got = seq.subtrees().collect::<Vec<_>>();
        let want = vec![
            Subtree::new(0, 8).unwrap(),
            Subtree::new(8, 10).unwrap(),
            Subtree::new(8, 16).unwrap(),
            Subtree::new(16, 20).unwrap(),
            Subtree::new(20, 24).unwrap(),
            Subtree::new(24, 30).unwrap(),
            Subtree::new(30, 32).unwrap(),
            Subtree::new(32, 40).unwrap(),
            Subtree::new(40, 48).unwrap(),
            Subtree::new(48, 50).unwrap(),
        ];
        assert_eq!(got, want);

        let mut single_entry = LandmarkSequence::create(1);
        single_entry.add(1, 10, 1).unwrap();
        assert_eq!(
            single_entry.subtrees().collect::<Vec<_>>(),
            vec![Subtree::new(0, 1).unwrap(), Subtree::new(1, 1).unwrap()]
        );
    }

    #[test]
    fn allocation_removes_expired_landmarks() {
        let mut seq = LandmarkSequence::create(3);
        seq.add(10, 100, 50).unwrap();
        seq.add(20, 110, 50).unwrap();
        seq.add(30, 120, 111).unwrap();
        assert_eq!(
            seq.landmarks,
            VecDeque::from([
                Landmark {
                    tree_size: 20,
                    expiration: 110
                },
                Landmark {
                    tree_size: 30,
                    expiration: 120
                }
            ])
        );
    }

    #[test]
    fn publication_round_trip() {
        let mut seq = LandmarkSequence::create(2);
        seq.add(5, 100, 50).unwrap();
        seq.add(10, 110, 50).unwrap();
        assert_eq!(seq.to_bytes().unwrap(), b"2\n10 110\n5 100\n0 0\n");
        assert_eq!(
            LandmarkSequence::from_bytes(&seq.to_bytes().unwrap(), 2, 50).unwrap(),
            seq
        );
        assert!(
            LandmarkSequence::from_bytes_with_latest_tree_size(
                &seq.to_bytes().unwrap(),
                2,
                50,
                Some(9)
            )
            .is_err()
        );
    }

    #[test]
    fn strict_publication_parser() {
        let valid = b"2\n10 110\n5 100\n0 0\n";
        assert!(LandmarkSequence::from_bytes(valid, 2, 50).is_ok());
        assert!(LandmarkSequence::from_bytes(b"0\n0 0\n", 0, 50).is_ok());
        assert!(LandmarkSequence::from_bytes(b"0\n1 1\n0 0\n", 1, 50).is_err());
        assert!(LandmarkSequence::from_bytes(b"1\n1 18446744073709551615\n0 0\n", 1, 50).is_ok());

        for invalid in [
            b"2\n10 110\n5 100\n0 0".as_slice(),
            b"02\n10 110\n5 100\n0 0\n",
            b"2\n010 110\n5 100\n0 0\n",
            b"2\n10 0110\n5 100\n0 0\n",
            b"2\n10  110\n5 100\n0 0\n",
            b"2\n10 110\n5 100\n0 0\n\n",
            b"2\n10\t110\n5 100\n0 0\n",
            b"2\r\n10 110\r\n5 100\r\n0 0\r\n",
            b"281474976710656\n0 0\n",
            b"0\n281474976710656 0\n",
            b"2\n10 110\n10 100\n0 0\n",
            b"2\n10 100\n5 110\n0 0\n",
            b"1\n10 110\n5 100\n0 0\n",
            b"2\n10 110\n5 100\n1 0\n",
        ] {
            assert!(
                LandmarkSequence::from_bytes(invalid, 2, 50).is_err(),
                "accepted {:?}",
                String::from_utf8_lossy(invalid)
            );
        }
    }

    #[test]
    fn rejects_activity_errors() {
        let stale = LandmarkSequence::from_bytes(b"2\n10 49\n5 40\n0 0\n", 2, 50).unwrap();
        assert_eq!(stale.landmarks.len(), 1);
        assert_eq!(stale.first_index(), 10);
        assert!(LandmarkSequence::from_bytes(b"2\n10 100\n5 90\n0 0\n", 1, 50).is_err());
        assert!(LandmarkSequence::from_bytes(b"2\n10 100\n5 90\n", 2, 50).is_err());

        let mut full = LandmarkSequence::create(1);
        full.add(1, 100, 50).unwrap();
        assert!(full.add(2, 110, 50).is_err());
    }
}
