//! Landmark sequence management for Merkle Tree Certificates.
//!
//! This module implements the landmark sequence as specified in
//! [draft-ietf-plants-merkle-tree-certs-02, Section 6.3.1](https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-02.html#section-6.3.1).
//!
//! # Key Concepts
//!
//! - **Landmarks**: Agreed-upon tree sizes used to optimize certificate construction
//! - **Active Landmarks**: The most recent `max_active_landmarks` landmarks
//! - **Landmark Subtrees**: Subtrees covering the interval between consecutive landmarks
//!
//! # Important: Landmark Storage Invariant
//!
//! The `landmarks` deque stores `num_active_landmarks + 1` tree sizes, which equals
//! `max_active_landmarks + 1` at steady state. This is **correct by design** per the spec.
//!
//! ## Why One Extra Landmark?
//!
//! Landmark subtrees are defined by intervals `[prev_tree_size, tree_size)` between
//! consecutive landmarks. To compute subtrees for ALL active landmarks, we need the
//! tree size of the landmark immediately before the oldest active landmark (which is
//! expired but still needed for computation).
//!
//! ## Example
//!
//! With `max_active_landmarks = 169`:
//! - File contains `num_active_landmarks = 169` (at most)
//! - File stores `169 + 1 = 170` tree sizes
//! - Deque contains 170 landmarks
//! - The 169 most recent are "active" (contain unexpired certs)
//! - The oldest (expired) landmark is kept to compute subtrees
//!
//! This is validated by: `num_active_landmarks <= max_active_landmarks` (not `<`).

use crate::MtcError;
use std::{collections::VecDeque, fmt::Write};
use tlog_tiles::Subtree;

/// A sequence of landmarks used for constructing landmark certificates.
///
/// Landmarks are numbered consecutively from zero and define subtrees that
/// relying parties can use to optimize certificate validation.
///
/// # Invariants
///
/// - `landmarks.len() <= max_active_landmarks + 1` (one extra for subtree computation)
/// - Tree sizes are strictly monotonically increasing
/// - At steady state: `landmarks.len() == max_active_landmarks + 1`
#[derive(Debug, PartialEq, Clone)]
pub struct LandmarkSequence {
    /// Maximum number of active landmarks (those containing unexpired certificates).
    /// The deque may contain `max_active_landmarks + 1` total landmarks.
    pub max_active_landmarks: usize,
    /// The ID of the most recently added landmark.
    pub last_landmark: usize,
    /// Tree sizes for the landmarks, from oldest to newest.
    /// Contains up to `max_active_landmarks + 1` entries at steady state.
    pub landmarks: VecDeque<u64>,
}

/// The location in object storage for the landmark sequence.
pub const LANDMARK_KEY: &str = "landmark";

/// The location in object storage for the landmark checkpoint.
pub const LANDMARK_CHECKPOINT_KEY: &str = "landmark-checkpoint";

/// The location in object storage for the landmark bundle. Its serialized form is JSON.
pub const LANDMARK_BUNDLE_KEY: &str = "landmark-bundle";

impl LandmarkSequence {
    /// Create a new landmark sequence with the given `max_active_landmarks` and an
    /// initial landmark with id 0 and tree size 0.
    pub fn create(max_active_landmarks: usize) -> Self {
        Self {
            max_active_landmarks,
            last_landmark: 0,
            landmarks: VecDeque::from(vec![0]),
        }
    }
    /// Get the first index that is covered by the landmark sequence.
    ///
    /// # Panics
    ///
    /// Panics if the landmark sequence is empty, which should never happen.
    pub fn first_index(&self) -> u64 {
        *self.landmarks.front().expect("landmark sequence is empty")
    }
    /// Add a new landmark with the given tree size, removing the oldest landmark
    /// if necessary to maintain the invariant that `landmarks.len() <= max_active_landmarks + 1`.
    ///
    /// Returns `true` if a new landmark was added, or `false` if the tree size
    /// matches the most recent landmark (no change).
    ///
    /// # Important Note
    ///
    /// The check `if self.landmarks.len() > self.max_active_landmarks` happens **before**
    /// the push. This is intentional and correct per the spec! It allows the deque
    /// to reach `max_active_landmarks + 1` elements, which is needed to compute subtrees
    /// for all active landmarks.
    ///
    /// At steady state:
    /// - Before push: `len = max_active_landmarks + 1`
    /// - Check: `(max_active_landmarks + 1) > max_active_landmarks`? → `true` → drain 1
    /// - After drain: `len = max_active_landmarks`
    /// - After push: `len = max_active_landmarks + 1` ✓
    ///
    /// # Errors
    ///
    /// Returns an error if the tree size is not strictly greater than the last
    /// landmark tree size (monotonicity violation).
    pub fn add(&mut self, tree_size: u64) -> Result<bool, MtcError> {
        if let Some(last) = self.landmarks.back() {
            if tree_size == *last {
                // The last landmark is unchanged.
                return Ok(false);
            }
            if tree_size < *last {
                return Err(MtcError::Dynamic(
                    "landmark sequence must be strictly increasing".into(),
                ));
            }
        }
        // CRITICAL: Check happens BEFORE push to allow deque to reach max_active_landmarks + 1 elements.
        // This is correct per spec - we need the extra (oldest) landmark to compute subtrees.
        // See module-level documentation for detailed explanation.
        if self.landmarks.len() > self.max_active_landmarks {
            self.landmarks
                .drain(..self.landmarks.len() - self.max_active_landmarks);
        }
        self.landmarks.push_back(tree_size);
        self.last_landmark += 1;
        Ok(true)
    }

    /// Return the landmark ID and subtree covering `leaf_index`, or `None` if
    /// the `leaf_index` is not covered by a landmark range.
    ///
    /// # Panics
    ///
    /// Will panic if landmarks are not sorted or are not unique.
    pub fn subtree_for_index(&self, leaf_index: u64) -> Option<(usize, Subtree)> {
        // Find the index of the first landmark greater than the leaf index.
        let hi_index = self
            .landmarks
            .partition_point(|&landmark| landmark <= leaf_index);

        // Get the lower index, if it exists.
        let lo_index = hi_index.checked_sub(1)?;

        // Return the ID of the higher landmark.
        let landmark_id = hi_index + (self.last_landmark + 1 - self.landmarks.len());

        // Get lo and hi landmarks, if they exist.
        let &lo = self.landmarks.get(lo_index)?;
        let &hi = self.landmarks.get(hi_index)?;

        // Find which landmark subtree within `[lo, hi)` contains the leaf.
        let (left, right) = Subtree::split_interval(lo, hi).unwrap();
        if left.contains(leaf_index) {
            Some((landmark_id, left))
        } else {
            right.map(|tree| (landmark_id, tree))
        }
    }

    /// Serialize the landmark sequence to the wire format.
    ///
    /// The format is defined in
    /// [draft-ietf-plants-merkle-tree-certs-02, Section 6.3.1](https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-02.html#section-6.3.1):
    ///
    /// ```text
    /// <last_landmark> <num_active_landmarks>
    /// <tree_size_N>    // Most recent (last_landmark)
    /// <tree_size_N-1>
    /// ...
    /// <tree_size_0>    // Oldest
    /// ```
    ///
    /// # Important
    ///
    /// - `num_active_landmarks = landmarks.len() - 1`
    /// - File contains `num_active_landmarks + 1` tree sizes
    /// - With `max_active_landmarks = 169`, file can have `num_active_landmarks = 169`,
    ///   which means 170 total tree sizes
    ///
    /// # Errors
    ///
    /// Will return an error if writing to the buffer fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MtcError> {
        let mut buffer = format!("{} {}\n", self.last_landmark, self.landmarks.len() - 1);
        for landmark in self.landmarks.iter().rev() {
            writeln!(buffer, "{landmark}")?;
        }
        Ok(buffer.into_bytes())
    }

    /// Deserialize a landmark sequence from the wire format.
    ///
    /// Validates that:
    /// - `num_active_landmarks <= max_active_landmarks` (allows equality!)
    /// - `num_active_landmarks <= last_landmark`
    /// - Tree sizes are strictly monotonically decreasing in the file
    ///
    /// # Important: Validation Behavior
    ///
    /// The validation uses `num_active_landmarks <= max_active_landmarks`, not `<`.
    /// This means with `max_active_landmarks = 169`, a file with `num_active_landmarks = 169`
    /// is **valid** and will create a deque with 170 landmarks. This is correct
    /// per the spec!
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file is malformed or too large (`> 10_000` bytes)
    /// - Validation constraints are violated
    /// - Tree sizes are not strictly monotonically decreasing
    pub fn from_bytes(data: &[u8], max_active_landmarks: usize) -> Result<Self, MtcError> {
        // Note: `lines()` will return the same thing whether or not there's a
        // newline after the last line, and whether or not there are carriage
        // returns preceding each newline.

        // Set some upper limit on what we're willing to process.
        if data.len() > 10_000 {
            return Err(MtcError::Dynamic("too much data".into()));
        }
        let mut iter = std::str::from_utf8(data)?.lines();
        let first = iter
            .next()
            .ok_or(MtcError::Dynamic("missing first line".into()))?
            .split_once(' ')
            .ok_or(MtcError::Dynamic("malformed first line".into()))?;
        let last_landmark = first.0.parse::<usize>()?;
        let num_active_landmarks = first.1.parse::<usize>()?;

        // Note: Uses > not >= to allow num_active_landmarks == max_active_landmarks (correct per spec).
        // This means a file with max_active_landmarks=169 can have num_active_landmarks=169,
        // and will contain 170 tree sizes (169 active + 1 expired for subtree computation).
        if num_active_landmarks > max_active_landmarks {
            return Err(MtcError::Dynamic(
                "num_active_landmarks must not be greater than max_active_landmarks".into(),
            ));
        }
        if num_active_landmarks > last_landmark {
            return Err(MtcError::Dynamic(
                "num_active_landmarks must not be greater than last_landmark".into(),
            ));
        }

        let mut landmarks = VecDeque::with_capacity(num_active_landmarks + 1);
        for i in 0..=num_active_landmarks {
            let landmark = iter
                .next()
                .ok_or(MtcError::Dynamic("malformed landmark line".into()))?
                .parse::<u64>()?;
            if i > 0 && landmark >= landmarks[0] {
                return Err(MtcError::Dynamic(
                    "landmarks must be in decreasing order".into(),
                ));
            }
            landmarks.push_front(landmark);
        }
        if iter.next().is_some() {
            return Err(MtcError::Dynamic(
                "trailing data in landmark sequence".into(),
            ));
        }
        Ok(Self {
            max_active_landmarks,
            last_landmark,
            landmarks,
        })
    }

    /// Iterate over the sequence of subtrees determined by the landmark sequence.
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
    landmarks: &'a VecDeque<u64>,
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

        let subtree;
        (subtree, self.next_subtree) =
            Subtree::split_interval(self.landmarks[self.index - 1], self.landmarks[self.index])
                .unwrap();

        self.index += 1;
        Some(subtree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subtree_for_index() {
        let mut seq = LandmarkSequence::create(10);
        assert_eq!(seq.first_index(), 0);
        // Only have a single landmark so no subtrees yet.
        assert!(seq.subtree_for_index(0).is_none());
        // Check landmark sequence at partial capacity.
        for i in 1..=5 {
            seq.add(i * 10).unwrap();
        }
        assert_eq!(seq.first_index(), 0);
        // At first landmark.
        assert_eq!(
            seq.subtree_for_index(0),
            Some((1, Subtree::new(0, 8).unwrap()))
        );
        // Past last landmark.
        assert!(seq.subtree_for_index(50).is_none());
        // Valid landmark, left subtree aligned with lower landmark tree size.
        assert_eq!(
            seq.subtree_for_index(31),
            Some((4, Subtree::new(30, 32).unwrap()))
        );
        // Valid landmark, left subtree extending beyond lower landmark tree
        // size.
        assert_eq!(
            seq.subtree_for_index(12),
            Some((2, Subtree::new(8, 16).unwrap()))
        );
        // Valid landmark, right subtree.
        assert_eq!(
            seq.subtree_for_index(33),
            Some((4, Subtree::new(32, 40).unwrap()))
        );

        // New tree size matching the last landmark tree size is ignored.
        let old_seq = seq.clone();
        seq.add(50).unwrap();
        assert_eq!(seq, old_seq);
        // Error if we try to add a smaller tree size.
        assert!(seq.add(49).is_err());

        // Put landmark sequence at full capacity.
        for i in 6..=20 {
            seq.add(i * 10).unwrap();
        }
        assert_eq!(seq.first_index(), 100);
        // Before first landmark.
        assert!(seq.subtree_for_index(99).is_none());
        // Just within first landmark.
        assert_eq!(
            seq.subtree_for_index(100),
            Some((11, Subtree::new(100, 104).unwrap()))
        );
        // At last landmark.
        assert_eq!(
            seq.subtree_for_index(199),
            Some((20, Subtree::new(192, 200).unwrap()))
        );
        // Past last landmark.
        assert!(seq.subtree_for_index(200).is_none());
    }

    #[test]
    fn test_subtrees() {
        let mut seq = LandmarkSequence::create(10);
        assert!(seq.subtrees().next().is_none());

        for i in 1..=5 {
            seq.add(i * 10).unwrap();
        }
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
    }

    #[test]
    fn test_max_active_landmarks_plus_one_is_correct() {
        // This test documents and validates the CORRECT behavior per the spec:
        // The deque should contain max_active_landmarks + 1 entries at steady state.
        //
        // From draft-ietf-plants-merkle-tree-certs-02, Section 6.3.1:
        // - "The most recent max_active_landmarks landmarks are said to be active"
        // - File format stores "num_active_landmarks + 1 lines" of tree sizes
        // - Validation: "num_active_landmarks <= max_active_landmarks"
        //
        // This means with max_active_landmarks=169, the file can have num_active=169,
        // which results in 170 total tree sizes (169 + 1).

        let max_active_landmarks = 10;
        let mut seq = LandmarkSequence::create(max_active_landmarks);

        // Fill to steady state
        for i in 1..=20 {
            seq.add(i * 10).unwrap();
        }

        // At steady state, we should have max_active_landmarks + 1 entries
        assert_eq!(
            seq.landmarks.len(),
            max_active_landmarks + 1,
            "Deque should contain max_active_landmarks + 1 = {} landmarks at steady state",
            max_active_landmarks + 1
        );

        // The serialized file should have num_active = max_active_landmarks
        let bytes = seq.to_bytes().unwrap();
        let content = String::from_utf8(bytes).unwrap();
        let first_line = content.lines().next().unwrap();
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        let num_active: usize = parts[1].parse().unwrap();

        assert_eq!(
            num_active, max_active_landmarks,
            "Serialized file should have num_active_landmarks = {}",
            max_active_landmarks
        );

        // File should contain num_active + 1 lines of tree sizes
        let tree_size_lines: Vec<_> = content.lines().skip(1).collect();
        assert_eq!(
            tree_size_lines.len(),
            num_active + 1,
            "File should contain {} tree size lines",
            num_active + 1
        );
    }

    #[test]
    fn test_production_config_values() {
        // Validate the production configuration produces correct values.
        // Production: 7 days (604800 secs), 1 hour intervals (3600 secs)

        let max_cert_lifetime_secs: usize = 604_800; // 7 days
        let landmark_interval_secs: usize = 3_600; // 1 hour

        let max_active_landmarks = max_cert_lifetime_secs.div_ceil(landmark_interval_secs) + 1;

        assert_eq!(
            max_active_landmarks, 169,
            "Production max_active_landmarks should be 169"
        );

        let mut seq = LandmarkSequence::create(max_active_landmarks);

        // Simulate 200 hours of operation
        for hour in 1..=200 {
            seq.add(hour).unwrap();
        }

        // At steady state (after 169 additions), should have 170 landmarks
        assert_eq!(
            seq.landmarks.len(),
            170,
            "Production should maintain 170 landmarks (169 active + 1 expired)"
        );

        // Validate serialization
        let bytes = seq.to_bytes().unwrap();
        let content = String::from_utf8(bytes.clone()).unwrap();
        let first_line = content.lines().next().unwrap();
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        let num_active: usize = parts[1].parse().unwrap();

        assert_eq!(
            num_active, 169,
            "Production file should have num_active_landmarks = 169"
        );

        // Validate deserialization accepts this
        let loaded = LandmarkSequence::from_bytes(&bytes, max_active_landmarks)
            .expect("Should successfully load file with num_active=169");

        assert_eq!(loaded.landmarks.len(), 170);
    }

    #[test]
    fn test_subtrees_require_extra_landmark() {
        // This test demonstrates WHY we need the extra (expired) landmark:
        // to compute subtrees for the oldest active landmark.

        let max_active_landmarks = 5;
        let mut seq = LandmarkSequence::create(max_active_landmarks);

        // Add landmarks up to capacity
        for i in 1..=10 {
            seq.add(i * 10).unwrap();
        }

        // At steady state: 6 landmarks total (5 active + 1 expired)
        assert_eq!(seq.landmarks.len(), 6);

        // The landmarks are: [50, 60, 70, 80, 90, 100]
        // - Oldest (expired): 50
        // - Active: 60, 70, 80, 90, 100

        // To compute subtrees for landmark 60 (oldest active), we need:
        // - The interval [50, 60) -- requires knowing landmark 50's tree size!
        // - Without landmark 50, we couldn't compute these subtrees

        let subtrees: Vec<_> = seq.subtrees().collect();

        // Verify we got subtrees for all active landmarks
        // With 5 active landmarks, we should get 10 subtrees
        assert_eq!(
            subtrees.len(),
            10,
            "Should be able to compute subtrees with the extra landmark, got {} subtrees",
            subtrees.len()
        );

        // The oldest landmark (50) is needed to compute the first subtrees
        // starting from the interval [50, 60)
        assert_eq!(seq.first_index(), 50, "Oldest landmark should be 50");
    }

    #[test]
    fn test_validation_allows_max_active_landmarks() {
        // Verify that from_bytes accepts num_active_landmarks == max_active_landmarks
        // This is correct per spec: "num_active_landmarks <= max_active_landmarks"

        let max_active_landmarks = 169;

        // Create a sequence with max_active_landmarks + 1 entries
        let seq = LandmarkSequence {
            max_active_landmarks: max_active_landmarks,
            last_landmark: 200,
            landmarks: (32..=201).collect(), // 170 landmarks
        };

        assert_eq!(seq.landmarks.len(), 170);

        // Serialize
        let bytes = seq.to_bytes().unwrap();
        let content = String::from_utf8(bytes.clone()).unwrap();
        let first_line = content.lines().next().unwrap();
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        let num_active: usize = parts[1].parse().unwrap();

        // num_active should be 169
        assert_eq!(num_active, 169);

        // from_bytes should accept this (169 <= 169 is true)
        let loaded = LandmarkSequence::from_bytes(&bytes, max_active_landmarks)
            .expect("Should accept file with num_active == max_active_landmarks");

        assert_eq!(loaded.landmarks.len(), 170);
    }
}
