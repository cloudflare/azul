use anyhow::{anyhow, bail};
use std::{collections::VecDeque, fmt::Write};
use tlog_tiles::Subtree;

#[derive(Debug, PartialEq, Clone)]
pub struct LandmarkSequence {
    max_landmarks: usize,
    last_landmark: usize,
    landmarks: VecDeque<u64>,
}

/// The location in object storage for the landmark bundle.
pub static LANDMARK_KEY: &str = "landmark";

impl LandmarkSequence {
    /// Create a new landmark sequence with the given `max_landmarks` and an
    /// initial landmark with id 0 and tree size 0.
    pub fn create(max_landmarks: usize) -> Self {
        Self {
            max_landmarks,
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
    /// Add a new landmark with the given tree size, removing a landmark if the
    /// maximum size would be exceeded. Returns true if the new landmark is
    /// added, or false otherwise.
    ///
    /// # Errors
    ///
    /// Will return an error if the tree size is smaller than the last landmark
    /// tree size.
    pub fn add(&mut self, tree_size: u64) -> Result<bool, anyhow::Error> {
        if let Some(last) = self.landmarks.back() {
            if tree_size == *last {
                // The last landmark is unchanged.
                return Ok(false);
            }
            if tree_size < *last {
                bail!("landmark sequence must be strictly increasing");
            }
        }
        // Keep `max_landmarks + 1` tree sizes, since we want `max_landmarks`
        // landmark intervals.
        if self.landmarks.len() == self.max_landmarks + 1 {
            self.landmarks.pop_front();
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

    /// Serialize according to
    /// <https://www.ietf.org/archive/id/draft-davidben-tls-merkle-tree-certs-06.html#section-6.3.1>.
    ///
    /// # Errors
    ///
    /// Will return an error if writing to the buffer fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        let mut buffer = format!("{} {}\n", self.last_landmark, self.landmarks.len() - 1);
        for landmark in self.landmarks.iter().rev() {
            writeln!(buffer, "{landmark}")?;
        }
        Ok(buffer.into_bytes())
    }

    /// Deserialize according to
    /// <https://www.ietf.org/archive/id/draft-davidben-tls-merkle-tree-certs-06.html#section-6.3.1>.
    ///
    /// # Errors
    ///
    /// Will return an error if the landmark sequence is invalid or if
    /// `data.len() > 10_000`.
    pub fn from_bytes(data: &[u8], max_landmarks: usize) -> Result<Self, anyhow::Error> {
        // Note: `lines()` will return the same thing whether or not there's a
        // newline after the last line, and whether or not there are carriage
        // returns preceding each newline.

        // Set some upper limit on what we're willing to process.
        if data.len() > 10_000 {
            bail!("too much data");
        }
        let mut iter = std::str::from_utf8(data)?.lines();
        let first = iter
            .next()
            .ok_or(anyhow!("missing first line"))?
            .split_once(' ')
            .ok_or(anyhow!("malformed first line"))?;
        let last_landmark = first.0.parse::<usize>()?;
        let num_active_landmarks = first.1.parse::<usize>()?;

        if num_active_landmarks > max_landmarks {
            bail!("condition not met: num_active_landmarks ≤ max_landmarks");
        }
        if num_active_landmarks > last_landmark {
            bail!("condition not met: num_active_landmarks ≤ last_landmark");
        }

        let mut landmarks = VecDeque::with_capacity(num_active_landmarks + 1);
        for i in 0..=num_active_landmarks {
            let landmark = iter
                .next()
                .ok_or(anyhow!("malformed landmark line"))?
                .parse::<u64>()?;
            if i > 0 && landmark >= landmarks[0] {
                bail!("landmarks in non-decreasing order");
            }
            landmarks.push_front(landmark);
        }
        if iter.next().is_some() {
            bail!("trailing data");
        }
        Ok(Self {
            max_landmarks,
            last_landmark,
            landmarks,
        })
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
}
