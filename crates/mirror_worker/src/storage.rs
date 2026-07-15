// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Object storage for the mirrored copy of each origin log.
//!
//! A single R2 bucket (bound as [`PUBLIC_BUCKET_BINDING`]) backs every
//! origin the mirror serves. Objects for a given origin are stored under
//! a distinct `<origin hash>/` key prefix, where `origin hash` is the
//! lowercase hex SHA-256 of the log's origin, the same identifier the
//! [c2sp.org/tlog-mirror][spec] monitoring interface uses in its URL
//! layout (`<monitoring prefix>/<origin hash>/...`, per [C2SP/C2SP#277]).
//! Keeping the storage prefix identical to the served path means the read
//! interface can proxy R2 keys to URLs without
//! translation.
//!
//! [`OriginBucket`] is a thin [`ObjectBackend`] adapter that prepends the
//! prefix to every key, so the commit path can use bare
//! [tlog-tiles][tiles] paths (`checkpoint`, `tile/...`, `tile/entries/...`)
//! exactly as [`generic_log_worker`] and [`tlog_tiles`] produce them.
//!
//! [spec]: https://c2sp.org/tlog-mirror
//! [tiles]: https://c2sp.org/tlog-tiles
//! [C2SP/C2SP#277]: https://github.com/C2SP/C2SP/pull/277

use generic_log_worker::{ObjectBackend, ObjectBucket, log_ops::UploadOptions};
use sha2::{Digest as _, Sha256};
#[allow(clippy::wildcard_imports)]
use worker::*;

/// `wrangler.jsonc` binding name for the mirror's public R2 bucket.
pub(crate) const PUBLIC_BUCKET_BINDING: &str = "PUBLIC_BUCKET";

/// Compute a log's *origin hash*: the lowercase hex-encoded SHA-256 of
/// the origin string, per [c2sp.org/tlog-mirror][spec]. Used both as the
/// R2 key prefix and (by the read interface) as the monitoring URL path
/// component.
///
/// [spec]: https://c2sp.org/tlog-mirror
#[must_use]
pub(crate) fn origin_hash(origin: &str) -> String {
    hex::encode(Sha256::digest(origin.as_bytes()))
}

/// An [`ObjectBackend`] that stores every object under a single origin's
/// `<origin hash>/` key prefix in the shared public bucket.
///
/// Constructed per request via [`load_origin_bucket`]. Callers pass bare
/// tlog-tiles paths; the prefix is applied transparently.
pub(crate) struct OriginBucket {
    inner: ObjectBucket,
    prefix: String,
}

impl OriginBucket {
    /// Prepend the origin prefix to a bare tlog-tiles key.
    fn prefixed(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }
}

impl ObjectBackend for OriginBucket {
    async fn upload<S: AsRef<str>, D: Into<Vec<u8>>>(
        &self,
        key: S,
        data: D,
        opts: &UploadOptions,
    ) -> Result<()> {
        self.inner
            .upload(self.prefixed(key.as_ref()), data, opts)
            .await
    }

    async fn fetch<S: AsRef<str>>(&self, key: S) -> Result<Option<Vec<u8>>> {
        self.inner.fetch(self.prefixed(key.as_ref())).await
    }
}

/// Build an [`OriginBucket`] for `origin`, backed by the shared public R2
/// bucket bound as [`PUBLIC_BUCKET_BINDING`].
///
/// # Errors
///
/// Returns an error if the `PUBLIC_BUCKET` binding is missing or not an
/// R2 bucket.
pub(crate) fn load_origin_bucket(env: &Env, origin: &str) -> Result<OriginBucket> {
    let bucket = env.bucket(PUBLIC_BUCKET_BINDING)?;
    Ok(OriginBucket {
        inner: ObjectBucket::new(bucket),
        prefix: format!("{}/", origin_hash(origin)),
    })
}

#[cfg(test)]
mod tests {
    use super::origin_hash;

    /// Pin the origin-hash construction against a known SHA-256 vector so
    /// the storage prefix (and, later, the monitoring URL path) can't
    /// drift. `echo -n "example.com/log1" | sha256sum`.
    #[test]
    fn origin_hash_matches_known_vector() {
        assert_eq!(
            origin_hash("example.com/log1"),
            "82df480cc8e80fed3584d9ac8520c582266fcefbb4257d4c758a0efa6bad9c95"
        );
    }
}
