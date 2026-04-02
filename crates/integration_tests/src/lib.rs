// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Integration test helpers for the static CT API and MTC API workers.
//!
//! These tests run against a live `wrangler dev` instance.
//! Set `BASE_URL` to point at the server; defaults to `http://localhost:8787`.
//!
//! CT tests: set `LOG_NAME` to choose the log shard (default: `dev2026h1a`).
//! MTC tests: set `MTC_LOG_NAME` to choose the log shard (default: `dev2`).

pub mod assertions;
pub mod client;
pub mod fixtures;
