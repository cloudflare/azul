// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Client-side conformance suite for [c2sp.org/tlog-mirror](https://c2sp.org/tlog-mirror)
//! server implementations.
//!
//! Each case encodes a request body with this crate and sends it to a live
//! mirror, so a framing disagreement between implementations surfaces as a
//! failing assertion rather than two self-consistent test suites that never
//! exchange bytes.
//!
//! The suite is skipped unless `TLOG_MIRROR_URL` names a submission prefix.
//! `scripts/test-interop.sh` starts a server and sets it. Set
//! `TLOG_MIRROR_EXPECT_FAIL=1` for an implementation that is known not to
//! conform yet: the failures are reported but do not fail the run.

use std::time::Duration;

use tlog_mirror::AddEntriesRequestHeader;

/// A log origin the server is not configured to serve. The spec requires a
/// 404 for an unknown origin, which is the narrowest response that still
/// proves the server parsed `log_origin` out of the body.
const UNKNOWN_ORIGIN: &str = "conformance.example/unknown-log";

struct Outcome {
    case: &'static str,
    detail: String,
}

/// A conformance case: a name and a check run against a submission prefix.
type Case = (&'static str, fn(&str) -> Result<(), String>);

fn submission_prefix() -> Option<String> {
    let value = std::env::var("TLOG_MIRROR_URL").ok()?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        return None;
    }
    Some(value.trim_end_matches('/').to_owned())
}

fn expect_fail() -> bool {
    std::env::var("TLOG_MIRROR_EXPECT_FAIL").is_ok_and(|value| value == "1")
}

fn post_add_entries(prefix: &str, body: Vec<u8>) -> Result<(u16, String), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| format!("build client: {error}"))?;
    let mut request = client
        .post(format!("{prefix}/add-entries"))
        .header("Content-Type", "application/octet-stream");
    // Some servers route by the configured submission prefix host rather than
    // the dial address, and would otherwise answer from the default mux.
    if let Ok(host) = std::env::var("TLOG_MIRROR_HOST")
        && !host.is_empty()
    {
        request = request.header("Host", host);
    }
    let response = request
        .body(body)
        .send()
        .map_err(|error| format!("request failed: {error}"))?;
    let status = response.status().as_u16();
    Ok((status, response.text().unwrap_or_default()))
}

fn header_body(origin: &str) -> Vec<u8> {
    let mut body = Vec::new();
    AddEntriesRequestHeader {
        log_origin: origin.to_owned(),
        upload_start: 0,
        upload_end: 0,
        ticket: Vec::new(),
    }
    .write_to(&mut body)
    .expect("encode add-entries header");
    body
}

/// A server that reached origin lookup must say so. A bare "404 page not
/// found" means the request never reached the `add-entries` handler, which
/// would let a framing mismatch pass unnoticed.
fn check_origin_was_parsed(status: u16, body: &str, label: &str) -> Result<(), String> {
    let body = body.trim();
    if body.eq_ignore_ascii_case("404 page not found") {
        return Err(format!(
            "{label}: request did not reach the add-entries handler (set TLOG_MIRROR_HOST?)"
        ));
    }
    if status == 404 {
        return Ok(());
    }
    Err(format!(
        "{label}: expected 404 for an unknown log origin, got {status}: {body}"
    ))
}

/// The server must parse `log_origin` from a body this crate encoded. With a
/// mismatched length prefix the server reads a different number of bytes and
/// rejects the framing instead of reporting an unknown log.
fn case_unknown_origin_is_parsed(prefix: &str) -> Result<(), String> {
    let (status, body) = post_add_entries(prefix, header_body(UNKNOWN_ORIGIN))?;
    check_origin_was_parsed(status, &body, "unknown origin")
}

/// The same check at the maximum origin length the uint8 prefix can encode,
/// which is where a uint16 reader misreads the length most visibly.
fn case_max_length_origin_is_parsed(prefix: &str) -> Result<(), String> {
    let origin = format!("conformance.example/{}", "a".repeat(255 - 20));
    assert_eq!(origin.len(), 255, "origin must fill the uint8 prefix");
    let (status, body) = post_add_entries(prefix, header_body(&origin))?;
    check_origin_was_parsed(status, &body, "255-byte origin")
}

#[test]
fn mirror_server_conformance() {
    let Some(prefix) = submission_prefix() else {
        eprintln!("TLOG_MIRROR_URL is unset; skipping mirror conformance suite");
        return;
    };

    let cases: &[Case] = &[
        ("unknown_origin_is_parsed", case_unknown_origin_is_parsed),
        (
            "max_length_origin_is_parsed",
            case_max_length_origin_is_parsed,
        ),
    ];

    let mut failures = Vec::new();
    for (case, run) in cases {
        match run(&prefix) {
            Ok(()) => println!("ok   {case}"),
            Err(detail) => {
                println!("FAIL {case}: {detail}");
                failures.push(Outcome { case, detail });
            }
        }
    }

    if failures.is_empty() {
        return;
    }
    let summary = failures
        .iter()
        .map(|failure| format!("  {}: {}", failure.case, failure.detail))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        expect_fail(),
        "{} of {} conformance cases failed against {prefix}:\n{summary}",
        failures.len(),
        cases.len()
    );
    eprintln!(
        "{} of {} conformance cases failed against {prefix} (expected failure):\n{summary}",
        failures.len(),
        cases.len()
    );
}
