// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Client-side checks of the [c2sp.org/tlog-mirror](https://c2sp.org/tlog-mirror)
//! `add-entries` request preamble, run against a live server.
//!
//! Each case encodes a request body with this crate and sends it to a live
//! mirror, so a framing disagreement between implementations surfaces as a
//! failing assertion rather than two self-consistent test suites that never
//! exchange bytes.
//!
//! Scope is the preamble only: the `log_origin` length prefix, the `ticket`
//! length prefix, and the `upload_start`/`upload_end` range. Entry packages,
//! subtree consistency proofs, and the `mirror-info` response body need a
//! configured log and an accepted checkpoint, so they are not covered here.
//!
//! The suite is skipped unless `TLOG_MIRROR_URL` names a submission prefix.
//! `scripts/test-interop.sh` starts a server and sets it. Set
//! `TLOG_MIRROR_EXPECT_FAIL=1` for an implementation that is known not to
//! conform yet: the failures are reported rather than failing the run, and
//! the run fails if every case unexpectedly passes.

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
    header_body_with(origin, 0, 0, &[])
}

fn header_body_with(origin: &str, start: u64, end: u64, ticket: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    AddEntriesRequestHeader {
        log_origin: origin.to_owned(),
        upload_start: start,
        upload_end: end,
        ticket: ticket.to_vec(),
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

/// A truncated `ticket` must be rejected rather than treated as an unknown
/// log. The origin parses, so reaching the 404 would mean the server never
/// validated the rest of the preamble.
///
/// Only the status class is asserted: the spec does not fix a response body
/// for a malformed preamble, so implementations word these differently.
fn case_truncated_ticket_is_rejected(prefix: &str) -> Result<(), String> {
    // Claim eight ticket bytes and supply none.
    let mut body = header_body_with(UNKNOWN_ORIGIN, 0, 0, &[]);
    let ticket_size = body.len() - 2;
    body[ticket_size..].copy_from_slice(&8u16.to_be_bytes());

    let (status, response) = post_add_entries(prefix, body)?;
    if (400..500).contains(&status) && status != 404 {
        return Ok(());
    }
    Err(format!(
        "truncated ticket: expected a 4xx rejection other than 404, got {status}: {}",
        response.trim()
    ))
}

/// `upload_start` must be less than or equal to `upload_end`. As above, the
/// origin parses first, so a 404 would mean the range went unchecked.
fn case_inverted_range_is_rejected(prefix: &str) -> Result<(), String> {
    // `write_to` refuses an inverted range, so encode a valid one and swap the
    // two big-endian u64s on the wire.
    let mut body = header_body_with(UNKNOWN_ORIGIN, 5, 10, &[]);
    let end_offset = body.len() - 2 - 8;
    let start_offset = end_offset - 8;
    body[start_offset..end_offset].copy_from_slice(&10u64.to_be_bytes());
    body[end_offset..end_offset + 8].copy_from_slice(&5u64.to_be_bytes());

    let (status, response) = post_add_entries(prefix, body)?;
    if (400..500).contains(&status) && status != 404 {
        return Ok(());
    }
    Err(format!(
        "inverted range: expected a 4xx rejection other than 404, got {status}: {}",
        response.trim()
    ))
}

#[test]
fn add_entries_preamble_conformance() {
    let Some(prefix) = submission_prefix() else {
        eprintln!("TLOG_MIRROR_URL is unset; skipping add-entries preamble conformance");
        return;
    };

    let cases: &[Case] = &[
        ("unknown_origin_is_parsed", case_unknown_origin_is_parsed),
        (
            "max_length_origin_is_parsed",
            case_max_length_origin_is_parsed,
        ),
        (
            "truncated_ticket_is_rejected",
            case_truncated_ticket_is_rejected,
        ),
        (
            "inverted_range_is_rejected",
            case_inverted_range_is_rejected,
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
        // A stale expectation is worth a failure: it is how we learn that an
        // implementation shipped the fix we are waiting on.
        assert!(
            !expect_fail(),
            "all {} conformance cases passed against {prefix}, but \
             TLOG_MIRROR_EXPECT_FAIL is set; drop the marker for this implementation",
            cases.len()
        );
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
