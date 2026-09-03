// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

// Build script to include per-environment configuration and trusted roots.

use bootstrap_mtc_api::ID_RDNA_TRUSTANCHOR_ID;
use config::AppConfig;
use der::asn1::Utf8StringRef;
use der::{Any, Tag};
use url::Url;
use x509_cert::{
    attr::AttributeTypeAndValue,
    name::{RdnSequence, RelativeDistinguishedName},
};

fn main() {
    let loaded = worker_build_config::load::<AppConfig>(include_str!("config.schema.json"));
    for (name, params) in &loaded.config.logs {
        // Make sure we can create the RDN sequence for the issuer log ID.
        let _ = RdnSequence::from(vec![
            RelativeDistinguishedName::try_from(vec![AttributeTypeAndValue {
                oid: ID_RDNA_TRUSTANCHOR_ID,
                value: Any::new(
                    Tag::Utf8String,
                    Utf8StringRef::new(&params.log_id).unwrap().as_bytes(),
                )
                .unwrap(),
            }])
            .unwrap(),
        ]);

        // Valid location hints: https://developers.cloudflare.com/durable-objects/reference/data-location/#supported-locations-1
        if let Some(location) = &params.location_hint {
            assert!(
                [
                    "wnam", "enam", "sam", "weur", "eeur", "apac", "oc", "afr", "me",
                ]
                .contains(&location.as_str()),
                "{name} invalid location hint: {location}"
            );
        }

        check_url(&params.submission_url);
        if !params.monitoring_url.is_empty() {
            check_url(&params.monitoring_url);
        }
    }

    loaded.stage();
}

// Validate the URL prefix according to https://datatracker.ietf.org/doc/html/rfc6962#section-4.
// "The <log server> prefix can include a path as well as a server name and a port."
fn check_url(s: &str) {
    let u = Url::parse(s).unwrap();
    assert!(["http", "https"].contains(&u.scheme()), "invalid scheme");
    assert!(u.domain().is_some(), "invalid domain");
    assert_eq!(
        u.as_str(),
        &format!("{}{}", u.origin().ascii_serialization(), u.path()),
        "invalid URL components"
    );
}
