// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Sentry integration for Cloudflare Workers.
//!
//! Provides a custom [`sentry_core::Transport`] that buffers envelopes in memory
//! and flushes them synchronously via the Workers `fetch` API. Flushing is
//! intended only for catastrophic errors where latency no longer matters.
//!
//! # Usage
//!
//! ```ignore
//! // In your worker crate's lib.rs:
//! static SENTRY_TRANSPORT: OnceLock<Option<Arc<WorkerTransport>>> = OnceLock::new();
//!
//! pub fn init_sentry(env: &Env) -> Option<&'static Arc<WorkerTransport>> {
//!     SENTRY_TRANSPORT.get_or_init(|| {
//!         let dsn = env.var("SENTRY_DSN").ok()?.to_string();
//!         if dsn.is_empty() { return None; }
//!         obs::sentry::init(&dsn, env!("DEPLOY_ENV"))
//!     }).as_ref()
//! }
//!
//! // On catastrophic error:
//! sentry_core::capture_message("something broke", sentry_core::Level::Fatal);
//! if let Some(transport) = init_sentry(&env) {
//!     obs::sentry::flush(transport).await;
//! }
//! ```

use std::panic;
use std::sync::{Arc, Mutex, OnceLock};

use std::borrow::Cow;
use std::time::UNIX_EPOCH;

use sentry_core::protocol::{Event, Exception, Frame, Level, Mechanism, Stacktrace};
use sentry_core::{ClientOptions, Envelope, Transport, TransportFactory};
use sha2::{Digest, Sha256};

/// A [`Transport`] that buffers envelopes in memory for later synchronous
/// flush via Workers `fetch`. Serialization is deferred to flush time to avoid
/// wasted work when no flush occurs.
pub struct WorkerTransport {
    dsn: sentry_core::types::Dsn,
    envelopes: Mutex<Vec<Envelope>>,
    /// Cloudflare Access service-token client ID (`CF-Access-Client-ID`
    /// header). Required when the Sentry ingest endpoint is behind
    /// Cloudflare Access.
    access_client_id: Option<String>,
    /// Cloudflare Access service-token client secret
    /// (`CF-Access-Client-Secret` header).
    access_client_secret: Option<String>,
}

impl Transport for &'static WorkerTransport {
    fn send_envelope(&self, envelope: Envelope) {
        if let Ok(mut guard) = self.envelopes.lock() {
            guard.push(envelope);
        }
    }
}

struct Factory(&'static WorkerTransport);

impl TransportFactory for Factory {
    fn create_transport(&self, _opts: &ClientOptions) -> Arc<dyn Transport> {
        Arc::new(self.0)
    }
}

/// Global transport reference for the panic hook. The hook cannot go through
/// `sentry_core::capture_event` because that calls `random_uuid()` which
/// requires `getrandom` — unavailable during a WASM panic.
static PANIC_HOOK_TRANSPORT: OnceLock<WorkerTransport> = OnceLock::new();

/// Initialize sentry with a custom Workers-compatible transport.
///
/// Installs a panic hook that captures panics as Sentry exception events,
/// chaining with any previously installed hook (e.g. `console_error_panic_hook`)
/// so that console output is preserved. The hook bypasses
/// `sentry_core::capture_event` entirely because that function calls
/// `random_uuid()` -> `getrandom`, which panics in WASM during a panic hook
/// (JS interop unavailable). Instead, we construct the [`Envelope`] directly
/// and push it to the transport buffer.
///
/// Returns `None` if the DSN is empty or invalid, allowing graceful opt-out
/// when `SENTRY_DSN` is not configured.
#[must_use]
#[allow(clippy::too_many_lines)] // Panic-hook event construction is deliberately inline; see safety comments.
pub fn init(
    dsn: &str,
    environment: &str,
    access_client_id: Option<&str>,
    access_client_secret: Option<&str>,
) -> Option<&'static WorkerTransport> {
    use std::sync::Once;
    static HOOK: Once = Once::new();

    if dsn.is_empty() {
        return None;
    }
    let parsed_dsn: sentry_core::types::Dsn = dsn.parse().ok()?;
    // Store a reference for the panic hook before installing it.
    let transport = PANIC_HOOK_TRANSPORT.get_or_init(|| WorkerTransport {
        dsn: parsed_dsn.clone(),
        envelopes: Mutex::default(),
        access_client_id: access_client_id.map(String::from),
        access_client_secret: access_client_secret.map(String::from),
    });
    let client = sentry_core::Client::from(ClientOptions {
        dsn: Some(parsed_dsn),
        environment: Some(environment.to_string().into()),
        release: sentry_core::release_name!(),
        transport: Some(Arc::new(Factory(transport))),
        ..Default::default()
    });
    let hub = sentry_core::Hub::current();
    hub.bind_client(Some(Arc::new(client)));

    // Install the panic hook (at most once).
    HOOK.call_once(|| {
        let next = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            // Build a Sentry Event from the panic info. Since WASM
            // targets do not support `std::backtrace`, we extract
            // what we can from the panic location (file, line, column)
            // and encode it as a single-frame stacktrace.
            //
            // This code must not call `Event::default()` or any path
            // through `getrandom` (e.g. `Uuid::new_v4()`), because the
            // JS interop required by `getrandom`'s `wasm_js` backend
            // may not be available during a panic hook, causing a
            // double-panic that aborts the WASM module.
            //
            // `SystemTime::now()` also panics on wasm32-unknown-unknown
            // (no clock), so we use `UNIX_EPOCH` — the Sentry ingest
            // endpoint uses the `sent_at` header instead when the event
            // timestamp is epoch-zero.
            let msg = match info.payload().downcast_ref::<&'static str>() {
                Some(s) => (*s).to_string(),
                None => match info.payload().downcast_ref::<String>() {
                    Some(s) => s.clone(),
                    None => "Box<dyn Any>".to_string(),
                },
            };

            // Derive a deterministic UUID from the panic message and
            // location so that Sentry does not deduplicate distinct
            // panics (which it would if every event shared Uuid::nil).
            // SHA-256 is pure Rust, so it is safe to call from a panic
            // hook — unlike `getrandom`/`Uuid::new_v4()`.
            let event_id = {
                let mut h = Sha256::new();
                h.update(msg.as_bytes());
                if let Some(loc) = info.location() {
                    h.update(loc.file().as_bytes());
                    h.update(loc.line().to_le_bytes());
                    h.update(loc.column().to_le_bytes());
                }
                let hash = h.finalize();
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&hash[..16]);
                // Set version (4) and variant (RFC 4122) bits so the
                // value is a syntactically valid UUID.
                bytes[6] = (bytes[6] & 0x0F) | 0x40; // version 4
                bytes[8] = (bytes[8] & 0x3F) | 0x80; // variant RFC 4122
                sentry_core::types::Uuid::from_bytes(bytes)
            };

            let stacktrace = info.location().map(|loc| Stacktrace {
                frames: vec![Frame {
                    function: Some("panic".into()),
                    filename: Some(loc.file().into()),
                    lineno: Some(loc.line().into()),
                    colno: Some(loc.column().into()),
                    ..Default::default()
                }],
                ..Default::default()
            });

            // Construct the event field-by-field instead of using
            // `..Default::default()` because `Event::default()` calls
            // `random_uuid()` and `SystemTime::now()`, both of which
            // panic in WASM panic hooks. The Sentry ingest endpoint
            // uses the `sent_at` envelope header when the event
            // timestamp is epoch-zero.
            #[allow(clippy::default_trait_access)]
            let event = Event {
                event_id,
                level: Level::Fatal,
                fingerprint: Cow::Borrowed(&[]),
                platform: Cow::Borrowed("other"),
                timestamp: UNIX_EPOCH,
                exception: vec![Exception {
                    ty: "panic".into(),
                    value: Some(msg),
                    mechanism: Some(Mechanism {
                        ty: "panic".into(),
                        handled: Some(false),
                        ..Default::default()
                    }),
                    stacktrace,
                    ..Default::default()
                }]
                .into(),
                culprit: Default::default(),
                transaction: Default::default(),
                message: Default::default(),
                logentry: Default::default(),
                logger: Default::default(),
                modules: Default::default(),
                server_name: Default::default(),
                release: Default::default(),
                dist: Default::default(),
                environment: Default::default(),
                user: Default::default(),
                request: Default::default(),
                contexts: Default::default(),
                breadcrumbs: Default::default(),
                stacktrace: Default::default(),
                template: Default::default(),
                threads: Default::default(),
                tags: Default::default(),
                extra: Default::default(),
                debug_meta: Default::default(),
                sdk: Default::default(),
            };

            let mut envelope = Envelope::new();
            envelope.add_item(event);
            transport.send_envelope(envelope);
            next(info);
        }));
    });

    Some(transport)
}

/// Wrap an async future with [`futures_util::FutureExt::catch_unwind`],
/// capturing any panic as a Sentry exception event and flushing all
/// buffered envelopes before re-raising the panic.
///
/// Use this in both Durable Object `fetch` / `alarm` handlers and
/// frontend worker `main` functions so that panics are reported to
/// Sentry before the WASM isolate is torn down.
///
/// The panic hook (installed by [`init`]) captures the event; this
/// function ensures the transport is flushed before the isolate dies.
///
/// # Example
///
/// ```ignore
/// async fn fetch(&self, req: Request) -> Result<Response> {
///     catch_unwind_and_flush(get_sentry_transport(), self.0.fetch(req)).await
/// }
/// ```
pub async fn catch_unwind_and_flush<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    use futures_util::FutureExt;
    use std::panic::AssertUnwindSafe;

    if PANIC_HOOK_TRANSPORT.get().is_some() {
        match AssertUnwindSafe(future).catch_unwind().await {
            Ok(val) => val,
            Err(payload) => {
                // The panic hook already captured the event — we just
                // need to flush before re-panicking.
                flush().await;
                std::panic::resume_unwind(payload);
            }
        }
    } else {
        future.await
    }
}

/// Like [`catch_unwind_and_flush`], but also reports `Err` results to
/// Sentry before returning them.
///
/// This is the standard wrapper for Durable Object `fetch` / `alarm`
/// handlers: it catches panics, and on `Err` it captures the error as
/// a Sentry message with the given tags and flushes.
///
/// # Errors
///
/// Returns the inner future's `Err` unchanged after reporting it.
///
/// # Example
///
/// ```ignore
/// async fn fetch(&self, req: Request) -> Result<Response> {
///     catch_unwind_report_and_flush(
///         get_sentry_transport(),
///         &[("handler", "do_fetch"), ("do_type", "batcher")],
///         self.0.fetch(req),
///     ).await
/// }
/// ```
pub async fn catch_unwind_report_and_flush<F, T, E>(
    tags: &[(&str, &str)],
    future: F,
) -> Result<T, E>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let result = catch_unwind_and_flush(future).await;
    if let Err(e) = &result {
        capture_error_and_flush(e, sentry_core::Level::Fatal, tags).await;
    }
    result
}

/// Capture an error and immediately flush all buffered envelopes.
///
/// Tags are scoped to this single event via [`sentry_core::with_scope`]
/// so they do not leak into subsequent events on the same hub (which
/// would happen with `configure_scope` in long-lived isolates like DOs).
pub async fn capture_error_and_flush(
    error: &dyn std::fmt::Display,
    level: sentry_core::Level,
    tags: &[(&str, &str)],
) {
    sentry_core::with_scope(
        |scope| {
            for &(key, value) in tags {
                scope.set_tag(key, value);
            }
        },
        || {
            sentry_core::capture_message(&error.to_string(), level);
        },
    );
    flush().await;
}

/// Synchronously POST all buffered envelopes to the Sentry ingest endpoint.
///
/// Call this only on catastrophic errors -- it blocks until all envelopes are
/// sent (or fail). Errors during sending are logged to the console but not
/// propagated.
pub async fn flush() {
    let Some(transport) = PANIC_HOOK_TRANSPORT.get() else {
        return;
    };
    let envelopes = {
        let Ok(mut guard) = transport.envelopes.lock() else {
            return;
        };
        std::mem::take(&mut *guard)
    };
    if envelopes.is_empty() {
        return;
    }

    let dsn = &transport.dsn;
    let url = format!(
        "{}://{}:{}/api/{}/envelope/",
        dsn.scheme(),
        dsn.host(),
        dsn.port(),
        dsn.project_id(),
    );
    let auth = format!(
        "Sentry sentry_key={}, sentry_version=7, sentry_client=azul/{}",
        dsn.public_key(),
        env!("CARGO_PKG_VERSION"),
    );

    for envelope in envelopes {
        let mut body = Vec::new();
        if let Err(e) = envelope.to_writer(&mut body) {
            worker::console_error!("sentry: failed to serialize envelope: {e:?}");
            continue;
        }
        let req = match worker::Request::new_with_init(
            &url,
            &worker::RequestInit {
                method: worker::Method::Post,
                body: Some(body.into()),
                ..Default::default()
            },
        ) {
            Ok(mut r) => {
                if let Ok(h) = r.headers_mut() {
                    let _ = h.set("Content-Type", "application/x-sentry-envelope");
                    let _ = h.set("X-Sentry-Auth", &auth);
                    if let Some(id) = &transport.access_client_id {
                        let _ = h.set("CF-Access-Client-ID", id);
                    }
                    if let Some(secret) = &transport.access_client_secret {
                        let _ = h.set("CF-Access-Client-Secret", secret);
                    }
                }
                r
            }
            Err(e) => {
                worker::console_error!("sentry: failed to build request: {e:?}");
                continue;
            }
        };
        if let Err(e) = worker::Fetch::Request(req).send().await {
            worker::console_error!("sentry: failed to send envelope: {e:?}");
        }
    }
}
