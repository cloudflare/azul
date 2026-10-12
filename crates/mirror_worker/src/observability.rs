// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Per-invocation mirror telemetry. Registries are flushed through the same
//! optional Wshim binding used by the frontend and the CT Durable Objects.

use std::cell::Cell;

use generic_log_worker::{
    obs::{self, Wshim, metrics},
    util::now_millis,
};
use prometheus::{
    CounterVec, GaugeVec, HistogramVec, Registry, register_counter_vec_with_registry,
    register_gauge_vec_with_registry, register_histogram_vec_with_registry,
};
use worker::{Env, Response, State};

use crate::storage::origin_hash;

pub(crate) struct InvocationMetrics {
    registry: Registry,
    requests: CounterVec,
    duration: HistogramVec,
    errors: CounterVec,
    publication: GaugeVec,
    witness_failures: GaugeVec,
    cleaner_backlog: GaugeVec,
    registry_sync: GaugeVec,
    component: &'static str,
    operation: &'static str,
    started: u64,
    degraded: Cell<bool>,
}

impl InvocationMetrics {
    pub(crate) fn new(component: &'static str, operation: &'static str) -> Self {
        let registry = metrics::registry();
        let requests = register_counter_vec_with_registry!(
            "mirror_invocations_total",
            "Mirror DO and scheduled invocations by outcome.",
            &["component", "operation", "outcome"],
            &registry,
        )
        .unwrap();
        let duration = register_histogram_vec_with_registry!(
            "mirror_invocation_duration_seconds",
            "Mirror DO and scheduled invocation duration.",
            &["component", "operation"],
            vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0],
            &registry,
        )
        .unwrap();
        let errors = register_counter_vec_with_registry!(
            "mirror_invocation_errors_total",
            "Mirror invocation failures by kind.",
            &["component", "operation", "kind"],
            &registry,
        )
        .unwrap();
        let publication = register_gauge_vec_with_registry!(
            "mirror_last_publication_timestamp_seconds",
            "Last successful checkpoint publication (Unix time), by origin and role.",
            &["origin", "role"],
            &registry,
        )
        .unwrap();
        let witness_failures = register_gauge_vec_with_registry!(
            "mirror_witness_publication_failure_event",
            "Witness checkpoint signing or publication failed in this invocation, by origin.",
            &["origin"],
            &registry,
        )
        .unwrap();
        let cleaner_backlog = register_gauge_vec_with_registry!(
            "mirror_cleaner_backlog_leaves",
            "Committed entries awaiting partial-tile cleanup, by origin.",
            &["origin"],
            &registry,
        )
        .unwrap();
        let registry_sync = register_gauge_vec_with_registry!(
            "mirror_registry_last_sync_timestamp_seconds",
            "Last successful cosigner registry synchronization (Unix time).",
            &["component"],
            &registry,
        )
        .unwrap();
        Self {
            registry,
            requests,
            duration,
            errors,
            publication,
            witness_failures,
            cleaner_backlog,
            registry_sync,
            component,
            operation,
            started: now_millis(),
            degraded: Cell::new(false),
        }
    }

    fn record(&self, outcome: &str) {
        self.requests
            .with_label_values(&[self.component, self.operation, outcome])
            .inc();
        #[allow(clippy::cast_precision_loss)]
        self.duration
            .with_label_values(&[self.component, self.operation])
            .observe(now_millis().saturating_sub(self.started) as f64 / 1000.0);
    }

    pub(crate) fn response(&self, response: &worker::Result<Response>) {
        let (outcome, error) = match response.as_ref().map(Response::status_code) {
            Ok(code) if code >= 500 => ("error", Some("http_5xx")),
            Ok(code) if code >= 400 => ("rejected", None),
            Ok(_) if self.degraded.get() => ("error", None),
            Ok(_) => ("success", None),
            Err(_) => ("error", Some("handler")),
        };
        self.record(outcome);
        if let Some(kind) = error {
            self.error(kind);
        }
    }

    pub(crate) fn scheduled(&self, result: &worker::Result<()>) {
        if result.is_err() {
            self.record("error");
            self.error("sync");
        } else {
            self.record("success");
        }
    }

    pub(crate) fn error(&self, kind: &'static str) {
        self.errors
            .with_label_values(&[self.component, self.operation, kind])
            .inc();
    }

    /// Record a failure swallowed by a best-effort handler returning HTTP 200.
    pub(crate) fn degraded(&self, kind: &'static str) {
        self.degraded.set(true);
        self.error(kind);
    }

    pub(crate) fn publication(&self, origin: &str, role: &'static str) {
        self.publication
            .with_label_values(&[&origin_hash(origin), role])
            .set(as_f64(generic_log_worker::util::now_millis()) / 1000.0);
    }

    pub(crate) fn witness_failure(&self, origin: &str) {
        self.witness_failures
            .with_label_values(&[&origin_hash(origin)])
            .set(1.0);
    }

    pub(crate) fn cleaner_backlog(&self, origin: &str, cleaned: u64, committed: u64) {
        self.cleaner_backlog
            .with_label_values(&[&origin_hash(origin)])
            .set(as_f64(committed.saturating_sub(cleaned)));
    }

    pub(crate) fn registry_sync(&self) {
        self.registry_sync
            .with_label_values(&["cosigner_registry"])
            .set(as_f64(generic_log_worker::util::now_millis()) / 1000.0);
    }

    pub(crate) fn flush_do(self, state: &State, env: &Env) {
        if let Ok(wshim) = Wshim::from_env(env) {
            state.wait_until(async move {
                wshim.flush(&obs::logs::LOGGER).await;
                wshim.flush(&self.registry).await;
            });
        }
    }

    pub(crate) async fn flush(self, env: &Env) {
        if let Ok(wshim) = Wshim::from_env(env) {
            wshim.flush(&obs::logs::LOGGER).await;
            wshim.flush(&self.registry).await;
        }
    }
}

#[allow(clippy::cast_precision_loss)]
fn as_f64(value: u64) -> f64 {
    value as f64
}
