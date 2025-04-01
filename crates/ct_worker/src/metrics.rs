//! Metrics for CT log operations.
use prometheus::{
    self, register_counter_vec_with_registry, register_counter_with_registry,
    register_gauge_with_registry, register_histogram_vec_with_registry,
    register_histogram_with_registry, Counter, CounterVec, Gauge, Histogram, HistogramVec,
    Registry, TextEncoder,
};

// Metrics for the Sequencer DO. Use Cloudflare
// [analytics](https://developers.cloudflare.com/analytics/) for metrics on visitor traffic hitting
// the Frontend Worker.
// Reference: <https://github.com/FiloSottile/sunlight/blob/main/internal/ctlog/metrics.go>
#[derive(Debug)]
pub(crate) struct Metrics {
    pub(crate) registry: Registry,

    pub(crate) req_count: CounterVec,
    pub(crate) req_in_flight: Gauge,
    pub(crate) req_duration: HistogramVec,
    pub(crate) entry_count: CounterVec,

    pub(crate) seq_count: CounterVec,
    pub(crate) seq_pool_size: Histogram,
    pub(crate) seq_duration: Histogram,
    pub(crate) seq_delay: Histogram,
    pub(crate) seq_leaf_size: Histogram,
    pub(crate) seq_tiles: Counter,
    pub(crate) seq_data_tile_size: Histogram,

    pub(crate) tree_time: Gauge,
    pub(crate) tree_size: Gauge,

    pub(crate) config_roots: Gauge,
    // Also available in /metadata endpoint.
    pub(crate) config_start: Gauge,
    // Also available in /metadata endpoint.
    pub(crate) config_end: Gauge,
}

impl Metrics {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn new() -> Self {
        let r = Registry::new();
        let req_count = register_counter_vec_with_registry!(
            "do_requests_total",
            "Requests served by the Durable Object, by endpoint.",
            &["endpoint"],
            r
        )
        .unwrap();
        let req_in_flight = register_gauge_with_registry!(
            "do_in_flight_requests",
            "Requests currently being served by the Durable Object.",
            r
        )
        .unwrap();
        let req_duration = register_histogram_vec_with_registry!(
            "do_requests_duration_seconds",
            "Durable Object request serving latencies in seconds, by endpoint.",
            &["endpoint"],
            vec![0.5, 1.0, 1.5],
            r,
        )
        .unwrap();
        let entry_count = register_counter_vec_with_registry!(
            "do_entries_total",
            "Entries submitted to be sequenced, by type and status.",
            &["type", "status"],
            r
        )
        .unwrap();
        let seq_count = register_counter_vec_with_registry!(
            "sequencing_rounds_total",
            "Number of sequencing rounds, by error category if failed.",
            &["error"],
            r
        )
        .unwrap();
        let seq_pool_size = register_histogram_with_registry!(
            "sequencing_pool_entries",
            "Number of entries in the pools being sequenced.",
            vec![0.0, 10.0, 100.0, 1000.0, 2000.0, 4000.0],
            r
        )
        .unwrap();
        let seq_duration = register_histogram_with_registry!(
            "sequencing_duration_seconds",
            "Duration of sequencing rounds, successful or not.",
            vec![0.5, 1.0, 2.0, 4.0, 8.0],
            r
        )
        .unwrap();
        let seq_delay = register_histogram_with_registry!(
            "sequencing_delay_seconds",
            "Delay between sequencing rounds beyond the expected sequencing interval.",
            vec![0.5, 1.0, 2.0, 4.0, 8.0],
            r
        )
        .unwrap();
        let seq_leaf_size = register_histogram_with_registry!(
            "sequencing_leaf_bytes",
            "Size of leaves in sequencing rounds, successful or not.",
            vec![1000.0, 1500.0, 2000.0, 4000.0],
            r
        )
        .unwrap();
        let seq_tiles = register_counter_with_registry!(
            "sequencing_uploaded_tiles_total",
            "Number of tiles uploaded in successful rounds, including partials.",
            r
        )
        .unwrap();
        let seq_data_tile_size = register_histogram_with_registry!(
            "sequencing_data_tiles_bytes",
            "Size of uploaded data tiles, including partials.",
            vec![10_000.0, 100_000.0, 1_000_000.0],
            r
        )
        .unwrap();
        let tree_size = register_gauge_with_registry!(
            "tree_size_leaves_total",
            "Size of the latest published tree head.",
            r
        )
        .unwrap();
        let tree_time = register_gauge_with_registry!(
            "tree_timestamp_seconds",
            "Timestamp of the latest published tree head.",
            r
        )
        .unwrap();
        let config_roots =
            register_gauge_with_registry!("config_roots_total", "Number of accepted roots.", r)
                .unwrap();
        let config_start = register_gauge_with_registry!(
            "config_notafter_start_timestamp_seconds",
            "Start of the NotAfter accepted period.",
            r
        )
        .unwrap();
        let config_end = register_gauge_with_registry!(
            "config_notafter_end_timestamp_seconds",
            "End of the NotAfter accepted period.",
            r
        )
        .unwrap();
        Self {
            registry: r,
            req_count,
            req_in_flight,
            req_duration,
            entry_count,
            seq_count,
            seq_pool_size,
            seq_duration,
            seq_delay,
            seq_leaf_size,
            seq_tiles,
            seq_data_tile_size,
            tree_size,
            tree_time,
            config_roots,
            config_start,
            config_end,
        }
    }
    pub(crate) fn encode(&self) -> String {
        let mut buffer = String::new();
        let encoder = TextEncoder::new();
        encoder
            .encode_utf8(&self.registry.gather(), &mut buffer)
            .unwrap();
        buffer
    }
}

pub(crate) struct ObjectMetrics {
    pub(crate) duration: HistogramVec,
    pub(crate) upload_size_bytes: Histogram,
    pub(crate) errors: CounterVec,
}

impl ObjectMetrics {
    pub(crate) fn new(r: &Registry) -> Self {
        let duration = register_histogram_vec_with_registry!(
            "object_duration_seconds",
            "Duration of object storage operations, by method.",
            &["method"],
            vec![0.25, 0.5, 1.0],
            r
        )
        .unwrap();
        let upload_size_bytes = register_histogram_with_registry!(
            "object_upload_size_bytes",
            "Body size in bytes for object storage puts.",
            vec![100.0, 1_000.0, 10_000.0, 100_000.0, 1_000_000.0],
            r
        )
        .unwrap();
        let errors = register_counter_vec_with_registry!(
            "object_put_errors_total",
            "Number of failed object storage operations, by method.",
            &["method"],
            r
        )
        .unwrap();
        Self {
            duration,
            upload_size_bytes,
            errors,
        }
    }
}

// Perform a potentially-lossy conversion to f64 from the input type.
pub(crate) trait AsF64 {
    fn as_f64(&self) -> f64;
}

macro_rules! impl_as_f64 {
    ($($t:ty),*) => {
        $(
            #[allow(clippy::cast_precision_loss)]
            impl AsF64 for $t {
                fn as_f64(&self) -> f64 {
                    *self as f64
                }
            }
        )*
    };
}

impl_as_f64!(usize, u64, i64);

pub(crate) fn millis_diff_as_secs(start: u64, end: u64) -> f64 {
    (end.as_f64() - start.as_f64()) / 1e3
}
