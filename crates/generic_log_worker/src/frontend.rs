use crate::{obs::metrics, util::now_millis};
use axum::{
    extract::{MatchedPath, State},
    http::StatusCode,
};
use tower_service::Service as _;
use worker::{Env, WorkerVersionMetadata};

pub async fn request_metrics(
    State((env, metrics)): State<(Env, metrics::FrontendWorkerMetrics)>,
    request: axum::extract::Request,
    mut next: axum::middleware::Next,
) -> axum::response::Response {
    let start = now_millis();
    let metric_labels = request.extensions().get::<MatchedPath>().cloned().map(|m| {
        let log = request
            .uri()
            .path()
            .strip_prefix("/logs/")
            .and_then(|rest| rest.split('/').next())
            .unwrap_or("unknown")
            .to_owned();
        (m, log)
    });

    let Ok(response) = next.call(request).await;
    if let Some((path, log)) = metric_labels {
        // The time a request takes to execute will never overflow an f64
        #[allow(clippy::cast_precision_loss)]
        metrics
            .http_request_duration_ms
            .with_label_values(&[path.as_str(), &log])
            .observe((now_millis() - start) as f64);
        metrics
            .http_request_total
            .with_label_values(&[path.as_str(), &log])
            .inc();
    }
    let version = env
        .get_binding::<WorkerVersionMetadata>("VERSION_METADATA")
        .map_or_else(
            |_| String::from("unknown"),
            |v| match v.tag() {
                t if t.is_empty() => v.id(),
                t => t,
            },
        );
    metrics
        .versioned_requests_total
        .with_label_values(&[
            match response.status() {
                StatusCode::INTERNAL_SERVER_ERROR => "error",
                _ => "success",
            },
            &version,
        ])
        .inc();
    response
}
