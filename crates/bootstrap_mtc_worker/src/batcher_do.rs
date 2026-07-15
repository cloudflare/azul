use crate::{BootstrapMtcSequenceMetadata, CONFIG, init_sentry};
use generic_log_worker::{BATCHER_BINDING, BatcherConfig, GenericBatcher, get_durable_object_name};
#[allow(clippy::wildcard_imports)]
use worker::*;

#[durable_object(fetch)]
struct Batcher(GenericBatcher<BootstrapMtcSequenceMetadata>);

// SAFETY: Durable Objects are single-threaded; the `RefUnwindSafe` bound
// is required by `wasm-bindgen` when building with `panic=unwind`.
impl std::panic::RefUnwindSafe for Batcher {}

impl DurableObject for Batcher {
    fn new(state: State, env: Env) -> Self {
        let name = get_durable_object_name(
            &env,
            &state,
            BATCHER_BINDING,
            &mut CONFIG
                .logs
                .iter()
                .map(|(name, params)| (name.as_str(), params.num_batchers)),
        );
        let params = &CONFIG.logs[name];
        let config = BatcherConfig {
            name: name.to_string(),
            max_batch_entries: params.max_batch_entries,
            batch_timeout_millis: params.batch_timeout_millis,
            enable_dedup: false, // deduplication is not currently supported
            location_hint: params.location_hint.clone(),
        };
        init_sentry(&env);
        Batcher(GenericBatcher::new(state, env, config))
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        generic_log_worker::obs::sentry::catch_unwind_report_and_flush(
            &[("handler", "do_fetch"), ("do_type", "batcher")],
            self.0.fetch(req),
        )
        .await
    }
}
