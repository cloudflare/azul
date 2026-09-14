use crate::{CONFIG, IetfMtcSequenceMetadata, init_sentry};
use generic_log_worker::{BatcherConfig, GenericBatcher, get_sharded_durable_object_base_name};
#[allow(clippy::wildcard_imports)]
use worker::*;

#[durable_object(fetch)]
struct Batcher(GenericBatcher<IetfMtcSequenceMetadata>);

// SAFETY: Durable Objects are single-threaded; this is required by wasm-bindgen
// when building with panic unwinding.
impl std::panic::RefUnwindSafe for Batcher {}

impl DurableObject for Batcher {
    fn new(state: State, env: Env) -> Self {
        let name = get_sharded_durable_object_base_name(&state);
        let params = &CONFIG.logs[&name];
        let config = BatcherConfig {
            max_batch_entries: params.max_batch_entries,
            batch_timeout_millis: params.batch_timeout_millis,
            enable_dedup: true,
            enable_long_term_dedup: false,
            location_hint: params.location_hint.clone(),
            name,
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
