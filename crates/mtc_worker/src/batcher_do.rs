use crate::CONFIG;
use generic_log_worker::{get_durable_object_name, BatcherConfig, GenericBatcher, BATCHER_BINDING};
#[allow(clippy::wildcard_imports)]
use worker::*;

#[durable_object(fetch)]
struct Batcher(GenericBatcher);

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
        Batcher(GenericBatcher::new(state, env, config))
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.0.fetch(req).await
    }
}
