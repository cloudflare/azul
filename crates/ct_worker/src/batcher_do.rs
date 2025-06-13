use crate::CONFIG;
use generic_log_worker::{
    get_durable_object_name, get_durable_object_stub, load_cache_kv, BatcherConfig, GenericBatcher,
};
use static_ct_api::StaticCTPendingLogEntry;
#[allow(clippy::wildcard_imports)]
use worker::*;

#[durable_object]
struct Batcher(GenericBatcher<StaticCTPendingLogEntry>);

#[durable_object]
impl DurableObject for Batcher {
    fn new(state: State, env: Env) -> Self {
        let (_, name) = get_durable_object_name(state).unwrap();
        let params = &CONFIG.logs[&name];
        let kv = load_cache_kv(&env, &name).unwrap();
        let sequencer = get_durable_object_stub(
            &env,
            &name,
            None,
            "SEQUENCER",
            params.location_hint.as_deref(),
        )
        .unwrap();
        let config = BatcherConfig {
            name,
            max_batch_entries: params.max_batch_entries,
            batch_timeout_millis: params.batch_timeout_millis,
        };
        Batcher(GenericBatcher::new(config, kv, sequencer))
    }

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        self.0.fetch(req).await
    }
}
