use crate::CONFIG;
use generic_log_worker::{
    get_durable_object_name, get_durable_object_stub, load_cache_kv, BatcherConfig, GenericBatcher,
};
use mtc_api::MtcPendingLogEntry;
#[allow(clippy::wildcard_imports)]
use worker::*;

#[durable_object]
struct Batcher(GenericBatcher<MtcPendingLogEntry>);

#[durable_object]
impl DurableObject for Batcher {
    fn new(state: State, env: Env) -> Self {
        let (_, object_name) = get_durable_object_name(state).unwrap();
        // Get the log name from the batcher name (see 'get_durable_object_stub'
        // for how the batcher name is derived).
        let name = object_name.rsplit_once('_').unwrap().0;
        let params = &CONFIG.logs[name];
        let kv = load_cache_kv(&env, name).unwrap();
        let sequencer = get_durable_object_stub(
            &env,
            name,
            None,
            "SEQUENCER",
            params.location_hint.as_deref(),
        )
        .unwrap();
        let config = BatcherConfig {
            name: name.to_string(),
            max_batch_entries: params.max_batch_entries,
            batch_timeout_millis: params.batch_timeout_millis,
        };
        Batcher(GenericBatcher::new(config, kv, sequencer))
    }

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        self.0.fetch(req).await
    }
}
