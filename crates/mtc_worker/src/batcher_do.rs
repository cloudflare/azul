use crate::CONFIG;
use generic_log_worker::{get_durable_object_stub, load_cache_kv, BatcherConfig, GenericBatcher};
use mtc_api::BootstrapMtcPendingLogEntry;
#[allow(clippy::wildcard_imports)]
use worker::*;

#[durable_object]
struct Batcher(GenericBatcher<BootstrapMtcPendingLogEntry>);

impl DurableObject for Batcher {
    fn new(state: State, env: Env) -> Self {
        // Find the Durable Object name by enumerating all possibilities.
        // TODO after update to worker > 0.6.0 use ObjectId::equals for comparison.
        let id = state.id().to_string();
        let namespace = env.durable_object("BATCHER").unwrap();
        let (name, params) = CONFIG
            .logs
            .iter()
            .find(|(name, params)| {
                for shard_id in 0..params.num_batchers {
                    if id
                        == namespace
                            .id_from_name(&format!("{name}_{shard_id:x}"))
                            .unwrap()
                            .to_string()
                    {
                        return true;
                    }
                }
                false
            })
            .expect("unable to find batcher name");
        let kv = if params.enable_dedup {
            Some(load_cache_kv(&env, name).unwrap())
        } else {
            None
        };
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

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.0.fetch(req).await
    }
}
