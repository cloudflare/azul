use crate::CONFIG;
use generic_log_worker::batcher_do::GenericBatcher;
use static_ct_api::StaticCTPendingLogEntry;
#[allow(clippy::wildcard_imports)]
use worker::*;

#[durable_object]
struct Batcher(GenericBatcher<StaticCTPendingLogEntry>);

#[durable_object]
impl DurableObject for Batcher {
    fn new(state: State, env: Env) -> Self {
        Batcher(GenericBatcher::new(CONFIG.clone(), env))
    }

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        self.0.fetch(req).await
    }
}
