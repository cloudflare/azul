use std::time::Duration;

use crate::{load_checkpoint_signers, load_origin, CONFIG};
use generic_log_worker::{get_durable_object_name, CleanerConfig, GenericCleaner, CLEANER_BINDING};
use mtc_api::BootstrapMtcPendingLogEntry;
use signed_note::VerifierList;
use tlog_tiles::PendingLogEntry;
#[allow(clippy::wildcard_imports)]
use worker::*;

#[durable_object(alarm)]
struct Cleaner(GenericCleaner);

impl DurableObject for Cleaner {
    fn new(state: State, env: Env) -> Self {
        let name = get_durable_object_name(
            &env,
            &state,
            CLEANER_BINDING,
            &mut CONFIG.logs.keys().map(|name| (name.as_str(), 0)),
        );
        let params = &CONFIG.logs[name];

        let config = CleanerConfig {
            name: name.to_string(),
            origin: load_origin(name),
            data_path: BootstrapMtcPendingLogEntry::DATA_TILE_PATH,
            aux_path: BootstrapMtcPendingLogEntry::AUX_TILE_PATH,
            verifiers: VerifierList::new(
                load_checkpoint_signers(&env, name)
                    .iter()
                    .map(|s| s.verifier())
                    .collect(),
            ),
            clean_interval: Duration::from_secs(params.clean_interval_secs),
        };

        Cleaner(GenericCleaner::new(&state, env, config))
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.0.fetch(req).await
    }

    async fn alarm(&self) -> Result<Response> {
        self.0.alarm().await.and(Response::ok("Alarm done"))
    }
}
