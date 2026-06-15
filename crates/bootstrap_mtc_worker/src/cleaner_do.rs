use std::time::Duration;

use crate::{CONFIG, init_sentry, load_checkpoint_cosigner, load_origin};
use bootstrap_mtc_api::BootstrapMtcPendingLogEntry;
use generic_log_worker::{CLEANER_BINDING, CleanerConfig, GenericCleaner, get_durable_object_name};
use signed_note::VerifierList;
use tlog_checkpoint::CheckpointSigner;
use tlog_entry::PendingLogEntry;
#[allow(clippy::wildcard_imports)]
use worker::*;

#[durable_object(alarm)]
struct Cleaner(GenericCleaner);

// SAFETY: Durable Objects are single-threaded; the `RefUnwindSafe` bound
// is required by `wasm-bindgen` when building with `panic=unwind`.
impl std::panic::RefUnwindSafe for Cleaner {}

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
            verifiers: VerifierList::new(vec![load_checkpoint_cosigner(&env, name).verifier()]),
            clean_interval: Duration::from_secs(params.clean_interval_secs),
        };

        init_sentry(&env);
        Cleaner(GenericCleaner::new(state, &env, config))
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        generic_log_worker::obs::sentry::catch_unwind_report_and_flush(
            &[("handler", "do_fetch"), ("do_type", "cleaner")],
            self.0.fetch(req),
        )
        .await
    }

    async fn alarm(&self) -> Result<Response> {
        generic_log_worker::obs::sentry::catch_unwind_report_and_flush(
            &[("handler", "do_alarm"), ("do_type", "cleaner")],
            self.0.alarm(),
        )
        .await
    }
}
