use std::{rc::Rc, time::Duration};

use crate::{CONFIG, init_sentry, load_checkpoint_signers, load_origin};
use generic_log_worker::{
    CheckpointVerifierSource, CleanerConfig, GenericCleaner, key_service::Keyring,
};
use signed_note::VerifierList;
use static_ct_api::StaticCTPendingLogEntry;
use tlog_entry::PendingLogEntry;
#[allow(clippy::wildcard_imports)]
use worker::*;

enum CleanerVerifiers {
    Local(Rc<VerifierList>),
    Service { ring: Keyring, shard: String },
}

impl CheckpointVerifierSource for CleanerVerifiers {
    async fn verifiers(&self) -> Result<Rc<VerifierList>> {
        match self {
            Self::Local(verifiers) => Ok(Rc::clone(verifiers)),
            Self::Service { ring, shard } => crate::key_service::load_shard_verifiers(ring, shard)
                .await
                .map(Rc::new)
                .map_err(Error::from),
        }
    }
}

#[durable_object(alarm)]
struct Cleaner(GenericCleaner<CleanerVerifiers>);

// SAFETY: Durable Objects are single-threaded; the `RefUnwindSafe` bound
// is required by `wasm-bindgen` when building with `panic=unwind`.
impl std::panic::RefUnwindSafe for Cleaner {}

impl DurableObject for Cleaner {
    fn new(state: State, env: Env) -> Self {
        let name = state
            .id()
            .name()
            .expect("durable object name not provided by runtime");
        let params = &CONFIG.logs[&name];

        let config = CleanerConfig {
            origin: load_origin(&name),
            data_path: StaticCTPendingLogEntry::DATA_TILE_PATH,
            aux_path: StaticCTPendingLogEntry::AUX_TILE_PATH,
            verifiers: if let Some(ring) = Keyring::new(&env) {
                CleanerVerifiers::Service {
                    ring,
                    shard: name.clone(),
                }
            } else {
                CleanerVerifiers::Local(Rc::new(VerifierList::new(
                    load_checkpoint_signers(&env, &name)
                        .iter()
                        .map(|s| s.verifier())
                        .collect(),
                )))
            },
            clean_interval: Duration::from_secs(params.clean_interval_secs),
            name,
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
