use crate::obs::WshimData;
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{Mutex, Once},
};

pub struct Logger {
    entries: Mutex<Vec<LogEntry>>,
}

#[derive(Serialize)]
struct LogEntry {
    message: String,
    level: String,
    #[serde(flatten)]
    fields: HashMap<String, String>,
}

impl WshimData for &'static Logger {
    fn endpoint() -> &'static str {
        "log"
    }
    fn to_body(&self) -> Vec<u8> {
        let logs = std::mem::take(&mut *self.entries.lock().unwrap());

        // schema
        // logs: { message: { message: string; ...fields } }[]
        serde_json::to_vec(&serde_json::json!({
            "logs": logs
                .into_iter()
                .map(|log_entry| serde_json::json!({ "message": log_entry }))
                .collect::<Vec<_>>(),
        }))
        .unwrap()
    }
}

pub static LOGGER: Logger = Logger {
    entries: Mutex::new(Vec::new()),
};

/// Initialize the logger.
///
/// # Panics
///
/// Will panic if setting the global logger with `set_logger` fails.
pub fn init(level: Option<&str>) {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let level = level
            .and_then(|l| l.parse().ok())
            .unwrap_or(log::Level::Info);
        log::set_max_level(level.to_level_filter());
        log::set_logger(&LOGGER).unwrap();
    });
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record) {
        struct Visitor<'m>(&'m mut HashMap<String, String>);
        impl<'kvs> log::kv::VisitSource<'kvs> for Visitor<'_> {
            fn visit_pair(
                &mut self,
                key: log::kv::Key<'kvs>,
                value: log::kv::Value<'kvs>,
            ) -> Result<(), log::kv::Error> {
                self.0.insert(key.as_str().to_owned(), value.to_string());
                Ok(())
            }
        }

        console_log::log(record);
        let mut fields = HashMap::new();
        if let Some(module) = record.module_path() {
            if let Some(file) = record.file() {
                if let Some(line) = record.line() {
                    fields.insert("location".to_owned(), format!("{module}::{file}:{line}"));
                }
            }
        }
        record
            .key_values()
            .visit(&mut Visitor(&mut fields))
            .unwrap();
        self.entries.lock().unwrap().push(LogEntry {
            message: format!("{}", record.args()),
            level: record.level().to_string(),
            fields,
        });
    }

    fn flush(&self) {
        // flushing the logs is an async process so we can't call it from here. But that is okay,
        // this function is optional and not guaranteed to called anyway and we already flush at
        // the end of each request.
    }
}
