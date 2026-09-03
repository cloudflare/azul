use serde::de::DeserializeOwned;
use std::{env, fs};

pub struct LoadedConfig<T> {
    pub deploy_env: String,
    pub config: T,
    config_file: String,
}

#[must_use]
/// Load and validate the Worker config selected by `DEPLOY_ENV`.
///
/// # Panics
///
/// Panics if the config or schema cannot be read, parsed, or validated.
pub fn load<T: DeserializeOwned>(schema_contents: &str) -> LoadedConfig<T> {
    let deploy_env = env::var("DEPLOY_ENV").unwrap_or_else(|_| "dev".to_string());
    let config_file = format!("config.{deploy_env}.json");
    let config_contents = fs::read_to_string(&config_file)
        .unwrap_or_else(|e| panic!("failed to read config file '{config_file}': {e}"));
    let json = serde_json::from_str(&config_contents)
        .unwrap_or_else(|e| panic!("failed to deserialize JSON config '{config_file}': {e}"));
    let schema = serde_json::from_str(schema_contents)
        .unwrap_or_else(|e| panic!("failed to deserialize JSON schema 'config.schema.json': {e}"));
    jsonschema::validate(&schema, &json).unwrap_or_else(|e| {
        panic!("config '{config_file}' does not match schema 'config.schema.json': {e}")
    });
    let config = serde_json::from_str(&config_contents)
        .unwrap_or_else(|e| panic!("failed to parse '{config_file}' as application config: {e}"));
    LoadedConfig {
        deploy_env,
        config,
        config_file,
    }
}

impl<T> LoadedConfig<T> {
    /// Copy the validated config to `OUT_DIR` and emit Cargo metadata.
    ///
    /// # Panics
    ///
    /// Panics if `OUT_DIR` is missing or the config cannot be copied.
    pub fn stage(self) {
        let out_dir = env::var("OUT_DIR").expect("OUT_DIR is not set");
        fs::copy(&self.config_file, format!("{out_dir}/config.json"))
            .expect("failed to copy config file");
        println!("cargo::rustc-env=DEPLOY_ENV={}", self.deploy_env);
        println!("cargo::rerun-if-env-changed=DEPLOY_ENV");
        println!("cargo::rerun-if-changed=config.schema.json");
        println!("cargo::rerun-if-changed={}", self.config_file);
    }
}
