# AGENTS.md

Azul is a Rust workspace implementing tiled Certificate Transparency logs and Merkle Tree Certificates for deployment on Cloudflare Workers.

**Tech Stack:** Rust (edition 2021), Cloudflare Workers (WASM via worker-build), Cargo workspace resolver v2

## Directory Structure

```
crates/ct_worker/      - Static CT API Worker (deployable); wrangler.jsonc here
crates/mtc_worker/     - Merkle Tree CA Worker (deployable); wrangler.jsonc here
crates/generic_log_worker/ - Shared Durable Object logic (Sequencer, Batcher, Cleaner)
crates/tlog_tiles/     - C2SP tlog-tiles spec impl (published to crates.io)
crates/static_ct_api/  - C2SP static-ct-api spec impl (published to crates.io)
fuzz/                  - cargo-fuzz targets for tlog parsing
```

## Commands

```bash
cargo build                      # build all workspace crates
cargo clippy -- -D warnings      # lint; warnings are errors in CI
cargo test                       # run all tests
cargo bench                      # run benchmarks (criterion in signed_note)

# Fuzzing (nightly required)
cargo fuzz run fuzz_parse_tile_path
cargo fuzz run fuzz_parse_checkpoint

# Worker local dev (run from crates/ct_worker/ or crates/mtc_worker/)
npx wrangler -e=dev dev
./reset-dev.sh                   # clear local wrangler state between runs

# Worker deploy
npx wrangler -e=${ENV} deploy
npx wrangler -e=${ENV} tail
```

## Code Patterns

- Worker crates use `crate-type = ["cdylib"]`; library crates use `rlib`
- Worker build is handled by `worker-build`, not `cargo build` directly — wrangler.jsonc invokes it automatically
- Config types live in separate sub-crates: `crates/ct_worker/config/`, `crates/mtc_worker/config/`
- `DEPLOY_ENV=<env>` env var must be set when invoking `worker-build` manually; wrangler.jsonc sets it per environment
- `der` crate is patched to a private fork in `Cargo.toml` `[patch.crates-io]` — do not remove or alter this

## Workflow

### Deploying a Worker
1. Run `./scripts/create-log.sh` to provision R2 bucket, KV namespace, and signing/witness keys
2. Set required secrets: `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 | npx wrangler -e=${ENV} secret put SIGNING_KEY_${LOG_NAME}`
3. `npx wrangler -e=${ENV} deploy` from the worker's crate directory

### Adding a New Workspace Crate
1. Create `crates/<name>/Cargo.toml` with `workspace = true` fields
2. Add the path to `[workspace.members]` in root `Cargo.toml`
3. Add shared dependencies to `[workspace.dependencies]` rather than duplicating versions

## Boundaries

✅ **Always:** Run `cargo clippy -- -D warnings` before pushing; CI fails on any warning
✅ **Always:** Add new shared dependencies to `[workspace.dependencies]` in root `Cargo.toml`
⚠️ **Requires Approval:** Publishing crates to crates.io (`tlog_tiles`, `static_ct_api`, `signed_note`, `signed_note`) — worker crates have `publish = false`
🚫 **Never:** Remove or modify the `[patch.crates-io]` override for `der`; it points to a required fork
