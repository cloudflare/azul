# AGENTS.md

Azul is a Rust workspace implementing tiled Certificate Transparency logs and Merkle Tree Certificates for deployment on Cloudflare Workers.

**Tech Stack:** Rust (edition 2021), Cloudflare Workers (WASM via worker-build), Cargo workspace resolver v2

## Directory Structure

```
crates/ct_worker/      - Static CT API Worker (deployable); wrangler.jsonc here
crates/bootstrap_mtc_worker/     - Bootstrap MTC CA Worker (deployable); wrangler.jsonc here
crates/generic_log_worker/ - Shared Durable Object logic (Sequencer, Batcher, Cleaner)
crates/tlog_tiles/     - C2SP tlog-tiles spec impl (published to crates.io)
crates/static_ct_api/  - C2SP static-ct-api spec impl (published to crates.io)
fuzz/                  - cargo-fuzz targets for tlog parsing
```

## Commands

```bash
cargo build                      # build all workspace crates
cargo clippy -- -D warnings      # lint; warnings are errors in CI
cargo test                       # run all unit tests (excludes integration_tests — requires wrangler dev)
cargo bench                      # run benchmarks (criterion in signed_note)

# Fuzzing (nightly required)
cargo fuzz run fuzz_parse_tile_path
cargo fuzz run fuzz_parse_checkpoint

# Worker local dev (run from crates/ct_worker/ or crates/bootstrap_mtc_worker/)
npx wrangler -e=dev dev
./reset-dev.sh                   # clear local wrangler state between runs

# Integration tests (requires wrangler dev to be running)

# CT worker tests — from crates/ct_worker/:
npx wrangler -e=dev dev &
# From workspace root:
cargo test -p integration_tests --test static_ct_api
# Override defaults:
BASE_URL=http://localhost:8787 LOG_NAME=dev2026h1a cargo test -p integration_tests --test static_ct_api

# Bootstrap MTC worker tests — from crates/bootstrap_mtc_worker/:
npx wrangler -e=dev dev &
# From workspace root:
cargo test -p integration_tests --test bootstrap_mtc_api
# Override defaults:
BASE_URL=http://localhost:8787 BOOTSTRAP_MTC_LOG_NAME=dev2 cargo test -p integration_tests --test bootstrap_mtc_api

# IETF MTC worker tests — from crates/ietf_mtc_worker/:
npx wrangler -e=dev dev &
# From workspace root:
cargo test -p integration_tests --test ietf_mtc_api
# Override defaults:
BASE_URL=http://localhost:8787 IETF_MTC_LOG_NAME=dev2 cargo test -p integration_tests --test ietf_mtc_api

# Worker deploy
npx wrangler -e=${ENV} deploy
npx wrangler -e=${ENV} tail
```

## Code Patterns

- Worker crates use `crate-type = ["cdylib"]`; library crates use `rlib`
- Worker build is handled by `worker-build`, not `cargo build` directly — wrangler.jsonc invokes it automatically
- Config types live in separate sub-crates: `crates/ct_worker/config/`, `crates/bootstrap_mtc_worker/config/`
- `DEPLOY_ENV=<env>` env var must be set when invoking `worker-build` manually; wrangler.jsonc sets it per environment


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

✅ **Always:** Before pushing any commit, run the pre-push checks locally and confirm they pass:

```bash
cargo clippy --workspace --all-targets -- -D warnings   # lint; CI fails on any warning
cargo test --workspace --lib --bins                     # unit tests (integration_tests requires wrangler dev; skip or run separately)
cargo fmt --all --check                                 # formatting; advisory in CI, but easy to fix
cargo machete                                           # unused-dependency check; advisory in CI, but easy to fix
```

If any step fails, fix the issue in the commit it belongs to (use `git commit --fixup=<sha>` + `git rebase --autosquash`) rather than layering a separate "fix lint" commit on top.

✅ **Always:** Add new shared dependencies to `[workspace.dependencies]` in root `Cargo.toml`. Do not add a dependency to a crate's `Cargo.toml` before you actually use it — `cargo machete` will flag speculative additions.

✅ **Always:** Keep Workers-specific concerns (Durable Object storage formats, KV dedup cache, Worker runtime dependencies) out of the specification-level crates (`tlog_tiles`, `static_ct_api`, `bootstrap_mtc_api`, `signed_note`). Those crates implement public specs and are published to crates.io; they should not gain types, traits, or dependencies whose only consumers are Cloudflare Workers. Wire-format types used only by the sequencer and frontend belong in `generic_log_worker` or the concrete worker crate.
⚠️ **Requires Approval:** Publishing crates to crates.io (`tlog_tiles`, `static_ct_api`, `signed_note`, `signed_note`) — worker crates have `publish = false`

