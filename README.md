# Azul

Azul (short for [azulejos](https://en.wikipedia.org/wiki/Azulejo), the colorful Portuguese and Spanish ceramic tiles) contains an implementation of a tiled certificate transparency log compatible with the [Static CT API](https://c2sp.org/static-ct-api), built for deployment on [Cloudflare Workers](https://workers.cloudflare.com). It also contains several crates implementing various C2SP specifications. Read the [blog post](https://blog.cloudflare.com/azul-certificate-transparency-log) for more details.

The crates in the repository are organized as follows:

- **[ct_worker](crates/ct_worker)**: A Static CT API log implementation for deployment on Cloudflare Workers.
- **[static_ct_api](crates/static_ct_api)** ([crates.io](https://crates.io/crates/static_ct_api)): An implementation of the [C2SP static-ct-api](https://c2sp.org/static-ct-api) specification.
- **[signed_note](crates/signed_note)** ([crates.io](https://crates.io/crates/signed_note)): An implementation of the [C2SP signed-note](https://c2sp.org/signed-note) specification.
- **[tlog_tiles](crates/tlog_tiles)** ([crates.io](https://crates.io/crates/tlog_tiles)): An implementation of the [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) and [C2SP checkpoint](https://c2sp.org/tlog-checkpoint) specifications.

## Deploy

See instructions in the [ct_worker](crates/ct_worker/README.md) crate for deployment instructions.

## Build

    cargo build

## Test

    cargo test

## Benchmark

    cargo bench

## Fuzz

Follow setup instructions from <https://rust-fuzz.github.io/book/cargo-fuzz/setup.html> (requires nightly compiler).

    cargo fuzz run fuzz_parse_tile_path
    cargo fuzz run fuzz_parse_tree
    cargo fuzz run fuzz_parse_record
