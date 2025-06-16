# Generic Log Worker

A Rust implementation of a tiled Merkle Tree log for deployment on [Cloudflare Workers](https://workers.cloudflare.com/). This is compatible with different specific protocols/signing formats, eg [Static CT](https://c2sp.org/static-ct-api) and [tlog](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md).

## Architecture

The 'brain' of each log is a single-threaded 'Sequencer' Durable Object, and much of the system is architected around offloading as much work as possible to other components of the system (like 'Batcher' Durable Objects) to improve overall throughput. Read the [blog post](https://blog.cloudflare.com/azul-certificate-transparency-log) for more details, specifically about the Static CT specialization of this crate.

> :warning: **Warning** The software in this crate is written specifically for the [Cloudflare Durable Objects](https://developers.cloudflare.com/durable-objects/) execution model, with single-threaded execution and [input/output gates](https://blog.cloudflare.com/durable-objects-easy-fast-correct-choose-three) to avoid race conditions. Running it elsewhere could lead to concurrency bugs.

![System Diagram](doc/img/static-ct.drawio.svg)
