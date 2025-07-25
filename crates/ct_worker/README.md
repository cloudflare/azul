# Static CT API Worker

A Rust implementation of the [Static CT API](https://c2sp.org/static-ct-api) for deployment on [Cloudflare Workers](https://workers.cloudflare.com/).

## Architecture

This project can be used to run multiple CT log shards within a single Workers application.

The 'brain' of each CT log is a single-threaded 'Sequencer' Durable Object, and much of the system is architected around offloading as much work as possible to other components of the system (like 'Batcher' Durable Objects) to improve overall throughput. Read the [blog post](https://blog.cloudflare.com/azul-certificate-transparency-log) for more details.

> :warning: **Warning** The software in this crate is written specifically for the [Cloudflare Durable Objects](https://developers.cloudflare.com/durable-objects/) execution model, with single-threaded execution and [input/output gates](https://blog.cloudflare.com/durable-objects-easy-fast-correct-choose-three) to avoid race conditions. Running it elsewhere could lead to concurrency bugs.

![System Diagram](doc/img/static-ct.drawio.svg)

### Life of an add-[pre-]chain request

The Frontend (a Worker in a location close to the client) handles incoming requests (1) for the [Submission APIs](https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#submission-apis). After validating the request (2) and checking the deduplication cache (3), it submits the entry (4) to a Batcher (selected via consistent hashing over the entry), and awaits the response.

The Batcher receives requests (keeping them open) and groups the entries into batches which it submits (5) to the Sequencer, which then adds the request to a pool of entries to be sequenced. An [Alarm](https://developers.cloudflare.com/durable-objects/api/alarms/) fires every `sequence_interval` (default 1s) to trigger the Sequencer to sequence the pool of entries (6) and update state in the Object ([R2](https://developers.cloudflare.com/r2)) and Lock ([Durable Object Storage](https://developers.cloudflare.com/durable-objects/api/storage-api)) backends.

After persisting log state, the Sequencer returns sequenced entry metadata (7) to the Batcher, which in turn sends entry metadata to waiting Frontend requests and writes batch metadata to the deduplication cache in Workers KV. When the Frontend receives the response, it returns a Signed Certificate Timestamp (SCT) to the client (8).

## Test logs

Two prototype logs are available for testing, with configuration in `wrangler.jsonc` and `config.cftest.json` and roots from `roots.default.pem`.

    curl -s https://static-ct.cloudflareresearch.com/logs/cftest2025h1a/metadata | jq
    {
      "description": "Cloudflare Research 'cftest2025h1a' log",
      "log_type": "test",
      "log_id": "7DSwkhPo35hYEZa4DVlPq6Pm/bG4aOw/kqhHvYd6z/k=",
      "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8LxK0sAKYODiZe9gDeak7agggQ0wvBOeEMSi7cLlFzcTlm1AexxsC04r/4rBIhf8liQqyRTrL3u1jpz6NJ4tLg==",
      "witness_key": "MCowBQYDK2VwAyEAWTVSsOnsIYq+LZ6CUxgI8ONvJvE+YSF27N9BXZ02EP8=",
      "mmd": 86400,
      "submission_url": "https://static-ct.cloudflareresearch.com/logs/cftest2025h1a/",
      "monitoring_url": "https://static-ct-public-cftest2025h1a.cloudflareresearch.com/",
      "temporal_interval": {
        "start_inclusive": "2025-01-01T00:00:00Z",
        "end_exclusive": "2025-07-01T00:00:00Z"
      }
    }

    curl -s https://static-ct.cloudflareresearch.com/logs/cftest2025h2a/metadata | jq
    {
      "description": "Cloudflare Research 'cftest2025h2a' log",
      "log_type": "test",
      "log_id": "2KJiliJSBM2181NJWC5O1mWiRRsPJ6i2iWE2s7n8Bwg=",
      "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYipauBOPEktPb0JVpkRQq6wtRDRIj8GmKYvzM0Lpw1oSh9Uis9khpPCH6xyrDstk019AHuCq19KT5f+/MkY/yA==",
      "witness_key": "MCowBQYDK2VwAyEA8jhNnqw2LXtyjb0Os+R3eiKfxnsP8tnke5iZZ16nBbU=",
      "mmd": 86400,
      "submission_url": "https://static-ct.cloudflareresearch.com/logs/cftest2025h2a/",
      "monitoring_url": "https://static-ct-public-cftest2025h2a.cloudflareresearch.com/",
      "temporal_interval": {
        "start_inclusive": "2025-07-01T00:00:00Z",
        "end_exclusive": "2026-01-01T00:00:00Z"
      }
    }

## Deployment

### Local deployment

Follow these instructions to spin up a CT log on your local machine using the `dev` configuration in `wrangler.jsonc` and `config.dev.json` (schema at `config.schema.json`), and secrets in `.dev.vars`.

1.  (Optional) [Clear the local storage cache](https://developers.cloudflare.com/workers/testing/local-development/#clear-wranglers-local-storage):

        rm -r .workers/state

1.  Deploy worker locally with `npx wrangler -e=dev dev`.

1.  Send some requests. After the first request that hits the Durable Object (`/ct/v1/add-[pre-]chain` or `/metrics`), the sequencing loop will begin.

    Submit a certificate from a server:

    ```text
    openssl s_client -showcerts -connect google.com:443 -servername google.com </dev/null 2>/dev/null |\
    while (set -o pipefail; openssl x509 -outform DER 2>/dev/null | base64); do :; done |\
    sed '/^$/d' | sed 's/.*/"&"/' | jq -sc '{"chain":.}' |\
    curl -s "http://localhost:8787/logs/dev2025h1a/ct/v1/add-chain" -d@-
    ```

    Use [ctclient](https://github.com/google/certificate-transparency-go/tree/master/client/ctclient) to 'cross-pollinate' entries from another log (RFC6962 logs only, until [static-ct-api support is added](https://github.com/google/certificate-transparency-go/issues/1669)) with overlapping roots and NotAfter temporal interval:

    ```text
    tmpdir=$(mktemp -d)
    ./ctclient get-entries --first 0 --last 31 --log_name "Google 'Argon2025h1' log" --chain --text=false | csplit -s -f $tmpdir/ - '/^Index=/' '{30}'
    for file in $tmpdir/*; do
      prefix=$(head -n1 $file | grep -o "pre-")
      cat $file | while (set -o pipefail; openssl x509 -outform DER 2>/dev/null | base64); do :; done |\
      sed '/^$/d' | sed 's/.*/"&"/' | jq -sc '{"chain":.}' |\
      curl -s "http://localhost:8787/logs/dev2025h1a/ct/v1/add-${prefix}chain" -d@- &
    done
    rm -r $tmpdir
    ```

    Checkpoints and other static data can also be retrieved through the worker (or directly from the R2 bucket):

        curl -s "http://localhost:8787/logs/dev2025h1a/checkpoint"

    Metadata necessary for writing to or consuming from logs is available at /metadata.

        curl -s "http://localhost:8787/logs/dev2025h1a/metadata"

    Prometheus metrics are exposed _publicly_ at /metrics.

        curl -s "http://localhost:8787/logs/dev2025h1a/metrics"

### Deployment to a workers.dev subdomain

Follow these instructions to deploy a CT log with the `dev` configuration to Cloudflare's network.

Run the following for each of the `dev2025h1a` and `dev2025h2a` log shards to configure resources (or use `scripts/create-log.sh`):

1.  Set log shard name and deployment environment.

        export LOG_NAME=dev2025h1a
        export ENV=dev

1.  Create R2 bucket for public assets, optionally with a [location hint](https://developers.cloudflare.com/r2/reference/data-location/).

        npx wrangler r2 bucket create static-ct-public-${LOG_NAME} [--location <location>]

1.  Create KV namespace for per-log deduplication cache.

    ```text
    # After running, add generated namespace ID to `wrangler.jsonc`
    npx wrangler kv namespace create static-ct-cache-${LOG_NAME}
    ```

1.  Generate [secrets](https://developers.cloudflare.com/workers/configuration/secrets) for the signing and witness keys. NOTE: this will overwrite any existing secrets of the same name.

        openssl genpkey -algorithm ed25519 | npx wrangler -e=${ENV} secret put WITNESS_KEY_${LOG_NAME}
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 | npx wrangler -e=${ENV} secret put SIGNING_KEY_${LOG_NAME}

1.  Deploy the worker. The worker will be available at `https://static-ct-${ENV}.<your-team>.workers.dev/logs/${LOG_NAME}`.

        npx wrangler -e=${ENV} deploy

1.  Tail the worker:

        npx wrangler -e=${ENV} tail

1.  Send some requests. See [local development](#local-deployment) for examples.

### Deployment to a custom domain

Follow these instructions to deploy to a custom domain, suitable for running a public CT log. We'll use the `cftest` environment as an example, which was used to deploy the [test logs][#test-logs].

1.  Create a new [deployment environment](https://developers.cloudflare.com/workers/wrangler/environments/) in `wrangler.jsonc` by copying or editing the existing `cftest` environment.

1.  Create a file `config.${ENV}.json` with the configuration for the log shards.

1.  (Optional) Create a file `roots.${ENV}.pem` with any custom accepted roots for the log shards, in PEM format. If `enable_ccadb_roots` is set to true, these roots are used in addition to roots auto-pulled from the CCADB list. If `enable_ccadb_roots` is set to false for any logs in the deployment, `roots.${ENV}.pem` is required to exist and contain at least one certificate. All logs shards deployed within the same Worker script use the same set of additional roots. Roots can be updated later, but roots should generally not be removed once added.

1.  First set environment variables to specify the log shard name and deployment environment as below and then follow the [instructions above](#deployment-to-a-workersdev-subdomain) to create resources for each log shard.

        export LOG_NAME=cftest2025h1a
        export ENV=cftest

1.  Configure R2 buckets via Cloudflare dashboard. The monitoring APIs are served directly from the bucket, so configure for public access with caching and compression.

    1. Set up [public access](https://developers.cloudflare.com/r2/buckets/public-buckets/) for the R2 bucket, either as a [custom domain](https://developers.cloudflare.com/r2/buckets/public-buckets/#custom-domains) (recommended for caching) or as an r2.dev subdomain.
    1. Add a [Cache Rule](https://developers.cloudflare.com/cache/how-to/cache-rules/) for the entire bucket, specifying `Respect origin TTL` as the `Browser TTL` option.
    1. Add a [Compression Rule](https://developers.cloudflare.com/rules/compression-rules/) to enable compression for the `/tile/data` path.

1.  Deploy the worker with `npx wrangler -e=${ENV} deploy`.

### Reset the worker

1.  Delete the worker via dashboard UI. This will delete all associated Durable Objects and secrets.

1.  Delete associated KV namespaces via dashboard UI.

1.  Delete associated R2 buckets via dashboard UI. You'll need to first delete all objects in the buckets, which you can either do manually (25 at a time, via the UI), or using a [lifecycle management rule](https://community.cloudflare.com/t/how-does-cloudflare-r2-quickly-delete-storage-buckets-with-data/692584) (recommended).

## Rust Docs

    cargo doc --open --document-private-items

## Debugging

See the [developer docs](https://developers.cloudflare.com/workers/observability/dev-tools/) for guidance on
profiling and debugging. Use `worker-build --dev` as the build command in `wrangler.toml` to build with debug symbols.

## Testing

### Unit tests

    cargo test

    # to include tests that take several minutes to run, which are ignored by default
    cargo test -- --ignored

## Check for unnecessary dependencies

    cargo machete

## Acknowledgements

This project ports code from [sunlight](https://github.com/FiloSottile/sunlight) and [certificate-transparency-go](https://github.com/google/certificate-transparency-go).

## License

The project is licensed under the [BSD-3-Clause License](./LICENSE).
