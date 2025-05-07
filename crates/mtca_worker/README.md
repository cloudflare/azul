# Merkle Tree Certificate Authority (MTCA) Worker

A Rust implementation of the [Photosynthesis](https://docs.google.com/document/d/1T8_VnmeaAZBqiEy8UnbCFoEkui0PgWCQjVdBW0gGp7c/edit?usp=sharing) design for [Merkle Tree Certificates](https://github.com/davidben/merkle-tree-certs) for deployment on [Cloudflare Workers](https://workers.cloudflare.com/).

## Deployment

### Local deployment

Follow these instructions to spin up a MTCA log on your local machine using the `dev` configuration in `wrangler.jsonc` and `config.dev.json` (schema at `config.schema.json`), and secrets in `.dev.vars`.

1.  (Optional) [Clear the local storage cache](https://developers.cloudflare.com/workers/testing/local-development/#clear-wranglers-local-storage):

        rm -r .workers/state

1.  Deploy worker locally with `npx wrangler -e=dev dev`.

1.  Send some requests. After the first request that hits the Durable Object (`/add-assertion` or `/metrics`), the sequencing loop will begin.

    Submit an assertion request generated with [mtc](https://github.com/bwesterb/mtc):

    ```text
    ./mtc new-assertion-request -X google.com:443 |\
    curl -s http://localhost:8787/logs/dev0/add-assertion --data-binary @-
    ```

    Checkpoints and other static data can also be retrieved through the worker (or directly from the R2 bucket):

        curl -s "http://localhost:8787/logs/dev0/checkpoint"

    Or for tiles (here a partial tile containing the first log entry):

        curl -s "http://localhost:8787/logs/dev0/tile/data/0/000.p/1"

    Metadata is available at /metadata.

        curl -s "http://localhost:8787/logs/dev0/metadata"

    Prometheus metrics are exposed _publicly_ at /metrics.

        curl -s "http://localhost:8787/logs/dev0/metrics"

### Deployment to a workers.dev subdomain

Follow these instructions to deploy a MTCA log with the `dev` configuration to Cloudflare's network.

Run the following for each of the `dev0` and `dev1` log shards to configure resources.

1.  Set log shard name and deployment environment.

        export LOG_NAME=dev0
        export ENV=dev

1.  Create R2 bucket for public assets, optionally with a [location hint](https://developers.cloudflare.com/r2/reference/data-location/).

        npx wrangler r2 bucket create mtca-public-${LOG_NAME} [--location <location>]

1.  Generate [secrets](https://developers.cloudflare.com/workers/configuration/secrets) for the signing and witness keys. NOTE: this will overwrite any existing secrets of the same name.

        openssl genpkey -algorithm ed25519 | npx wrangler -e=${ENV} secret put WITNESS_KEY_${LOG_NAME}
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 | npx wrangler -e=${ENV} secret put SIGNING_KEY_${LOG_NAME}

1.  Deploy the worker. The worker will be available at `https://mtca-${ENV}.<your-team>.workers.dev/logs/${LOG_NAME}`.

        npx wrangler -e=${ENV} deploy

1.  Tail the worker:

        npx wrangler -e=${ENV} tail

1.  Send some requests. See [local development](#local-deployment) for examples.

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

## License

The project is licensed under the [BSD-3-Clause License](./LICENSE).
