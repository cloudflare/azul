# Bootstrap MTC CA Worker

A Rust implementation of a [Bootstrap MTC CA](https://blog.cloudflare.com/bootstrap-mtc) for deployment on [Cloudflare Workers](https://workers.cloudflare.com/).

This worker implements an experimental Merkle Tree Certificates CA based on the bootstrap experiment described in the Cloudflare blog post above. It implements an older version of the MTC specification (approximately draft-davidben-tls-merkle-tree-certs-09).

The internal log architecture (Sequencer, Batcher, Cleaner Durable Objects, tiled R2 storage) is shared with the [Static CT Log](../ct_worker/README.md).

## How it works

For every MTC issued, the requester must provide a **bootstrap certificate chain** — a standard X.509 certificate chain with a path to a root trusted by the CA. By default the root store is the intersection of Chrome's and Mozilla's trust stores (sourced from the CCADB). The CA validates the chain, extracts the subject, SPKI, SANs, key usage, and EKU, and logs them as a `TBSCertificateLogEntry`.

Once a landmark interval elapses, the sequencer produces a landmark subtree and the CA can issue **signatureless MTC certificates** — DER-encoded X.509 structures whose `signatureValue` encodes a Merkle inclusion proof into the landmark subtree rather than a traditional signature. (The IETF draft renamed these to "landmark-relative" certificates.)

## Development

Requires `node` and `npm`.

```bash
# Run locally
npx wrangler -e=dev dev

# Reset local state between runs
./reset-dev.sh
```

To test the basic functionality, run the following script from this directory:

```bash
./test-dev.sh
```

This script:
1. Fetches a bootstrap certificate chain.
2. Submits it to the MTC CA running locally.
3. Waits for the next landmark (interval defined in [`config.dev.json`](./config.dev.json)).
4. Requests the signatureless MTC.

### Overriding the trust store

To test with your own root certificates:

1. Add `dev-bootstrap-roots` to the default features in `Cargo.toml`.
2. Append your root certificates (PEM format) to [`dev-bootstrap-roots.pem`](./dev-bootstrap-roots.pem).

### Integration tests

```bash
BASE_URL=http://localhost:8787 BOOTSTRAP_MTC_LOG_NAME=dev2 cargo test -p integration_tests --test bootstrap_mtc_api
```

## Deployment

See the [`ct_worker` documentation](../ct_worker/README.md#deployment-to-a-custom-domain) for deployment to a custom domain.

## License

The project is licensed under the [BSD-3-Clause License](./LICENSE).
