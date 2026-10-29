# IETF Merkle Tree CA Worker

A Rust implementation of an [IETF Merkle Tree Certificate CA](https://github.com/ietf-plants-wg/merkle-tree-certs/) for deployment on [Cloudflare Workers](https://workers.cloudflare.com/).

This worker implements [draft-ietf-plants-merkle-tree-certs-07](https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs-07).

> **Warning:** This worker is experimental and is not meant for production use.
> The `add-entry` endpoint is an unauthenticated interoperability endpoint. It
> does not perform ACME authorization or production certificate issuance
> validation and must not be deployed as a production CA interface.

The internal log architecture (Sequencer, Batcher, Cleaner Durable Objects, tiled R2 storage) is shared with the [Static CT Log](../ct_worker/README.md).

## How it works

For interoperability testing, callers submit a PKCS#10 CSR (base64url-encoded, no padding) to the unauthenticated `add-entry` endpoint, using the ACME `finalize` payload shape (RFC 8555 §7.4). The worker extracts the subject, SPKI, and SANs from the CSR and logs them as a `TBSCertificateLogEntry`. The validity window is set server-side to `[now, now + max_certificate_lifetime_secs]`.

Once a landmark interval elapses, the sequencer produces a landmark subtree and the CA can issue **landmark-relative MTC certificates** — DER-encoded X.509 structures whose `signatureValue` encodes a Merkle inclusion proof into the landmark subtree rather than a traditional signature.

The sequencer caches the CA's signature over each subtree it sequences under `subtree-sig/` in the public bucket, so that `add-entry` can return a standalone certificate immediately. These objects are an implementation detail of the worker and are not part of the specification. Each signs a subtree of the public log, so they disclose nothing beyond the log contents. The cleaner deletes those whose upper bound is at or below the oldest active landmark.

## Known limitations

- The subtree signing oracle (for external cosigners) is not yet implemented.
- The ACME interface is not yet complete.
- ACME order `notBefore`/`notAfter` fields are not currently supported.
- Persisted state from earlier draft versions must be reset before upgrading.

## Development

Requires `node` and `npm`.

```bash
# Run locally
npx wrangler -e=dev dev

# Reset local state between runs
./reset-dev.sh
```

### Integration tests

```bash
BASE_URL=http://localhost:8787 IETF_MTC_LOG_NAME=dev1 cargo test -p integration_tests --test ietf_mtc_api
```

## License

The project is licensed under the [BSD-3-Clause License](./LICENSE).
