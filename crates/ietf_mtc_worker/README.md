# IETF Merkle Tree CA Worker

A Rust implementation of an [IETF Merkle Tree Certificate CA](https://github.com/ietf-plants-wg/merkle-tree-certs/) for deployment on [Cloudflare Workers](https://workers.cloudflare.com/).

This worker implements [draft-ietf-plants-merkle-tree-certs-06](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/).

> **Warning:** The `add-entry` endpoint is an unauthenticated interoperability
> endpoint. It does not perform ACME authorization or production certificate
> issuance validation and must not be deployed as a production CA interface.

The internal log architecture (Sequencer, Batcher, Cleaner Durable Objects, tiled R2 storage) is shared with the [Static CT Log](../ct_worker/README.md).

## How it works

For interoperability testing, callers submit a PKCS#10 CSR (base64url-encoded, no padding) to the unauthenticated `add-entry` endpoint, using the ACME `finalize` payload shape (RFC 8555 §7.4). The worker extracts the subject, SPKI, and SANs from the CSR and logs them as a `TBSCertificateLogEntry`. The validity window is set server-side to `[now, now + max_certificate_lifetime_secs]`.

Once a landmark interval elapses, the sequencer produces a landmark subtree and the CA can issue **landmark-relative MTC certificates** — DER-encoded X.509 structures whose `signatureValue` encodes a Merkle inclusion proof into the landmark subtree rather than a traditional signature.

## Known limitations

- The subtree signing oracle (for external cosigners) is not yet implemented.
- The ACME interface is not yet complete.
- ACME order `notBefore`/`notAfter` fields are not currently supported.

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
BASE_URL=http://localhost:8787 IETF_MTC_LOG_NAME=dev2 cargo test -p integration_tests --test ietf_mtc_api
```

## License

The project is licensed under the [BSD-3-Clause License](./LICENSE).
