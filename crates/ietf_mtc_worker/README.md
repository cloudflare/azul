# IETF Merkle Tree CA Worker

A Rust implementation of an [IETF Merkle Tree Certificate CA](https://github.com/ietf-plants-wg/merkle-tree-certs/) for deployment on [Cloudflare Workers](https://workers.cloudflare.com/).

This worker implements [draft-ietf-plants-merkle-tree-certs-02](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/). For the older bootstrap experiment, see [`bootstrap_mtc_worker`](../bootstrap_mtc_worker/README.md).

The internal log architecture (Sequencer, Batcher, Cleaner Durable Objects, tiled R2 storage) is shared with the [Static CT Log](../ct_worker/README.md).

## How it works

Subscribers submit a PKCS#10 CSR (base64url-encoded, no padding) to the `add-entry` endpoint, matching the ACME `finalize` format (RFC 8555 §7.4). The CA extracts the subject, SPKI, and SANs from the CSR and logs them as a `TBSCertificateLogEntry`. The validity window is set server-side to `[now, now + max_certificate_lifetime_secs]`.

Once a landmark interval elapses, the sequencer produces a landmark subtree and the CA can issue **landmark-relative MTC certificates** — DER-encoded X.509 structures whose `signatureValue` encodes a Merkle inclusion proof into the landmark subtree rather than a traditional signature.

## Known limitations

- Standalone certificates (with cosignatures in the `signatures` field) are not yet implemented.
- ML-DSA signing is not yet implemented.
- The subtree signing oracle (for external cosigners) is not yet implemented.
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

## Deployment

See the [`ct_worker` documentation](../ct_worker/README.md#deployment-to-a-custom-domain) for deployment to a custom domain.

The production environment is `prod` (maps to `config.prod.json`):

```bash
npx wrangler -e=prod deploy
```

## License

The project is licensed under the [BSD-3-Clause License](./LICENSE).
