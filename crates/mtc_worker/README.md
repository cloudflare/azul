# Merkle Tree CA Worker

A Rust implementation of a [Merkle Tree CA](https://github.com/davidben/merkle-tree-certs/) (MTCA) for deployment on [Cloudflare Workers](https://workers.cloudflare.com/).

Much of the API and the internal architecture of the Merkle Tree CA is shared by the [Static CT Log](../ct_worker/README.md). This Worker also implements issuance of Merkle Tree Certificates (MTCs). The issuance API should be considered unstable. For now, its primary purpose is to support an experimental deployment of the MTC specification.

## Development

`node` and `npm` are required to run the Worker locally. First, use `npm` to install `wrangler`:

```bash
npm install -g wrangler@latest
```

Then use `wrangler` to run the Worker locally from this directory:

```bash
npx wrangler dev -e=dev
```

The Worker doesn't implement a full-blown MTCA. Instead, it implements what we call a **bootstrap MTCA**. For every MTC requested, the requester must provide a **bootstrap certificate**. A bootstrap certificate is a standard X.509 certificate chain that must have a path to a root certificate trusted by `mtc_worker`. By default, the root store used is the intersection of Chrome's and Mozilla's trust stores.

To test the basic functionality, run the following script from this directory:

```bash
./test-dev.sh
```

This script does the following:

1. Fetch a bootstrap certificate chain.

1. Submit the bootstrap certificate chain to the MTCA running locally.

1. Wait for the next landmark to be minted. The landmark interval is defined in [`config.dev.json`](./config.dev.json).

1. Request the signatureless MTC from the MTCA running locally

### Overriding the trust store

It may be useful to provide your own roots for testing. To do so:

1. Build the Worker with the `"dev-bootstrap-roots"` feature. Note that `wrangler` invokes `cargo` with a custom build script, so the simplest thing to do is to edit the `Cargo.toml` file by adding `"dev-boostrap-roots"` to the default feature set.

1. Append your roots to [`dev-bootstrap-roots.pem`](./dev-bootstrap-roots.pem).

## Deployment

See the [`ct_worker` documentation](../ct_worker/README.md#deployment-to-a-custom-domain) for deployment to a custom domain.

## License

The project is licensed under the [BSD-3-Clause License](./LICENSE).
