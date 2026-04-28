# Transparency Log Witness Worker

A [`c2sp.org/tlog-witness`](https://c2sp.org/tlog-witness) implementation on
[Cloudflare Workers](https://workers.cloudflare.com/).

A *witness* cosigns transparency-log checkpoints after checking them for
consistency with previously-observed state. Clients (typically the log
itself) call `POST /add-checkpoint` with a new checkpoint and a consistency
proof; the witness verifies the proof, atomically records the new latest
state, and returns a timestamped `cosignature/v1` signature.

The wire-format parsers and serializers live in the
[`tlog_witness`](../tlog_witness/) crate (published to crates.io); this crate
is the Cloudflare Workers-specific shell that wires them up to HTTP, Durable
Object storage for per-origin state, and a secret-managed Ed25519 signing
key.

## Known limitations

- Cosignatures are Ed25519 only (the only algorithm for `cosignature/v1`
  per c2sp.org/tlog-cosignature v1).
- Only logs that sign checkpoints with Ed25519 are accepted.

## Configuration

See [`config.schema.json`](config.schema.json). Each entry under `logs` gives
the origin line the witness will match against incoming checkpoints and one
or more DER-encoded `SubjectPublicKeyInfo` blobs (base64-encoded in config)
for keys that may sign checkpoints. The witness's own identity is configured
at the top level as `witness_name`; its signing key is provided out-of-band
as a `WITNESS_SIGNING_KEY` secret.

## Development

Requires `node` and `npm`.

```bash
# Run locally
npx wrangler -e=dev dev

# Reset local state between runs
./reset-dev.sh
```

## License

The project is licensed under the [BSD-3-Clause License](./LICENSE).
