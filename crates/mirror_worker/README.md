# Transparency Log Mirror Worker

A configurable Cloudflare Worker implementing
[`c2sp.org/tlog-witness`](https://c2sp.org/tlog-witness),
[`c2sp.org/tlog-mirror`](https://c2sp.org/tlog-mirror), or both protocols
with one per-origin `MirrorState` Durable Object.

## Configuration

`mode` is one of `witness`, `mirror`, or `witness-and-mirror`. The matching
`witness` and `mirror` identity sections are required only when that role is
enabled. `logs` is keyed by exact checkpoint origin and supports structured
Ed25519 and `subtree/v1` checkpoint signers.

Role keys remain separate secrets:

- `WITNESS_SIGNING_KEY` signs successful `add-checkpoint` responses and witness subtree responses.
- `MIRROR_SIGNING_KEY` signs completed mirror checkpoints and mirror subtree responses.
- `MIRROR_TICKET_KEY` seals mirror upload tickets.

Disabled-role secrets are not loaded. Mirror R2, ticket, and cleaner access is
confined to mirror operations.

## Mirror State

For each origin, `MirrorState` maintains
`committed.size <= next_entry.size <= pending.size`.

## Development

The dev configuration enables both roles. Run from this directory:

```bash
npx wrangler -e=dev dev
./reset-dev.sh
```

Run the integration suites from the workspace root against the same worker:

```bash
cargo test -p integration_tests --test tlog_witness
cargo test -p integration_tests --test tlog_mirror
```
